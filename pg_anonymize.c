/*-------------------------------------------------------------------------
 *
 * pg_anonymize.c
 *		Anonymize data on-the-fly
 *
 *
 * pg_anonymize
 * Copyright (C) 2022-2023 - Julien Rouhaud.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/genam.h"
#if PG_VERSION_NUM >= 120000
#include "access/relation.h"
#include "access/table.h"
#else
#include "access/heapam.h"
#include "access/htup_details.h"
#endif
#include "access/xact.h"
#if PG_VERSION_NUM < 140000
#include "catalog/indexing.h"
#endif
#include "catalog/pg_authid.h"
#if PG_VERSION_NUM >= 110000
#include "catalog/pg_namespace_d.h"
#else
#include "catalog/pg_namespace.h"
#endif
#include "catalog/pg_seclabel.h"
#include "catalog/pg_type.h"
#include "commands/copy.h"
#include "commands/seclabel.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "optimizer/plancat.h"
#include "parser/analyze.h"
#include "rewrite/rewriteHandler.h"
#include "tcop/utility.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/syscache.h"


PG_MODULE_MAGIC;

#define PGAN_PROVIDER	"pg_anonymize"
#define PGAN_ROLE_ANONYMIZED "anonymize"

/* Backward compatibility macros */
#if PG_VERSION_NUM < 120000
#define table_open(r, l) heap_open(r, l)
#define table_close(r, l) heap_close(r, l)
#endif

#if PG_VERSION_NUM < 150000
#define parse_analyze_fixedparams(r, s, p, n, e) parse_analyze(r, s, p, n, e)
#define MarkGUCPrefixReserved(c) EmitWarningsOnPlaceholders(c)
#endif

/*---- Local variables ----*/

bool pgan_toplevel = true;

/*---- GUC variables ----*/

static bool pgan_check_labels;
static bool pgan_enabled;

/*---- Function declarations ----*/

void		_PG_init(void);

static ProcessUtility_hook_type prev_ProcessUtility = NULL;
static post_parse_analyze_hook_type prev_post_parse_analyze_hook = NULL;

static void pgan_post_parse_analyze(ParseState *pstate, Query *query
#if PG_VERSION_NUM >= 140000
									, JumbleState *jstate
#endif
									);
static void pgan_ProcessUtility(PlannedStmt *pstmt, const char *queryString,
#if PG_VERSION_NUM >= 140000
								bool readOnlyTree,
#endif
								ProcessUtilityContext context, ParamListInfo params,
								QueryEnvironment *queryEnv,
								DestReceiver *dest,
#if PG_VERSION_NUM >= 130000
								QueryCompletion *qc
#else
								char *completionTag
#endif
								);

static void pgan_check_injection(Relation rel,
								const ObjectAddress *object,
								const char *seclabel);
static void pgan_check_expression_valid(Relation rel,
										const ObjectAddress *object,
										const char *seclabel);
static List *pgan_get_attnums(TupleDesc tupDesc, Relation rel,
							  List *attnamelist, bool is_copy);
static char *pgan_get_query_for_relid(Relation rel, List *attlist,
									  bool is_copy);
static bool pgan_hack_query(Node *node, void *context);
static void pgan_hack_rte(RangeTblEntry *rte);
static void pgan_object_relabel(const ObjectAddress *object,
							    const char *seclabel);
static char *pgan_typename(Oid typid);


void
_PG_init(void)
{
	register_label_provider(PGAN_PROVIDER, pgan_object_relabel);

	DefineCustomBoolVariable("pg_anonymize.check_labels",
							 "Check SECURITY LABELS when they are defined.",
							 NULL,
							 &pgan_check_labels,
							 true,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

	DefineCustomBoolVariable("pg_anonymize.enabled",
							 "Globally enable pg_anonymize.",
							 NULL,
							 &pgan_enabled,
							 true,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

	MarkGUCPrefixReserved("pg_anonymize");

	/* Install hooks. */
	prev_post_parse_analyze_hook = post_parse_analyze_hook;
	post_parse_analyze_hook = pgan_post_parse_analyze;
	prev_ProcessUtility = ProcessUtility_hook;
	ProcessUtility_hook = pgan_ProcessUtility;
}

/*
 * Make sure that the given expression doesn't contain any SQL injection
 * attempt.
 */
static void
pgan_check_injection(Relation rel,
					const ObjectAddress *object,
					const char *seclabel)
{
	FormData_pg_attribute *att;
	StringInfoData sql;
	List *parsetree_list;

	att = TupleDescAttr(RelationGetDescr(rel), object->objectSubId - 1);

	initStringInfo(&sql);
	appendStringInfo(&sql, "SELECT %s AS %s FROM %s.%s",
					 seclabel,
					 quote_identifier(NameStr(att->attname)),
					 quote_identifier(get_namespace_name(RelationGetNamespace(rel))),
					 quote_identifier(RelationGetRelationName(rel)));

	PG_TRY();
	{
		parsetree_list = pg_parse_query(sql.data);
	}
	PG_CATCH();
	{
		errcontext("during validation of expression \"%s\"", seclabel);
		PG_RE_THROW();
	}
	PG_END_TRY();

	if (list_length(parsetree_list) != 1)
		elog(ERROR, "SQL injection detected!");
}

/*
 * Perform sanity checks on the user provided security label
 */
static void
pgan_check_expression_valid(Relation rel, const ObjectAddress *object,
							const char *seclabel)
{
	StringInfoData sql;
	int ret;
	bool prev_xact_read_only;

	initStringInfo(&sql);
	appendStringInfo(&sql, "SELECT pg_typeof(%s)::regtype::oid FROM %s.%s LIMIT 1",
			seclabel,
			quote_identifier(get_namespace_name(RelationGetNamespace(rel))),
			quote_identifier(RelationGetRelationName(rel)));

	if ((ret = SPI_connect()) < 0)
	{
		/* internal error */
		elog(ERROR, "SPI_connect returned %d", ret);
	}

	/*
	 * We ask for read-only SPI execution, but it doesn't reliably detect write
	 * queries, so force additional executor check.
	 */
	prev_xact_read_only = XactReadOnly;
	PG_TRY();
	{
		XactReadOnly = true;
		SPI_execute(sql.data, true, 1);
		XactReadOnly = prev_xact_read_only;
	}
	PG_CATCH();
	{
		XactReadOnly = prev_xact_read_only;
		errcontext("during validation of expression \"%s\"", seclabel);
		PG_RE_THROW();
	}
	PG_END_TRY();

	/*
	 * No row in the source table, can't say about the expession apart that
	 * it's valid.
	 */
	if (SPI_processed == 0)
		elog(NOTICE, "the expression \"%s\" is valid but no data in table"
				" %s.%s, cannot check returned type",
				seclabel,
				quote_identifier(get_namespace_name(RelationGetNamespace(rel))),
				quote_identifier(RelationGetRelationName(rel)));
	else
	{
		FormData_pg_attribute *att;
		Oid		typid;
		bool	isnull;

		Assert(SPI_processed == 1);

		typid = DatumGetObjectId(SPI_getbinval(SPI_tuptable->vals[0],
											   SPI_tuptable->tupdesc,
						 		 			   1, &isnull));

		/* Should not happen */
		if (isnull)
			elog(ERROR, "unexpected NULL value");

		att = TupleDescAttr(RelationGetDescr(rel), object->objectSubId - 1);

		if (typid != att->atttypid)
		{
			if (typid == UNKNOWNOID && att->atttypid == TEXTOID)
			{
				/* Should be valid, but notify the user. */
				elog(NOTICE, "The expression has an unknown type, you may "
						"want to explicitly cast it to text");
			}
			else
				elog(ERROR, "The expression returns \"%s\" type, but the "
						" column is defined as \"%s\"",
					pgan_typename(typid),
					pgan_typename(att->atttypid));
		}
	}
	SPI_finish();
}

/*
 * Adaptation of CopyGetAttnums that optionally allows generated attributes
 */
static List *
pgan_get_attnums(TupleDesc tupDesc, Relation rel, List *attnamelist,
				 bool is_copy)
{
	List	   *attnums = NIL;

	if (attnamelist == NIL)
	{
		/* Generate default column list */
		int			attr_count = tupDesc->natts;
		int			i;

		for (i = 0; i < attr_count; i++)
		{
			if (TupleDescAttr(tupDesc, i)->attisdropped)
				continue;
#if PG_VERSION_NUM >= 120000
			/* Only COPY should ignore generated attributes */
			if (TupleDescAttr(tupDesc, i)->attgenerated && is_copy)
				continue;
#endif
			attnums = lappend_int(attnums, i + 1);
		}
	}
	else
	{
		/* Validate the user-supplied list and extract attnums */
		ListCell   *l;

		foreach(l, attnamelist)
		{
			char	   *name = strVal(lfirst(l));
			int			attnum;
			int			i;

			/* Lookup column name */
			attnum = InvalidAttrNumber;
			for (i = 0; i < tupDesc->natts; i++)
			{
				Form_pg_attribute att = TupleDescAttr(tupDesc, i);

				if (att->attisdropped)
					continue;
				if (namestrcmp(&(att->attname), name) == 0)
				{
#if PG_VERSION_NUM >= 120000
					if (att->attgenerated && is_copy)
						ereport(ERROR,
								(errcode(ERRCODE_INVALID_COLUMN_REFERENCE),
								 errmsg("column \"%s\" is a generated column",
										name),
								 errdetail("Generated columns cannot be used in COPY.")));
#endif
					attnum = att->attnum;
					break;
				}
			}
			if (attnum == InvalidAttrNumber)
			{
				if (rel != NULL)
					ereport(ERROR,
							(errcode(ERRCODE_UNDEFINED_COLUMN),
							 errmsg("column \"%s\" of relation \"%s\" does not exist",
									name, RelationGetRelationName(rel))));
				else
					ereport(ERROR,
							(errcode(ERRCODE_UNDEFINED_COLUMN),
							 errmsg("column \"%s\" does not exist",
									name)));
			}
			/* Check for duplicates */
			if (list_member_int(attnums, attnum))
				ereport(ERROR,
						(errcode(ERRCODE_DUPLICATE_COLUMN),
						 errmsg("column \"%s\" specified more than once",
								name)));
			attnums = lappend_int(attnums, attnum);
		}
	}

	return attnums;
}

/*
 * Generate an SQL query returning the anonymized data.
 */
static char *
pgan_get_query_for_relid(Relation rel, List *attlist, bool is_copy)
{
	List	   *attnums;
	ListCell   *lc;
	TupleDesc		tupdesc;
	StringInfoData select;
	bool		first, found_seclabel;

	/* We only anonymize plain relations and materialized views. */
	if (rel->rd_rel->relkind != RELKIND_RELATION &&
		rel->rd_rel->relkind != RELKIND_MATVIEW)
		return NULL;

	tupdesc = RelationGetDescr(rel);
	attnums = pgan_get_attnums(tupdesc, rel, attlist, is_copy);

	initStringInfo(&select);
	appendStringInfoString(&select, "SELECT ");

	found_seclabel = false;
	first = true;
	foreach(lc, attnums)
	{
		ObjectAddress addr;
		FormData_pg_attribute *att;
		int attnum = lfirst_int(lc);
		char *label;

		if (!first)
			appendStringInfoString(&select, ", ");
		else
			first = false;

		att = TupleDescAttr(tupdesc, attnum - 1);

		ObjectAddressSubSet(addr, RelationRelationId, RelationGetRelid(rel),
							attnum);
		label = GetSecurityLabel(&addr, PGAN_PROVIDER);
		if (label)
		{
			found_seclabel = true;
			appendStringInfo(&select, "%s AS %s", label,
							 quote_identifier(NameStr(att->attname)));
		}
		else
		{
			Assert(!att->attisdropped);
			appendStringInfoString(&select,
								   quote_identifier(NameStr(att->attname)));
		}
	}

	/* Finish building the query if we found any security label on the table. */
	if (found_seclabel)
	{
		appendStringInfo(&select, " FROM %s.%s",
						 quote_identifier(get_namespace_name(RelationGetNamespace(rel))),
						 quote_identifier(RelationGetRelationName(rel)));
		return select.data;
	}
	else
		return NULL;
}

/*
 * Walker function for query_tree_walker.
 * Inspect all range table entries in all found queries.
 */
static bool
pgan_hack_query(Node *node, void *context)
{
	if (node == NULL)
		return false;

	/* Ignore any Query that we generated. */
	if (IsA(node, Query) && ((Query *) node)->querySource != QSRC_PARSER)
	{
		Query	   *query = (Query *) node;
		ListCell   *rtable;

		foreach(rtable, query->rtable)
		{
			RangeTblEntry  *rte = lfirst_node(RangeTblEntry, rtable);

			if (rte->rtekind != RTE_RELATION)
				continue;

			if (rte->rtekind == RTE_SUBQUERY && rte->relid == 42)
				continue;

			pgan_hack_rte(rte);
		}

		return query_tree_walker(query,
								 pgan_hack_query,
								 context,
								 0);
	}

	return expression_tree_walker(node,
								  pgan_hack_query,
								  context);
}

/*
 * Transform the given plain relation RangeTblEntry to a subquery based on the
 * anonymized table if any of the relation's field should be anonymized.
 */
static void
pgan_hack_rte(RangeTblEntry *rte)
{
	Relation rel;
	char *sql;

	rel = relation_open(rte->relid, AccessShareLock);
	sql = pgan_get_query_for_relid(rel, NIL, false);
	relation_close(rel, NoLock);

	/*
	 * If we got a query, transform the given rte in a subquery pointing to it.
	 */
	if (sql)
	{
		List *parselist;
		RawStmt *raw;
		Query *subquery;
		bool prev_toplevel = pgan_toplevel;

		PG_TRY();
		{
			parselist = pg_parse_query(sql);
		}
		PG_CATCH();
		{
			errcontext("during anonymization of table %s", get_rel_name(rte->relid));
			PG_RE_THROW();
		}
		PG_END_TRY();

		Assert(list_length(parselist) == 1);
		Assert(IsA(linitial(parselist), RawStmt));

		raw = linitial_node(RawStmt, parselist);

		/*
		 * Be careful to not call our post_parse_analyze_hook when generating
		 * the new query.
		 */
		pgan_toplevel = false;
		PG_TRY();
		{
			subquery = parse_analyze_fixedparams(raw, sql, NULL, 0, NULL);
			pgan_toplevel = prev_toplevel;
		}
		PG_CATCH();
		{
			pgan_toplevel = prev_toplevel;
			PG_RE_THROW();
		}
		PG_END_TRY();

		/* Remember to not process it again */
		subquery->querySource = QSRC_PARSER;

		AcquireRewriteLocks(subquery, true, false);

		rte->rtekind = RTE_SUBQUERY;
		rte->subquery = subquery;
		rte->security_barrier = false;
		/* Clear fields that should not be set in a subquery RTE */
		rte->relid = InvalidOid;
		rte->relkind = 0;
#if PG_VERSION_NUM >= 120000
		rte->rellockmode = 0;
#endif
		rte->tablesample = NULL;
#if PG_VERSION_NUM >= 160000
		rte->perminfoindex = 0;		/* no permission checking for this RTE */
#endif
		rte->inh = false;			/* must not be set for a subquery */

#if PG_VERSION_NUM < 160000
		rte->requiredPerms = 0;		/* no permission check on subquery itself */
		rte->checkAsUser = InvalidOid;
		rte->selectedCols = NULL;
		rte->insertedCols = NULL;
		rte->updatedCols = NULL;
#if PG_VERSION_NUM >= 120000
		rte->extraUpdatedCols = NULL;
#endif			/* pg12+ */
#endif			/* pg16- */
	}
}

/*
 * Walks the given query and replace any reference to an anonymized table with
 * a subquery generating the anonymized data and configured.
 */
static void
pgan_post_parse_analyze(ParseState *pstate, Query *query
#if PG_VERSION_NUM >= 140000
		, JumbleState *jstate
#endif
		)
{
	ObjectAddress	addr;
	char		   *seclabel;

	/* Module disabled, recursive call or aborted transaction, bail out. */
	if (!pgan_enabled || !pgan_toplevel || !IsTransactionState())
		goto hook;

	/* XXX - should we try to prevent write queries ? */

	/* Role isn't declared as anonymized, bail out. */
	ObjectAddressSet(addr, AuthIdRelationId, GetUserId());
	seclabel = GetSecurityLabel(&addr, PGAN_PROVIDER);
	if (!seclabel || strcmp(seclabel, PGAN_ROLE_ANONYMIZED) != 0)
		goto hook;

	/* Walk the query and generate rewritten subquery when needed. */
	pgan_hack_query((Node *) query, NULL);

hook:
	if (prev_post_parse_analyze_hook)
		prev_post_parse_analyze_hook(pstate, query
#if PG_VERSION_NUM >= 140000
				, jstate
#endif
				);
}

/*
 * Intercept COPY TO commands to make sure anonymized data is emitted.
 */
static void
pgan_ProcessUtility(PlannedStmt *pstmt, const char *queryString,
#if PG_VERSION_NUM >= 140000
					bool readOnlyTree,
#endif
					ProcessUtilityContext context,
					ParamListInfo params, QueryEnvironment *queryEnv,
					DestReceiver *dest,
#if PG_VERSION_NUM >= 130000
					QueryCompletion *qc
#else
					char *completionTag
#endif
					)
{
	Node	   *parsetree = pstmt->utilityStmt;
	Relation rel;
	ObjectAddress addr;
	CopyStmt *stmt;
	char *seclabel, *sql;
	bool prev_toplevel = pgan_toplevel;

	/* Module disabled, recursive call or not a COPY statement, bail out. */
	if (!pgan_enabled || !pgan_toplevel || !IsA(parsetree, CopyStmt))
		goto hook;

	stmt = (CopyStmt *) parsetree;

	/* Only intercept plain COPY relation TO */
	if (stmt->is_from || !stmt->relation)
		goto hook;

	ObjectAddressSet(addr, AuthIdRelationId, GetUserId());
	seclabel = GetSecurityLabel(&addr, PGAN_PROVIDER);
	if (!seclabel || strcmp(seclabel, PGAN_ROLE_ANONYMIZED) != 0)
		goto hook;

	rel = relation_openrv(stmt->relation, AccessShareLock);
	sql = pgan_get_query_for_relid(rel, stmt->attlist, true);
	relation_close(rel, NoLock);

	/* If we got a query, use it in the COPY TO statement */
	if (sql)
	{
		List *parselist;

		PG_TRY();
		{
			parselist = pg_parse_query(sql);
			Assert(list_length(parselist) == 1);
			Assert(IsA(linitial(parselist), RawStmt));
		}
		PG_CATCH();
		{
			errcontext("during validation of expression \"%s\"", seclabel);
			PG_RE_THROW();
		}
		PG_END_TRY();

		pfree(stmt->relation);
		stmt->relation = NULL;
		if (stmt->attlist)
		{
			pfree(stmt->attlist);
			stmt->attlist = NULL;
		}
		stmt->query = linitial_node(RawStmt, parselist)->stmt;
		pgan_toplevel = false;
	}

hook:
	PG_TRY();
	{
		if (prev_ProcessUtility)
			prev_ProcessUtility(pstmt, queryString,
#if PG_VERSION_NUM >= 140000
								readOnlyTree,
#endif
								context, params, queryEnv,
								dest,
#if PG_VERSION_NUM >= 130000
								qc
#else
								completionTag
#endif
								);
		else
			standard_ProcessUtility(pstmt, queryString,
#if PG_VERSION_NUM >= 140000
									readOnlyTree,
#endif
									context, params, queryEnv,
									dest,
#if PG_VERSION_NUM >= 130000
									qc
#else
									completionTag
#endif
									);

		pgan_toplevel = prev_toplevel;
	}
	PG_CATCH();
	{
		pgan_toplevel = prev_toplevel;
		PG_RE_THROW();
	}
	PG_END_TRY();
}

/*
 * Sanity checks on the user provided security labels.
 */
static void
pgan_object_relabel(const ObjectAddress *object, const char *seclabel)
{
	switch (object->classId)
	{
		case RelationRelationId:
		{
			Relation rel;

			if (object->objectSubId == 0)
				elog(ERROR, "only security labels on columns are supported");

			/* Don't accept any catalog object */
			rel = relation_open(object->objectId, AccessShareLock);

			if (RelationGetNamespace(rel) == PG_CATALOG_NAMESPACE)
				elog(ERROR, "unsupported catalog relation \"%s\"",
						RelationGetRelationName(rel));

			/* Perform sanity checks when defining a new security label. */
			if (seclabel)
			{
				pgan_check_injection(rel, object, seclabel);

				if (pgan_check_labels)
					pgan_check_expression_valid(rel, object, seclabel);
			}

			relation_close(rel, AccessShareLock);
			break;
		}
		case AuthIdRelationId:
			if (seclabel && strcmp(seclabel, PGAN_ROLE_ANONYMIZED) != 0)
				elog(ERROR, "invalid label \"%s\" for a role", seclabel);
			break;
		default:
			elog(ERROR, "pg_anonymize does not support \"%s\" catalog",
					get_rel_name(object->classId));
			break;
	}
}

/* Return a palloc'd copy of the type name for the given type. */
static char *
pgan_typename(Oid typid)
{
	HeapTuple tup;
	char *res;

	tup = SearchSysCache1(TYPEOID, ObjectIdGetDatum(typid));

	if (!HeapTupleIsValid(tup))
		elog(ERROR, "type with oid %u is unknown", typid);

	res = pstrdup(NameStr(((Form_pg_type) GETSTRUCT(tup))->typname));
	ReleaseSysCache(tup);

	return res;
}
