/*-------------------------------------------------------------------------
 *
 * pg_anonymize.c
 *		Anonymize data on-the-fly
 *
 *
 * Copyright (c) 2022, Julien Rouhaud
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
#include "commands/copy.h"
#include "commands/seclabel.h"
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

static char *pgan_get_query_for_relid(Relation rel, List *attlist);
static bool pgan_hack_query(Node *node, void *context);
static void pgan_hack_rte(RangeTblEntry *rte);
static void pgan_object_relabel(const ObjectAddress *object,
							    const char *seclabel);


void
_PG_init(void)
{
	register_label_provider(PGAN_PROVIDER, pgan_object_relabel);

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
 * Generate an SQL query returning the anonymized data.
 */
static char *
pgan_get_query_for_relid(Relation rel, List *attlist)
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
	attnums = CopyGetAttnums(tupdesc, rel, attlist);

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
	sql = pgan_get_query_for_relid(rel, NIL);
	relation_close(rel, NoLock);

	/*
	 * If we got a query, transform the given rte in a subquery pointing to it.
	 */
	if (sql)
	{
		List *parselist;
		RawStmt *raw;
		Query *subquery;

		parselist = pg_parse_query(sql);

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
		}
#if PG_VERSION_NUM >= 130000
		PG_FINALLY();
		{
			pgan_toplevel = true;
		}
#else
		PG_CATCH();
		{
			pgan_toplevel = true;
			PG_RE_THROW();
		}
#endif
		PG_END_TRY();

#if PG_VERSION_NUM < 130000
		pgan_toplevel = true;
#endif

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
		rte->inh = false;			/* must not be set for a subquery */

		rte->requiredPerms = 0;		/* no permission check on subquery itself */
		rte->checkAsUser = InvalidOid;
		rte->selectedCols = NULL;
		rte->insertedCols = NULL;
		rte->updatedCols = NULL;
#if PG_VERSION_NUM >= 120000
		rte->extraUpdatedCols = NULL;
#endif
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
	sql = pgan_get_query_for_relid(rel, stmt->attlist);
	relation_close(rel, NoLock);

	/* If we got a query, use it in the COPY TO statement */
	if (sql)
	{
		List *parselist;

		parselist = pg_parse_query(sql);
		Assert(list_length(parselist) == 1);
		Assert(IsA(linitial(parselist), RawStmt));

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
	}
#if PG_VERSION_NUM >= 130000
	PG_FINALLY();
	{
		pgan_toplevel = true;
	}
#else
	PG_CATCH();
	{
		pgan_toplevel = true;
		PG_RE_THROW();
	}
#endif
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
