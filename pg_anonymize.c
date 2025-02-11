/*-------------------------------------------------------------------------
 *
 * pg_anonymize.c
 *		Anonymize data on-the-fly
 *
 *
 * pg_anonymize
 * Copyright (C) 2022-2024 - Julien Rouhaud.
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
#include "catalog/namespace.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_inherits.h"
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
#include "utils/varlena.h"


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

/* Reimplement some AttrMap features to keep later code simpler. */
#if PG_VERSION_NUM < 130000
#include "access/tupconvert.h"
typedef struct AttrMap
{
	AttrNumber *attnums;
	int			maplen;
} AttrMap;

static AttrMap *
build_attrmap_by_name_if_req(TupleDesc indesc, TupleDesc outdesc)
{
	AttrMap    *attrMap;
	AttrNumber *attnums;

#if PG_VERSION_NUM >= 120000
	attnums = convert_tuples_by_name_map_if_req(indesc, outdesc,
												"could not convert row type");
#else
	/* pg11- doesn't expose the "_if_req" part */
	attnums = convert_tuples_by_name_map(indesc, outdesc,
												"could not convert row type");
#endif

	if (attnums != NULL)
	{
		attrMap = (AttrMap *) palloc(sizeof(AttrMap));

		attrMap->attnums = attnums;
		attrMap->maplen = outdesc->natts;
	}
	else
		attrMap = NULL;

	return attrMap;
}

static void
free_attrmap(AttrMap *attrMap)
{
	pfree(attrMap->attnums);
	pfree(attrMap);
}
#endif

/* Used for pgan_get_rel_seclabels_worker() */
typedef struct pganWalkerContext
{
	Relation secRel;		/* Cached pg_seclabel relation */
	Relation inhRel;		/* Cached pg_inherits relation */
	char  **seclabels;		/* The array of found security labels */
	int		nb_labels;		/* # of columns for which we found a seclabel */
	TupleDesc tupdesc;		/* The original relation tupledesc */
} pganWalkerContext;

/*---- Local variables ----*/

static bool pgan_toplevel = true;

/*---- GUC variables ----*/

static bool pgan_check_labels = true;
static bool pgan_inherit_labels = true;
static bool pgan_enabled = true;

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
static void pgan_check_preload_lib(char *libnames, char *kind, bool missing_ok);
static List *pgan_get_attnums(TupleDesc tupDesc, Relation rel,
							  List *attnamelist, bool is_copy);
static char *pgan_get_query_for_relid(Relation rel, List *attlist,
									  bool is_copy);
static char **pgan_get_rel_seclabels(Relation rel);
static void pgan_get_rel_seclabels_worker(Relation rel,
										  pganWalkerContext *context);
static bool pgan_hack_query(Node *node, void *context);
static void pgan_hack_rte(RangeTblEntry *rte);
static bool pgan_is_role_anonymized(void);
static void pgan_object_relabel(const ObjectAddress *object,
							    const char *seclabel);


void
_PG_init(void)
{
	/*
	 * This extension can modify the Query in post_parse_analyze_hook, but
	 * doesn't have a way to adapt the raw query string accordingly.  This can
	 * cause problem with some extensions like pg_stat_statements that rely on
	 * both referring to the same thing.  To make sure that we don't cause
	 * interference, we process other post_parse_analyze_hook first before our
	 * own processing, but we have to make sure that we're the last module
	 * loaded.  Unfortunately we can only check that when our code is loaded,
	 * so we can only hope that no incompatible extension will be loaded
	 * afterwards.
	 */
	if (process_shared_preload_libraries_in_progress)
	{
		pgan_check_preload_lib(shared_preload_libraries_string,
							   "shared_preload_libraries", false);
	}
	else
	{
		/*
		 * Check on session_preload_libraries and local_preload_libraries in
		 * case that's how we're loaded.
		 */
		pgan_check_preload_lib(session_preload_libraries_string,
							   "session_preload_libraries", true);
		pgan_check_preload_lib(local_preload_libraries_string,
							   "local_preload_libraries", true);
	}

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

	DefineCustomBoolVariable("pg_anonymize.inherit_labels",
							 "Also use security label from parents if any.",
							 NULL,
							 &pgan_inherit_labels,
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
	char *prev_search_path;

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
	prev_search_path = pstrdup(namespace_search_path);
	PG_TRY();
	{
		XactReadOnly = true;
		set_config_option("search_path", "pg_catalog", PGC_SUSET,
						  PGC_S_SESSION, GUC_ACTION_SET, true, 0, false);
		SPI_execute(sql.data, true, 1);
		XactReadOnly = prev_xact_read_only;
		set_config_option("search_path", prev_search_path, PGC_SUSET,
						  PGC_S_SESSION, GUC_ACTION_SET, true, 0, false);
	}
	PG_CATCH();
	{
		XactReadOnly = prev_xact_read_only;
		set_config_option("search_path", prev_search_path, PGC_SUSET,
						  PGC_S_SESSION, GUC_ACTION_SET, true, 0, false);
		errcontext("during validation of expression \"%s\"", seclabel);
		PG_RE_THROW();
	}
	PG_END_TRY();

	/*
	 * No row in the source table, can't say about the expression apart that
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
					format_type_be(typid),
					format_type_be(att->atttypid));
		}
	}
	SPI_finish();
}

/*
 * Check that pg_anonymize is loaded last according to the given
 * xxx_preload_libraries_string.
 *
 * If missing_ok is true, don't raise an error if pg_anonymize is not present.
 */
static void
pgan_check_preload_lib(char *libnames, char *kind, bool missing_ok)
{
		List	   *xpl;
		ListCell   *lc;
		char	   *rawstring;
		char	   *libname;
		int			nb;

		/* Need a modifiable copy of string */
		rawstring = pstrdup(libnames);

		if (!SplitIdentifierString(rawstring, ',', &xpl))
			elog(ERROR, "Could not parse %s", kind);

		if (!missing_ok)
		{
			/* First a quick check to make sure we're the last element. */
			libname = (char *) llast(xpl);
			if (strcmp(libname, "pg_anonymize") != 0)
				elog(ERROR, "pg_anonymize needs to be last in %s", kind);
		}

		/*
		 * Some paranoid check: make sure we're not also somewhere else in the
		 * xxx_preload_libraries, as in that case we would not be loaded
		 * last.
		 */
		nb = 1;
		foreach(lc, xpl)
		{
			libname = (char *) lfirst(lc);

			if (nb != list_length(xpl) && strcmp(libname, "pg_anonymize") == 0)
				elog(ERROR, "pg_anonymize needs to be last in %s", kind);

			nb++;
		}
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
	char	  **seclabels;
	List	   *attnums;
	ListCell   *lc;
	TupleDesc	tupdesc;
	StringInfoData select;
	bool		first;

	/*
	 * We only anonymize plain (possibly partitioned) relations and
	 * materialized views.
	 */
	if (rel->rd_rel->relkind != RELKIND_RELATION &&
		rel->rd_rel->relkind != RELKIND_MATVIEW &&
		rel->rd_rel->relkind != RELKIND_PARTITIONED_TABLE)
		return NULL;

	/* COPY isn't allowed for partitioned table. */
	if (is_copy && rel->rd_rel->relkind == RELKIND_PARTITIONED_TABLE)
		return NULL;

	/* Fetch all the declared SECURITY LABEL on the relation. */
	seclabels = pgan_get_rel_seclabels(rel);

	/* Nothing to do if no SECURITY LABEL declared. */
	if (seclabels == NULL)
		return NULL;

	tupdesc = RelationGetDescr(rel);
	attnums = pgan_get_attnums(tupdesc, rel, attlist, is_copy);

	initStringInfo(&select);
	appendStringInfoString(&select, "SELECT ");

	first = true;
	foreach(lc, attnums)
	{
		FormData_pg_attribute *att;
		int attnum = lfirst_int(lc);

		if (!first)
			appendStringInfoString(&select, ", ");
		else
			first = false;

		att = TupleDescAttr(tupdesc, attnum - 1);

		/*
		 * If the column is anonymized, emit the proper expression, otherwise
		 * just emit the (quoted) column name.
		 */
		if (seclabels[attnum] != NULL)
		{
			appendStringInfo(&select, "%s AS %s", seclabels[attnum],
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
	appendStringInfo(&select, " FROM%s %s.%s",
					 (is_copy ? " ONLY" : ""),
					 quote_identifier(get_namespace_name(RelationGetNamespace(rel))),
					 quote_identifier(RelationGetRelationName(rel)));
	return select.data;
}

/*
 * Get all SECURITY LABELs for the given relation.
 *
 * This function returns an array, indexed by the underlying column attribute
 * number, of the security labels.
 *
 * If the relation doesn't have any security label defined, NULL is returned.
 */
static char **
pgan_get_rel_seclabels(Relation rel)
{
	pganWalkerContext *context;

	context = (pganWalkerContext *) palloc0(sizeof(pganWalkerContext));

	context->secRel = table_open(SecLabelRelationId, AccessShareLock);

	/* The worker function does all the work. */
	pgan_get_rel_seclabels_worker(rel, context);

	table_close(context->secRel, AccessShareLock);

	if (context->inhRel)
		table_close(context->inhRel, AccessShareLock);

	if (context->nb_labels == 0)
		return NULL;

	return context->seclabels;
}

/*
 * Function that looks for security labels for the given relation, and any of
 * its ancestor(s).
 *
 * This function will recurse, using a depth-first search, for all the given
 * relation ancestor(s) (if any) until either a security label has been found
 * for all columns of the original relation, or no more ancestor exist.
 *
 * Caller is responsible for opening and caching pg_catalog in secRel, with the
 * rest of the members zero-initialized.  This function will allocate the
 * seclabel array only if nb_labels is not zero and may open and cache
 * pg_inherits in inhRel.  Caller is also responsible for checking if inhRel is
 * cached and closing it in that case.
 */
static void
pgan_get_rel_seclabels_worker(Relation rel, pganWalkerContext *context)
{
	TupleDesc	tupdesc;
	AttrMap	   *attrMap;
	ScanKeyData keys[3];
	SysScanDesc scan;
	HeapTuple	tuple;

	ScanKeyInit(&keys[0],
				Anum_pg_seclabel_objoid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(RelationGetRelid(rel)));
	ScanKeyInit(&keys[1],
				Anum_pg_seclabel_classoid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(RelationRelationId));
	ScanKeyInit(&keys[2],
				Anum_pg_seclabel_provider,
				BTEqualStrategyNumber, F_TEXTEQ,
				CStringGetTextDatum(PGAN_PROVIDER));

	scan = systable_beginscan(context->secRel, SecLabelObjectIndexId, true,
							  NULL, 3, keys);

	tuple = systable_getnext(scan);

	/*
	 * Bail out if we didn't find any SECURITY LABEL for that relation and user
	 * don't want to inherit security labels, but after the necessary cleanup.
	 */
	if (!HeapTupleIsValid(tuple) && !pgan_inherit_labels)
	{
		systable_endscan(scan);
		return;
	}

	tupdesc = RelationGetDescr(rel);

	/*
	 * If this is the first call, we're passed the original relation.  In that
	 * case we save a copy of its tupledesc and allocate the seclabel array.
	 * Otherwise, we need to build an AttrMap as there's no guarantee that the
	 * original relation and the current ancestor have the same tuple
	 * descriptor.
	 */
	if (context->tupdesc == NULL)
	{
		context->tupdesc = CreateTupleDescCopy(tupdesc);
		/* No map needed. */
		attrMap = NULL;

		context->seclabels = palloc0(sizeof(char *) *
				/* AttrNumber is 1-based */
				(RelationGetNumberOfAttributes(rel) + 1));
	}
	else
	{
		attrMap = build_attrmap_by_name_if_req(context->tupdesc,
											   tupdesc
#if PG_VERSION_NUM >= 160000
											   , false
#endif
											   );
	}

	while (HeapTupleIsValid(tuple))
	{
		Datum		datum;
		bool		isnull;

		datum = heap_getattr(tuple, Anum_pg_seclabel_label,
							 RelationGetDescr(context->secRel), &isnull);
		if (!isnull)
		{
			int	attnum = ((FormData_pg_seclabel *) GETSTRUCT(tuple))->objsubid;

			/* If an AttrMap was build, get the mapped AttrNumber. */
			if (attrMap)
			{
				Assert(attnum <= attrMap->maplen);
				attnum = attrMap->attnums[attnum - 1];
				Assert(attnum <= context->tupdesc->natts);
			}

			/* Don't overload an existing security label. */
			if (context->seclabels[attnum] == NULL)
			{
				context->seclabels[attnum] = TextDatumGetCString(datum);
				context->nb_labels++;
			}
		}

		tuple = systable_getnext(scan);
	}
	systable_endscan(scan);

	if (attrMap)
		free_attrmap(attrMap);

	/*
	 * If we found a security label for all columns of the ancestor relation,
	 * or user don't want to inherit security labels, we're done!
	 */
	if (context->nb_labels == context->tupdesc->natts ||
		!pgan_inherit_labels)
	{
		return;
	}

	/* Check if we need to inherit security labels from ancestor */
	if (context->inhRel == NULL)
		context->inhRel = table_open(InheritsRelationId, AccessShareLock);

	ScanKeyInit(&keys[0],
				Anum_pg_inherits_inhrelid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(RelationGetRelid(rel)));

	scan = systable_beginscan(context->inhRel, InheritsRelidSeqnoIndexId, true,
							  NULL, 1, keys);

	/* Iterate over all ancestors if any, using a depth-first search. */
	while ((tuple = systable_getnext(scan)) != NULL)
	{
		Form_pg_inherits inh = (Form_pg_inherits) GETSTRUCT(tuple);
		Oid			inhparent = inh->inhparent;
		Relation	parentRel;

		parentRel = table_open(inhparent, AccessShareLock);

		pgan_get_rel_seclabels_worker(parentRel, context);

		table_close(parentRel, AccessShareLock);
	}
	systable_endscan(scan);
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

static bool
pgan_is_role_anonymized(void)
{
	ObjectAddress	addr;
	char		   *seclabel;

	ObjectAddressSet(addr, AuthIdRelationId, GetUserId());
	seclabel = GetSecurityLabel(&addr, PGAN_PROVIDER);

	return (seclabel && strcmp(seclabel, PGAN_ROLE_ANONYMIZED) == 0);
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
	/* XXX - should we try to prevent write queries ? */

	if (prev_post_parse_analyze_hook)
		prev_post_parse_analyze_hook(pstate, query
#if PG_VERSION_NUM >= 140000
				, jstate
#endif
				);

	/* Module disabled, recursive call or aborted transaction, bail out. */
	if (!pgan_enabled || !pgan_toplevel || !IsTransactionState())
		return;

	/* Role isn't declared as anonymized, bail out. */
	if (!pgan_is_role_anonymized())
		return;

	/*
	 * Walk the query and generate rewritten subqueries when needed.  We need
	 * to do this last as we don't have a way to generate a proper query string
	 * for that new Query, other any module relying on the Query and the
	 * query string to be consistent (like pg_stat_statements) would fail.
	 */
	pgan_hack_query((Node *) query, NULL);
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
	CopyStmt *stmt;
	char *sql;
	bool prev_toplevel = pgan_toplevel;
	const char *newsql = queryString;

	/* Module disabled, recursive call or not a COPY statement, bail out. */
	if (!pgan_enabled || !pgan_toplevel || !IsA(parsetree, CopyStmt))
		goto hook;

	stmt = (CopyStmt *) parsetree;

	/* Only intercept plain COPY relation TO */
	if (stmt->is_from || !stmt->relation)
		goto hook;

	if (!pgan_is_role_anonymized())
		goto hook;

	rel = relation_openrv(stmt->relation, AccessShareLock);
	sql = pgan_get_query_for_relid(rel, stmt->attlist, true);
	relation_close(rel, NoLock);

	/* If we got a query, use it in the COPY TO statement */
	if (sql)
	{
		List *parselist;
		StringInfoData copysql;

		PG_TRY();
		{
			parselist = pg_parse_query(sql);
			Assert(list_length(parselist) == 1);
			Assert(IsA(linitial(parselist), RawStmt));
		}
		PG_CATCH();
		{
			errcontext("during validation of expressions for anonymized table %s.%s",
					   quote_identifier(get_namespace_name(RelationGetNamespace(rel))),
					   quote_identifier(RelationGetRelationName(rel)));
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

		/*
		 * Generate a query string corresponding to the statement we're now
		 * really executing, and update all related field in the PlannedStmt.
		 */
		initStringInfo(&copysql);
		appendStringInfo(&copysql, "COPY (%s) TO ", sql);
		if (stmt->filename != NULL)
			appendStringInfo(&copysql, "'%s'",
							 quote_literal_cstr(stmt->filename));
		else
			appendStringInfoString(&copysql, "STDOUT");

		newsql = copysql.data;
		pstmt->stmt_location = 0;
		pstmt->stmt_len = strlen(newsql);
	}

hook:
	PG_TRY();
	{
		if (prev_ProcessUtility)
			prev_ProcessUtility(pstmt, newsql,
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
			standard_ProcessUtility(pstmt, newsql,
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
