/* Brilliant or insane?  You decide! */
#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/json_out/json_out.h>
#include <ccan/tal/str/str.h>
#include <common/deprecation.h>
#include <common/gossip_store.h>
#include <common/gossip_store_wiregen.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/setup.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <plugins/libplugin.h>
#include <sqlite3.h>
#include <stdio.h>
#include <unistd.h>

/* Minimized schemas.  C23 #embed, Where Art Thou? */
static const char schemas[] =
	#include "sql-schema_gen.h"
	;

/* TODO:
 * 10. General pagination API (not just chainmoves and channelmoves)
 * 11. Normalize account_id fields into another table, as they are highly duplicate, and use views to maintain the current API.
*/
enum fieldtype {
	/* Hex variants */
	FIELD_HEX,
	FIELD_HASH,
	FIELD_SECRET,
	FIELD_PUBKEY,
	FIELD_TXID,
	/* Integer variants */
	FIELD_MSAT,
	FIELD_INTEGER,
	FIELD_U64,
	FIELD_U32,
	FIELD_U16,
	FIELD_U8,
	FIELD_BOOL,
	/* Randoms */
	FIELD_NUMBER,
	FIELD_STRING,
	FIELD_SCID,
	FIELD_OUTPOINT,
};

struct fieldtypemap {
	const char *name;
	const char *sqltype;
};

static const struct fieldtypemap fieldtypemap[] = {
	{ "hex", "BLOB" }, /* FIELD_HEX */
	{ "hash", "BLOB" }, /* FIELD_HASH */
	{ "secret", "BLOB" }, /* FIELD_SECRET */
	{ "pubkey", "BLOB" }, /* FIELD_PUBKEY */
	{ "txid", "BLOB" }, /* FIELD_TXID */
	{ "msat", "INTEGER" }, /* FIELD_MSAT */
	{ "integer", "INTEGER" }, /* FIELD_INTEGER */
	{ "u64", "INTEGER" }, /* FIELD_U64 */
	{ "u32", "INTEGER" }, /* FIELD_U32 */
	{ "u16", "INTEGER" }, /* FIELD_U16 */
	{ "u8", "INTEGER" }, /* FIELD_U8 */
	{ "boolean", "INTEGER" }, /* FIELD_BOOL */
	{ "number", "REAL" }, /* FIELD_NUMBER */
	{ "string", "TEXT" }, /* FIELD_STRING */
	{ "short_channel_id", "TEXT" }, /* FIELD_SCID */
	{ "outpoint", "TEXT" }, /* FIELD_OUTPOINT */
};

struct column {
	/* We rename some fields to avoid sql keywords!
	 * And jsonname is NULL if this is a simple array. */
	const char *dbname, *jsonname;
	enum fieldtype ftype;

	/* Deprecation version range, if any. */
	const char *depr_start, *depr_end;
	/* If this is actually a subtable: */
	struct table_desc *sub;
};

struct db_query {
	struct command *cmd;
	sqlite3_stmt *stmt;
	struct table_desc **tables;
	const char *authfail;
	bool has_wildcard;
};

/* Waiting for another command to refresh table */
struct refresh_waiter {
	struct list_node list;
	struct command *cmd;
	struct db_query *dbq;
};

enum refresh_needs {
	/* Naive tables always need refresh */
	REFRESH_ALWAYS = 0x8,

	/* Up-to-date! */
	REFRESH_UNNECESSARY = 0,
	/* We were notified of new created entries */
	REFRESH_CREATED = 0x1,
	/* We were notified of new updated entries */
	REFRESH_UPDATED = 0x2,
	/* We were notified of new deleted entries */
	REFRESH_DELETED = 0x4,
};

struct table_desc {
	/* e.g. listpeers.  For sub-tables, the raw name without
	 * parent prepended */
	const char *cmdname;
	/* e.g. peers for listpeers, peers_channels for listpeers.channels. */
	const char *name;
	/* e.g. "payments" for listsendpays */
	const char *arrname;
	/* name if we need to wait for changes */
	const char *waitname;
	struct column **columns;
	char *update_stmt;
	/* If we are a subtable */
	struct table_desc *parent;
	/* Is this a sub object (otherwise, subarray if parent is true) */
	bool is_subobject;
	/* Do we use created_index as primary key?  Otherwise we create rowid. */
	bool has_created_index;
	/* Have we ever been used? */
	bool populated;
	/* function to refresh it. */
	struct command_result *(*refresh)(struct command *cmd,
					  struct table_desc *td,
					  struct db_query *dbq);
	/* some refresh functions maintain changed and created indexes */
	u64 last_created_index;
	u64 last_updated_index;
	/* Do we need a refresh? */
	enum refresh_needs refresh_needs;
	/* Are we refreshing now? */
	bool refreshing;
	/* When did we start refreshing? */
	struct timemono refresh_start;
	/* Any other commands waiting for the refresh completion */
	struct list_head refresh_waiters;
};

typedef STRMAP(struct table_desc *) tablemap;
struct sql {
	tablemap tablemap;
	struct sqlite3 *db;
	char *dbfilename;
	int gosstore_fd ;
	size_t gosstore_nodes_off, gosstore_channels_off;
	u64 next_rowid;

	/* This is an aux_command for all our watches */
	struct command *waitcmd;
};

static struct sql *sql_of(struct plugin *plugin)
{
	return plugin_get_data(plugin, struct sql);
}

/* It was tempting to put these in the schema, but they're really
 * just for our usage.  Though that would allow us to autogen the
 * documentation, too. */
struct index {
	const char *tablename;
	const char *fields[2];
};
static const struct index indices[] = {
	{
		"channels",
		{ "short_channel_id", NULL },
	},
	{
		"forwards",
		{ "in_channel", "in_htlc_id" },
	},
	{
		"htlcs",
		{ "short_channel_id", "id" },
	},
	{
		"invoices",
		{ "payment_hash", NULL },
	},
	{
		"nodes",
		{ "nodeid", NULL },
	},
	{
		"offers",
		{ "offer_id", NULL },
	},
	{
		"peers",
		{ "id", NULL },
	},
	{
		"peerchannels",
		{ "peer_id", NULL },
	},
	{
		"sendpays",
		{ "payment_hash", NULL },
	},
	{
		"transactions",
		{ "hash", NULL },
	},
	{
		"chainmoves",
		{ "account_id", NULL },
	},
	{
		"channelmoves",
		{ "account_id", NULL },
	},
	{
		"channelmoves",
		{ "payment_hash", NULL },
	},
};

static enum fieldtype find_fieldtype(const jsmntok_t *name)
{
	for (size_t i = 0; i < ARRAY_SIZE(fieldtypemap); i++) {
		if (json_tok_streq(schemas, name, fieldtypemap[i].name))
			return i;
	}
	errx(1, "Unknown JSON type %.*s",
	     name->end - name->start, schemas + name->start);
}

static struct sqlite3 *sqlite_setup(struct plugin *plugin)
{
	int err;
	struct sqlite3 *db;
	char *errmsg;
	struct sql *sql = sql_of(plugin);

	if (sql->dbfilename) {
		err = sqlite3_open_v2(sql->dbfilename, &db,
				      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
				      NULL);
	} else {
		err = sqlite3_open_v2("", &db,
				      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE
				      | SQLITE_OPEN_MEMORY,
				      NULL);
	}
	if (err != SQLITE_OK)
		plugin_err(plugin, "Could not create db: errcode %u", err);

	sqlite3_extended_result_codes(db, 1);

	/* From https://www.sqlite.org/c3ref/set_authorizer.html:
	 *
	 * Applications that need to process SQL from untrusted
	 * sources might also consider lowering resource limits using
	 * sqlite3_limit() and limiting database size using the
	 * max_page_count PRAGMA in addition to using an authorizer.
	 */
	sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 1000000);
	sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 10000);
	sqlite3_limit(db, SQLITE_LIMIT_COLUMN, 100);
	sqlite3_limit(db, SQLITE_LIMIT_EXPR_DEPTH, 100);
	sqlite3_limit(db, SQLITE_LIMIT_COMPOUND_SELECT, 10);
	sqlite3_limit(db, SQLITE_LIMIT_VDBE_OP, 1000);
	sqlite3_limit(db, SQLITE_LIMIT_ATTACHED, 1);
	sqlite3_limit(db, SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 500);
	sqlite3_limit(db, SQLITE_LIMIT_VARIABLE_NUMBER, 100);
	sqlite3_limit(db, SQLITE_LIMIT_TRIGGER_DEPTH, 1);
	sqlite3_limit(db, SQLITE_LIMIT_WORKER_THREADS, 1);

	err = sqlite3_exec(db, "PRAGMA foreign_keys = ON;", NULL, NULL, &errmsg);
	if (err != SQLITE_OK)
		plugin_err(plugin, "Could not set foreign_keys: %s", errmsg);

	if (sql->dbfilename) {
		err = sqlite3_exec(db,
				   "PRAGMA synchronous = OFF;"
				   "PRAGMA journal_mode = OFF;"
				   "PRAGMA temp_store = MEMORY;"
				   , NULL, NULL,
				   &errmsg);
		if (err != SQLITE_OK)
			plugin_err(plugin, "Could not disable sync: %s", errmsg);
	}

	return db;
}

static bool has_table_desc(struct table_desc **tables, struct table_desc *t)
{
	for (size_t i = 0; i < tal_count(tables); i++) {
		if (tables[i] == t)
			return true;
	}
	return false;
}

static struct column *find_column(const struct table_desc *td,
				  const char *dbname)
{
	for (size_t i = 0; i < tal_count(td->columns); i++) {
		if (streq(td->columns[i]->dbname, dbname))
			return td->columns[i];
	}
	return NULL;
}

static int sqlite_authorize(void *dbq_, int code,
			    const char *a,
			    const char *b,
			    const char *c,
			    const char *d)
{
	struct db_query *dbq = dbq_;

	/* You can do select statements */
	if (code == SQLITE_SELECT)
		return SQLITE_OK;

	/* You can do a column read: takes a table name, column name */
	if (code == SQLITE_READ) {
		struct sql *sql = sql_of(dbq->cmd->plugin);
		struct table_desc *td = strmap_get(&sql->tablemap, a);
		struct column *col;
		if (!td) {
			dbq->authfail = tal_fmt(dbq, "Unknown table %s", a);
			return SQLITE_DENY;
		}
		/* If it has a parent, we refresh that instead */
		while (td->parent)
			td = td->parent;
		if (!has_table_desc(dbq->tables, td))
			tal_arr_expand(&dbq->tables, td);

		/* Check column name, to control access to deprecated ones. */
		col = find_column(td, b);
		if (!col) {
			/* Magic column names like id, __id__ etc. */
			return SQLITE_OK;
		}

		/* Don't do tal if we are not deprecated at all */
		if (!col->depr_start)
			return SQLITE_OK;

		/* Can this command see this?  We have to allow this
		* (as null) with "SELECT *" though! */
		if (!command_deprecated_in_named_ok(dbq->cmd, td->cmdname,
						    col->jsonname,
						    col->depr_start,
						    col->depr_end)) {
			if (dbq->has_wildcard)
				return SQLITE_IGNORE;
			dbq->authfail = tal_fmt(dbq, "Deprecated column table %s.%s", a, b);
			return SQLITE_DENY;
		}

		return SQLITE_OK;
	}

	/* Some functions are fairly necessary: */
	if (code == SQLITE_FUNCTION) {
		if (streq(b, "abs"))
			return SQLITE_OK;
		if (streq(b, "avg"))
			return SQLITE_OK;
		if (streq(b, "coalesce"))
			return SQLITE_OK;
		if (streq(b, "count"))
			return SQLITE_OK;
		if (streq(b, "hex"))
			return SQLITE_OK;
		if (streq(b, "quote"))
			return SQLITE_OK;
		if (streq(b, "length"))
			return SQLITE_OK;
		if (streq(b, "like"))
			return SQLITE_OK;
		if (streq(b, "lower"))
			return SQLITE_OK;
		if (streq(b, "upper"))
			return SQLITE_OK;
		if (streq(b, "min"))
			return SQLITE_OK;
		if (streq(b, "max"))
			return SQLITE_OK;
		if (streq(b, "sum"))
			return SQLITE_OK;
		if (streq(b, "total"))
			return SQLITE_OK;
		if (streq(b, "date"))
			return SQLITE_OK;
		if (streq(b, "datetime"))
			return SQLITE_OK;
		if (streq(b, "julianday"))
			return SQLITE_OK;
		if (streq(b, "strftime"))
			return SQLITE_OK;
		if (streq(b, "time"))
			return SQLITE_OK;
		if (streq(b, "timediff"))
			return SQLITE_OK;
		if (streq(b, "unixepoch"))
			return SQLITE_OK;
		if (streq(b, "json_object"))
			return SQLITE_OK;
		if (streq(b, "json_group_array"))
			return SQLITE_OK;
	}

	/* See https://www.sqlite.org/c3ref/c_alter_table.html to decode these! */
	dbq->authfail = tal_fmt(dbq, "Unauthorized: %u arg1=%s arg2=%s dbname=%s caller=%s",
				code,
				a ? a : "(none)",
				b ? b : "(none)",
				c ? c : "(none)",
				d ? d : "(none)");
	return SQLITE_DENY;
}

static struct command_result *refresh_complete(struct command *cmd,
					       struct db_query *dbq)
{
	struct sql *sql = sql_of(cmd->plugin);
	char *errmsg;
	int err, num_cols;
	size_t num_rows;
	struct json_stream *ret;

	num_cols = sqlite3_column_count(dbq->stmt);

	/* We normally hit an error immediately, so return a simple error then */
	ret = NULL;
	num_rows = 0;
	errmsg = NULL;

	while ((err = sqlite3_step(dbq->stmt)) == SQLITE_ROW) {
		if (!ret) {
			ret = jsonrpc_stream_success(cmd);
			json_array_start(ret, "rows");
		}
		json_array_start(ret, NULL);
		for (size_t i = 0; i < num_cols; i++) {
			/* The returned value is one of
			 * SQLITE_INTEGER, SQLITE_FLOAT, SQLITE_TEXT,
			 * SQLITE_BLOB, or SQLITE_NULL */
			switch (sqlite3_column_type(dbq->stmt, i)) {
			case SQLITE_INTEGER: {
				s64 v = sqlite3_column_int64(dbq->stmt, i);
				json_add_s64(ret, NULL, v);
				break;
			}
			case SQLITE_FLOAT: {
				double v = sqlite3_column_double(dbq->stmt, i);
				json_add_primitive_fmt(ret, NULL, "%f", v);
				break;
			}
			case SQLITE_TEXT: {
				const char *c = (char *)sqlite3_column_text(dbq->stmt, i);
				if (!utf8_check(c, strlen(c))) {
					json_add_str_fmt(ret, NULL,
							 "INVALID UTF-8 STRING %s",
							 tal_hexstr(tmpctx, c, strlen(c)));
					errmsg = tal_fmt(cmd, "Invalid UTF-8 string row %zu column %zu",
							 num_rows, i);
				} else
					json_add_string(ret, NULL, c);
				break;
			}
			case SQLITE_BLOB:
				json_add_hex(ret, NULL,
					     sqlite3_column_blob(dbq->stmt, i),
					     sqlite3_column_bytes(dbq->stmt, i));
				break;
			case SQLITE_NULL:
				json_add_primitive(ret, NULL, "null");
				break;
			default:
				errmsg = tal_fmt(cmd, "Unknown column type %i in row %zu column %zu",
						 sqlite3_column_type(dbq->stmt, i),
						 num_rows, i);
			}
		}
		json_array_end(ret);
		num_rows++;
	}
	if (err != SQLITE_DONE)
		errmsg = tal_fmt(cmd, "Executing statement: %s",
				 sqlite3_errmsg(sql->db));

	sqlite3_finalize(dbq->stmt);


	/* OK, did we hit some error during?  Simple if we didn't
	 * already start answering! */
	if (errmsg) {
		if (!ret)
			return command_fail(cmd, LIGHTNINGD, "%s", errmsg);

		/* Otherwise, add it as a warning */
		json_array_end(ret);
		json_add_string(ret, "warning_db_failure", errmsg);
	} else {
		/* Empty result is possible, OK. */
		if (!ret) {
			ret = jsonrpc_stream_success(cmd);
			json_array_start(ret, "rows");
		}
		json_array_end(ret);
	}
	return command_finished(cmd, ret);
}

static void init_indices(struct plugin *plugin, const struct table_desc *td)
{
	struct sql *sql = sql_of(plugin);

	for (size_t i = 0; i < ARRAY_SIZE(indices); i++) {
		char *errmsg, *cmd;
		int err;

		if (!streq(indices[i].tablename, td->name))
			continue;

		cmd = tal_fmt(tmpctx, "CREATE INDEX %s_%zu_idx ON %s (%s",
			      indices[i].tablename, i,
			      indices[i].tablename,
			      indices[i].fields[0]);
		if (indices[i].fields[1])
			tal_append_fmt(&cmd, ", %s", indices[i].fields[1]);
		tal_append_fmt(&cmd, ");");
		err = sqlite3_exec(sql->db, cmd, NULL, NULL, &errmsg);
		if (err != SQLITE_OK)
			plugin_err(plugin, "Failed '%s': %s", cmd, errmsg);
	}
}

/* Recursion */
static struct command_result *refresh_tables(struct command *cmd,
					     struct db_query *dbq);

static struct command_result *next_refresh(struct command *cmd,
					   struct db_query *dbq)
{
	/* Remove that, iterate */
	tal_arr_remove(&dbq->tables, 0);
	return refresh_tables(cmd, dbq);
}

/* Recursion */
static struct command_result *one_refresh_done(struct command *cmd,
					       struct db_query *dbq,
					       bool was_limited)
{
	struct table_desc *td = dbq->tables[0];
	struct list_head waiters;
	struct refresh_waiter *rw;
	struct timerel refresh_duration = timemono_since(td->refresh_start);

	/* If we may have more, keep going. */
	if (was_limited)
		return td->refresh(cmd, dbq->tables[0], dbq);

	/* We are no longer refreshing */
	assert(td->refreshing);
	td->refreshing = false;
	plugin_log(cmd->plugin, LOG_DBG,
		   "Time to refresh %s: %"PRIu64".%09"PRIu64" seconds (last=%"PRIu64")",
		   td->name,
		   (u64)refresh_duration.ts.tv_sec,
		   (u64)refresh_duration.ts.tv_nsec,
		   td->last_created_index);

	if (!td->populated) {
		/* Now we've done initial population, install indices:
		 * much faster than creating them before! */
		init_indices(cmd->plugin, td);
		td->populated = true;
		refresh_duration = timemono_since(td->refresh_start);
		plugin_log(cmd->plugin, LOG_DBG,
			   "Time to refresh + create indices for %s: %"PRIu64".%09"PRIu64" seconds",
			   td->name,
			   (u64)refresh_duration.ts.tv_sec,
			   (u64)refresh_duration.ts.tv_nsec);
	}

	/* Transfer refresh waiters onto local list */
	list_head_init(&waiters);
	list_append_list(&waiters, &td->refresh_waiters);

	while ((rw = list_pop(&waiters, struct refresh_waiter, list)) != NULL) {
		struct command *rwcmd = rw->cmd;
		struct db_query *rwdbq = rw->dbq;
		tal_free(rw);

		/* Remove that one, and refresh the rest */
		assert(rwdbq->tables[0] == td);
		tal_arr_remove(&rwdbq->tables, 0);
		refresh_tables(rwcmd, rwdbq);
	}
	return next_refresh(cmd, dbq);
}

/* Mutual recursion */
static struct command_result *process_json_list(struct command *cmd,
						const char *buf,
						const jsmntok_t *arr,
						const u64 *rowid,
						const struct table_desc *td,
						u64 *last_created_index,
						u64 *last_updated_index);

/* Process all subobject columns */
static struct command_result *process_json_subobjs(struct command *cmd,
						   const char *buf,
						   const jsmntok_t *t,
						   const struct table_desc *td,
						   u64 this_rowid,
						   u64 *last_created_index,
						   u64 *last_updated_index)
{
	for (size_t i = 0; i < tal_count(td->columns); i++) {
		const struct column *col = td->columns[i];
		struct command_result *ret;
		const jsmntok_t *coltok;

		if (!col->sub)
			continue;

		coltok = json_get_member(buf, t, col->jsonname);
		if (!coltok)
			continue;

		/* If it's an array, use process_json_list */
		if (!col->sub->is_subobject) {
			ret = process_json_list(cmd, buf, coltok, &this_rowid,
						col->sub, last_created_index, last_updated_index);
		} else {
			ret = process_json_subobjs(cmd, buf, coltok, col->sub,
						   this_rowid, last_created_index, last_updated_index);
		}
		if (ret)
			return ret;
	}
	return NULL;
}

/* Returns NULL on success, otherwise has failed cmd. */
static struct command_result *process_json_obj(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *t,
					       const struct table_desc *td,
					       size_t row,
					       u64 this_rowid,
					       const u64 *parent_rowid,
					       size_t *sqloff,
					       sqlite3_stmt *stmt,
					       u64 *last_created_index,
					       u64 *last_updated_index)
{
	struct sql *sql = sql_of(cmd->plugin);
	int err;

	/* Subtables have row, arrindex as first two columns. */
	if (parent_rowid) {
		sqlite3_bind_int64(stmt, (*sqloff)++, *parent_rowid);
		sqlite3_bind_int64(stmt, (*sqloff)++, row);
	}

	/* FIXME: This is O(n^2): hash td->columns and look up the other way. */
	for (size_t i = 0; i < tal_count(td->columns); i++) {
		const struct column *col = td->columns[i];
		const jsmntok_t *coltok;

		if (col->sub) {
			struct command_result *ret;
			/* Handle sub-tables below: we need rowid! */
			if (!col->sub->is_subobject)
				continue;

			/* This can happen if the field is missing */
			if (!t)
				coltok = NULL;
			else
				coltok = json_get_member(buf, t, col->jsonname);
			ret = process_json_obj(cmd, buf, coltok, col->sub, row, this_rowid,
					       NULL, sqloff, stmt, last_created_index, last_updated_index);
			if (ret)
				return ret;
			continue;
		}

		/* This can happen if subobject does not exist in output! */
		if (!t)
			coltok = NULL;
		else {
			/* Array of primitives? */
			if (!col->jsonname)
				coltok = t;
			else
				coltok = json_get_member(buf, t, col->jsonname);
		}

		if (!coltok) {
			if (td->parent)
				plugin_log(cmd->plugin, LOG_DBG,
					   "Did not find json %s for %s in %.*s",
					   col->jsonname, td->name,
					   t ? json_tok_full_len(t) : 4, t ? json_tok_full(buf, t): "NULL");
			sqlite3_bind_null(stmt, (*sqloff)++);
		} else {
			u64 val64;
			struct amount_msat valmsat;
			u8 *valhex;
			double valdouble;
			bool valbool;

			switch (col->ftype) {
			case FIELD_U8:
			case FIELD_U16:
			case FIELD_U32:
			case FIELD_U64:
			case FIELD_INTEGER:
				if (!json_to_u64(buf, coltok, &val64)) {
					return command_fail(cmd, LIGHTNINGD,
							    "column %zu row %zu not a u64: %.*s",
							    i, row,
							    json_tok_full_len(coltok),
							    json_tok_full(buf, coltok));
				}
				sqlite3_bind_int64(stmt, (*sqloff)++, val64);
				/* created_index -> last_created_index */
				if (streq(col->dbname, "created_index")
				    && val64 > *last_created_index) {
					*last_created_index = val64;
				}
				/* updated_index -> last_updated_index */
				if (streq(col->dbname, "updated_index")
				    && val64 > *last_updated_index) {
					*last_updated_index = val64;
				}
				break;
			case FIELD_BOOL:
				if (!json_to_bool(buf, coltok, &valbool)) {
					return command_fail(cmd, LIGHTNINGD,
							    "column %zu row %zu not a boolean: %.*s",
							    i, row,
							    json_tok_full_len(coltok),
							    json_tok_full(buf, coltok));
				}
				sqlite3_bind_int(stmt, (*sqloff)++, valbool);
				break;
			case FIELD_NUMBER:
				if (!json_to_double(buf, coltok, &valdouble)) {
					return command_fail(cmd, LIGHTNINGD,
							    "column %zu row %zu not a double: %.*s",
							    i, row,
							    json_tok_full_len(coltok),
							    json_tok_full(buf, coltok));
				}
				sqlite3_bind_double(stmt, (*sqloff)++, valdouble);
				break;
			case FIELD_MSAT:
				if (!json_to_msat(buf, coltok, &valmsat)) {
					return command_fail(cmd, LIGHTNINGD,
							    "column %zu row %zu not an msat: %.*s",
							    i, row,
							    json_tok_full_len(coltok),
							    json_tok_full(buf, coltok));
				}
				sqlite3_bind_int64(stmt, (*sqloff)++, valmsat.millisatoshis /* Raw: db */);
				break;
			case FIELD_SCID:
			case FIELD_STRING:
			case FIELD_OUTPOINT:
				sqlite3_bind_text(stmt, (*sqloff)++, buf + coltok->start,
						  coltok->end - coltok->start,
						  SQLITE_STATIC);
				break;
			case FIELD_HEX:
			case FIELD_HASH:
			case FIELD_SECRET:
			case FIELD_PUBKEY:
			case FIELD_TXID:
				valhex = json_tok_bin_from_hex(tmpctx, buf, coltok);
				if (!valhex) {
					return command_fail(cmd, LIGHTNINGD,
							    "column %zu row %zu not valid hex: %.*s",
							    i, row,
							    json_tok_full_len(coltok),
							    json_tok_full(buf, coltok));
				}
				sqlite3_bind_blob(stmt, (*sqloff)++, valhex, tal_count(valhex),
						  SQLITE_STATIC);
				break;
			}
		}
	}

	/* Sub objects get folded into parent's SQL */
	if (td->parent && td->is_subobject)
		return NULL;

	err = sqlite3_step(stmt);
	if (err != SQLITE_DONE) {
		return command_fail(cmd, LIGHTNINGD,
				    "Error executing %s on row %zu: %s",
				    td->update_stmt,
				    row,
				    sqlite3_errmsg(sql->db));
	}

	return process_json_subobjs(cmd, buf, t, td, this_rowid, last_created_index, last_updated_index);
}

/* A list, such as in the top-level reply, or for a sub-table */
static struct command_result *process_json_list(struct command *cmd,
						const char *buf,
						const jsmntok_t *arr,
						const u64 *parent_rowid,
						const struct table_desc *td,
						u64 *last_created_index,
						u64 *last_updated_index)
{
	struct sql *sql = sql_of(cmd->plugin);
	size_t i;
	const jsmntok_t *t;
	int err;
	sqlite3_stmt *stmt;
	struct command_result *ret = NULL;

	err = sqlite3_prepare_v2(sql->db, td->update_stmt, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		return command_fail(cmd, LIGHTNINGD, "preparing '%s' failed: %s",
				    td->update_stmt,
				    sqlite3_errmsg(sql->db));
	}

	json_for_each_arr(i, t, arr) {
		/* sqlite3 columns are 1-based! */
		size_t off = 1;
		u64 this_rowid;

		if (!td->has_created_index) {
			this_rowid = sql->next_rowid++;
			/* First entry is always the rowid */
			sqlite3_bind_int64(stmt, off++, this_rowid);
		} else {
			if (!json_to_u64(buf,
					 json_get_member(buf, t, "created_index"),
					 &this_rowid))
				return command_fail(cmd, LIGHTNINGD, "No created_index in %s? '%.*s'",
						    td->cmdname,
						    json_tok_full_len(t),
						    json_tok_full(buf, t));
		}
		ret = process_json_obj(cmd, buf, t, td, i, this_rowid, parent_rowid, &off, stmt, last_created_index, last_updated_index);
		if (ret)
			break;
		sqlite3_reset(stmt);
	}
	sqlite3_finalize(stmt);
	return ret;
}

/* Process top-level JSON result object */
static struct command_result *process_json_result(struct command *cmd,
						  const char *buf,
						  const jsmntok_t *result,
						  const struct table_desc *td,
						  u64 *last_created_index,
						  u64 *last_updated_index,
						  size_t *num_entries)
{
	const jsmntok_t *arr;
	struct timerel so_far = timemono_since(td->refresh_start);
	plugin_log(cmd->plugin, LOG_DBG,
		   "Time to call %s: %"PRIu64".%09"PRIu64" seconds",
		   td->cmdname,
		   (u64)so_far.ts.tv_sec, (u64)so_far.ts.tv_nsec);

	arr = json_get_member(buf, result, td->arrname);
	if (num_entries)
		*num_entries = arr->size;
	return process_json_list(cmd, buf, arr, NULL, td, last_created_index, last_updated_index);
}

static struct command_result *default_list_done(struct command *cmd,
						const char *method,
						const char *buf,
						const jsmntok_t *result,
						struct db_query *dbq)
{
	struct sql *sql = sql_of(cmd->plugin);
	struct table_desc *td = dbq->tables[0];
	struct command_result *ret;
	int err;
	char *errmsg;

	/* FIXME: this is where a wait / pagination API is useful! */
	err = sqlite3_exec(sql->db, tal_fmt(tmpctx, "DELETE FROM %s;", td->name),
			   NULL, NULL, &errmsg);
	if (err != SQLITE_OK) {
		return command_fail(cmd, LIGHTNINGD, "cleaning '%s' failed: %s",
				    td->name, errmsg);
	}

	ret = process_json_result(cmd, buf, result, td, &td->last_created_index, &td->last_updated_index, NULL);
	if (ret)
		return ret;

	return one_refresh_done(cmd, dbq, false);
}

static struct command_result *default_refresh(struct command *cmd,
					      struct table_desc *td,
					      struct db_query *dbq)
{
	struct out_req *req;
	req = jsonrpc_request_start(cmd, td->cmdname,
				    default_list_done, forward_error,
				    dbq);
	return send_outreq(req);
}

static bool extract_scid(int gosstore_fd, size_t off, u16 type,
			 struct short_channel_id *scid)
{
	be64 raw;

	/* BOLT #7:
	 * 1. type: 258 (`channel_update`)
	 * 2. data:
	 *     * [`signature`:`signature`]
	 *     * [`chain_hash`:`chain_hash`]
	 *     * [`short_channel_id`:`short_channel_id`]
	 */
	/* Note that first two bytes are message type */
	const size_t update_scid_off = 2 + (64 + 32);

	off += sizeof(struct gossip_hdr);
	/* For delete_chan scid immediately follows type */
	if (type == WIRE_GOSSIP_STORE_DELETE_CHAN)
		off += 2;
	else if (type == WIRE_GOSSIP_STORE_PRIVATE_UPDATE_OBS)
		/* Prepend header */
		off += 2 + 2 + update_scid_off;
	else if (type == WIRE_CHANNEL_UPDATE)
		off += update_scid_off;
	else
		abort();

	if (pread(gosstore_fd, &raw, sizeof(raw), off) != sizeof(raw))
		return false;
	scid->u64 = be64_to_cpu(raw);
	return true;
}

/* Note: this deletes up to two rows, one for each direction. */
static void delete_channel_from_db(struct command *cmd,
				   struct short_channel_id scid)
{
	struct sql *sql = sql_of(cmd->plugin);
	int err;
	char *errmsg;

	err = sqlite3_exec(sql->db,
			   tal_fmt(tmpctx,
				   "DELETE FROM channels"
				   " WHERE short_channel_id = '%s'",
				   fmt_short_channel_id(tmpctx, scid)),
			   NULL, NULL, &errmsg);
	if (err != SQLITE_OK)
		plugin_err(cmd->plugin, "Could not delete from channels: %s",
			   errmsg);
}

static struct command_result *channels_refresh(struct command *cmd,
					       struct table_desc *td,
					       struct db_query *dbq);

static struct command_result *listchannels_one_done(struct command *cmd,
						    const char *method,
						    const char *buf,
						    const jsmntok_t *result,
						    struct db_query *dbq)
{
	struct table_desc *td = dbq->tables[0];
	struct command_result *ret;

	ret = process_json_result(cmd, buf, result, td, &td->last_created_index, &td->last_updated_index, NULL);
	if (ret)
		return ret;

	/* Continue to refresh more channels */
	return channels_refresh(cmd, td, dbq);
}

static struct command_result *channels_refresh(struct command *cmd,
					       struct table_desc *td,
					       struct db_query *dbq)
{
	struct sql *sql = sql_of(cmd->plugin);
	struct out_req *req;
	size_t msglen;
	u16 type, flags;

	if (sql->gosstore_fd == -1) {
		sql->gosstore_fd = open("gossip_store", O_RDONLY);
		if (sql->gosstore_fd == -1)
			plugin_err(cmd->plugin, "Could not open gossip_store: %s",
				   strerror(errno));
	}

	/* First time, set off to end and load from scratch */
	if (sql->gosstore_channels_off == 0) {
		sql->gosstore_channels_off = find_gossip_store_end(sql->gosstore_fd, 1);
		return default_refresh(cmd, td, dbq);
	}

	plugin_log(cmd->plugin, LOG_DBG, "Refreshing channels @%zu...",
		   sql->gosstore_channels_off);

	/* OK, try catching up! */
	while (gossip_store_readhdr(sql->gosstore_fd, sql->gosstore_channels_off,
				    &msglen, NULL, &flags, &type)) {
		struct short_channel_id scid;
		size_t off = sql->gosstore_channels_off;

		sql->gosstore_channels_off += sizeof(struct gossip_hdr) + msglen;

		if (flags & GOSSIP_STORE_DELETED_BIT)
			continue;

		if (type == WIRE_GOSSIP_STORE_ENDED) {
			/* Force a reopen */
			sql->gosstore_channels_off = sql->gosstore_nodes_off = 0;
			close(sql->gosstore_fd);
			sql->gosstore_fd = -1;
			return channels_refresh(cmd, td, dbq);
		}

		/* If we see a channel_announcement, we don't care until we
		 * see the channel_update */
		if (type == WIRE_CHANNEL_UPDATE
		    || type == WIRE_GOSSIP_STORE_PRIVATE_UPDATE_OBS) {
			/* This can fail if entry not fully written yet. */
			if (!extract_scid(sql->gosstore_fd, off, type, &scid)) {
				sql->gosstore_channels_off = off;
				break;
			}

			plugin_log(cmd->plugin, LOG_DBG, "Refreshing channel: %s",
				   fmt_short_channel_id(tmpctx, scid));
			/* FIXME: sqlite3 version 3.24.0 (2018-06-04) added
			 * UPSERT, but we don't require it. */
			delete_channel_from_db(cmd, scid);
			req = jsonrpc_request_start(cmd, "listchannels",
						    listchannels_one_done,
						    forward_error,
						    dbq);
			json_add_short_channel_id(req->js, "short_channel_id", scid);
			return send_outreq(req);
		} else if (type == WIRE_GOSSIP_STORE_DELETE_CHAN) {
			/* This can fail if entry not fully written yet. */
			if (!extract_scid(sql->gosstore_fd, off, type, &scid)) {
				sql->gosstore_channels_off = off;
				break;
			}
			plugin_log(cmd->plugin, LOG_DBG, "Deleting channel: %s",
				   fmt_short_channel_id(tmpctx, scid));
			delete_channel_from_db(cmd, scid);
		}
	}

	return one_refresh_done(cmd, dbq, false);
}

static struct command_result *nodes_refresh(struct command *cmd,
					    struct table_desc *td,
					    struct db_query *dbq);

static struct command_result *listnodes_one_done(struct command *cmd,
						 const char *method,
						 const char *buf,
						 const jsmntok_t *result,
						 struct db_query *dbq)
{
	struct table_desc *td = dbq->tables[0];
	struct command_result *ret;

	ret = process_json_result(cmd, buf, result, td, &td->last_created_index, &td->last_updated_index, NULL);
	if (ret)
		return ret;

	/* Continue to refresh more nodes */
	return nodes_refresh(cmd, td, dbq);
}

static void delete_node_from_db(struct command *cmd,
				const struct node_id *id)
{
	struct sql *sql = sql_of(cmd->plugin);
	int err;
	char *errmsg;

	err = sqlite3_exec(sql->db,
			   tal_fmt(tmpctx,
				   "DELETE FROM nodes"
				   " WHERE nodeid = X'%s'",
				   fmt_node_id(tmpctx, id)),
			   NULL, NULL, &errmsg);
	if (err != SQLITE_OK)
		plugin_err(cmd->plugin, "Could not delete from nodes: %s",
			   errmsg);
}

static bool extract_node_id(int gosstore_fd, size_t off, u16 type,
			    struct node_id *id)
{
	/* BOLT #7:
	 * 1. type: 257 (`node_announcement`)
	 * 2. data:
	 *    * [`signature`:`signature`]
	 *    * [`u16`:`flen`]
	 *    * [`flen*byte`:`features`]
	 *    * [`u32`:`timestamp`]
	 *    * [`point`:`node_id`]
	 */
	const size_t feature_len_off = 2 + 64;
	be16 flen;
	size_t node_id_off;

	off += sizeof(struct gossip_hdr);

	if (pread(gosstore_fd, &flen, sizeof(flen), off + feature_len_off)
	    != sizeof(flen))
		return false;

	node_id_off = off + feature_len_off + 2 + be16_to_cpu(flen) + 4;
	if (pread(gosstore_fd, id, sizeof(*id), node_id_off) != sizeof(*id))
		return false;

	return true;
}

static struct command_result *nodes_refresh(struct command *cmd,
					    struct table_desc *td,
					    struct db_query *dbq)
{
	struct sql *sql = sql_of(cmd->plugin);
	struct out_req *req;
	size_t msglen;
	u16 type, flags;

	if (sql->gosstore_fd == -1) {
		sql->gosstore_fd = open("gossip_store", O_RDONLY);
		if (sql->gosstore_fd == -1)
			plugin_err(cmd->plugin, "Could not open gossip_store: %s",
				   strerror(errno));
	}

	/* First time, set off to end and load from scratch */
	if (sql->gosstore_nodes_off == 0) {
		sql->gosstore_nodes_off = find_gossip_store_end(sql->gosstore_fd, 1);
		return default_refresh(cmd, td, dbq);
	}

	/* OK, try catching up! */
	while (gossip_store_readhdr(sql->gosstore_fd, sql->gosstore_nodes_off,
				    &msglen, NULL, &flags, &type)) {
		struct node_id id;
		size_t off = sql->gosstore_nodes_off;

		sql->gosstore_nodes_off += sizeof(struct gossip_hdr) + msglen;

		if (flags & GOSSIP_STORE_DELETED_BIT)
			continue;

		if (type == WIRE_GOSSIP_STORE_ENDED) {
			/* Force a reopen */
			sql->gosstore_nodes_off = sql->gosstore_channels_off = 0;
			close(sql->gosstore_fd);
			sql->gosstore_fd = -1;
			return nodes_refresh(cmd, td, dbq);
		}

		if (type == WIRE_NODE_ANNOUNCEMENT) {
			/* This can fail if entry not fully written yet. */
			if (!extract_node_id(sql->gosstore_fd, off, type, &id)) {
				sql->gosstore_nodes_off = off;
				break;
			}

			/* FIXME: sqlite 3.24.0 (2018-06-04) added UPSERT, but
			 * we don't require it. */
			delete_node_from_db(cmd, &id);
			req = jsonrpc_request_start(cmd, "listnodes",
						    listnodes_one_done,
						    forward_error,
						    dbq);
			json_add_node_id(req->js, "id", &id);
			return send_outreq(req);
		}
		/* FIXME: Add WIRE_GOSSIP_STORE_DELETE_NODE marker! */
	}

	return one_refresh_done(cmd, dbq, false);
}

/* Mutual recursion */
static void watch_for(struct sql *sql,
		      struct table_desc *td,
		      const char *indexname,
		      u64 next_index);

static struct command_result *wait_done(struct command *auxcmd,
					const char *method,
					const char *buf,
					const jsmntok_t *result,
					struct table_desc *td)
{
	const jsmntok_t *valtok;
	const char *indexname;
	u64 val;

	if ((valtok = json_get_member(buf, result, "created")) != NULL) {
		indexname = "created";
		td->refresh_needs |= REFRESH_CREATED;
	} else if ((valtok = json_get_member(buf, result, "updated")) != NULL) {
		indexname = "updated";
		td->refresh_needs |= REFRESH_UPDATED;
	} else if ((valtok = json_get_member(buf, result, "deleted")) != NULL) {
		indexname = "deleted";
		td->refresh_needs |= REFRESH_DELETED;
	} else {
		plugin_err(auxcmd->plugin,
			   "Invalid wait_done for %s: '%.*s'",
			   td->name,
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	}

	if (!json_to_u64(buf, valtok, &val)) {
		plugin_err(auxcmd->plugin,
			   "Invalid wait_done index for %s: '%.*s'",
			   td->name,
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	}

	/* Keep watching for next one */
	watch_for(sql_of(auxcmd->plugin), td, indexname, val + 1);
	return command_still_pending(auxcmd);
}

static void watch_for(struct sql *sql,
		      struct table_desc *td,
		      const char *indexname,
		      u64 next_index)
{
	struct out_req *req;

	req = jsonrpc_request_start(sql->waitcmd, "wait", wait_done,
				    plugin_broken_cb, td);
	json_add_string(req->js, "subsystem", td->waitname);
	json_add_string(req->js, "indexname", indexname);
	json_add_u64(req->js, "nextvalue", next_index);
	send_outreq(req);
}

/* First time we initialize counters and figure where we're up to */
static void watch_init(struct command *cmd,
		       struct table_desc *td,
		       const char *indexname,
		       u64 *max)
{
	struct json_out *params = json_out_new(NULL);
	const jsmntok_t *result, *valtok;
	const char *buf;
	u64 val;

	json_out_start(params, NULL, '{');
	json_out_addstr(params, "subsystem", td->waitname);
	json_out_addstr(params, "indexname", indexname);
	json_out_add(params, "nextvalue", false, "0");
	json_out_end(params, '}');

	result = jsonrpc_request_sync(tmpctx, cmd, "wait", take(params), &buf);

	valtok = json_get_member(buf, result, indexname);
	if (!valtok || !json_to_u64(buf, valtok, &val)) {
		plugin_err(cmd->plugin,
			   "Invalid wait reply for %s %s: '%.*s'",
			   td->name, indexname,
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	}

	if (max != NULL)
		*max = val;

	/* Place watch for when it increases */
	watch_for(sql_of(cmd->plugin), td, indexname, val + 1);
}

static struct command_result *refresh_tables(struct command *cmd,
					     struct db_query *dbq)
{
	struct table_desc *td;

	if (tal_count(dbq->tables) == 0)
		return refresh_complete(cmd, dbq);

	td = dbq->tables[0];

	/* If it's currently being refreshed, wait */
	if (td->refreshing) {
		struct refresh_waiter *rw = tal(cmd, struct refresh_waiter);
		rw->cmd = cmd;
		rw->dbq = dbq;
		list_add(&td->refresh_waiters, &rw->list);
		return command_still_pending(cmd);
	}

	if (td->refresh_needs == REFRESH_UNNECESSARY)
		return next_refresh(cmd, dbq);

	td->refreshing = true;
	td->refresh_start = time_mono();

	/* The first time, we may need to install watches */
	if (!td->populated && td->waitname) {
		/* We will initialize td->last_created_index as we read them in */
		watch_init(cmd, td, "created", NULL);
		watch_init(cmd, td, "updated", &td->last_updated_index);
		watch_init(cmd, td, "deleted", NULL);
	}

	return td->refresh(cmd, dbq->tables[0], dbq);
}

static struct command_result *json_sql(struct command *cmd,
				       const char *buffer,
				       const jsmntok_t *params)
{
	struct sql *sql = sql_of(cmd->plugin);
	struct db_query *dbq = tal(cmd, struct db_query);
	const char *query;
	int err;

	if (!param(cmd, buffer, params,
		   p_req("query", param_string, &query),
		   NULL))
		return command_param_failed();

	dbq->tables = tal_arr(dbq, struct table_desc *, 0);
	dbq->authfail = NULL;
	dbq->cmd = cmd;
	/* We might want to warn on SELECT *, since that is not really
	 * recommended as fields change, but SELECT COUNT(*) is totally
	 * legitimate.  So we suppress deprecation errors in this case */
	dbq->has_wildcard = (strchr(query, '*') != NULL);

	/* This both checks we're not altering, *and* tells us what
	 * tables to refresh. */
	err = sqlite3_set_authorizer(sql->db, sqlite_authorize, dbq);
	if (err != SQLITE_OK) {
		plugin_err(cmd->plugin, "Could not set authorizer: %s",
			   sqlite3_errmsg(sql->db));
	}

	err = sqlite3_prepare_v2(sql->db, query, -1, &dbq->stmt, NULL);
	sqlite3_set_authorizer(sql->db, NULL, NULL);

	if (err != SQLITE_OK) {
		char *errmsg = tal_fmt(tmpctx, "query failed with %s",
				       sqlite3_errmsg(sql->db));
		if (dbq->authfail)
			tal_append_fmt(&errmsg, " (%s)", dbq->authfail);
		return command_fail(cmd, LIGHTNINGD, "%s", errmsg);
	}

	return refresh_tables(cmd, dbq);
}

static bool ignore_column(const struct table_desc *td, const jsmntok_t *t)
{
	/* We don't use peers.log, since it'll always be empty unless we were to
	 * ask for it in listpeers, and it's not very useful. */
	if (streq(td->name, "peers") && json_tok_streq(schemas, t, "log"))
		return true;
	return false;
}

static struct command_result *param_tablename(struct command *cmd,
					      const char *name,
					      const char *buffer,
					      const jsmntok_t *tok,
					      struct table_desc **td)
{
	struct sql *sql = sql_of(cmd->plugin);
	*td = strmap_getn(&sql->tablemap, buffer + tok->start,
			  tok->end - tok->start);
	if (!*td)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Unknown table");
	return NULL;
}

static void json_add_column(struct json_stream *js,
			    const char *dbname,
			    const char *sqltypename)
{
	json_object_start(js, NULL);
	json_add_string(js, "name", dbname);
	json_add_string(js, "type", sqltypename);
	json_object_end(js);
}

static void json_add_columns(struct json_stream *js,
			     const struct table_desc *td)
{
	for (size_t i = 0; i < tal_count(td->columns); i++) {
		if (td->columns[i]->sub) {
			if (td->columns[i]->sub->is_subobject)
				json_add_columns(js, td->columns[i]->sub);
			continue;
		}
		json_add_column(js, td->columns[i]->dbname,
				fieldtypemap[td->columns[i]->ftype].sqltype);
	}
}

static void json_add_schema(struct json_stream *js,
			    const struct table_desc *td)
{
	bool have_indices;

	json_object_start(js, NULL);
	json_add_string(js, "tablename", td->name);
	/* This needs to be an array, not a dictionary, since dicts
	 * are often treated as unordered, and order is critical! */
	json_array_start(js, "columns");
	if (!td->has_created_index)
		json_add_column(js, "rowid", "INTEGER");
	if (td->parent) {
		json_add_column(js, "row", "INTEGER");
		json_add_column(js, "arrindex", "INTEGER");
	}
	json_add_columns(js, td);
	json_array_end(js);

	/* Don't print indices entry unless we have an index! */
	have_indices = false;
	for (size_t i = 0; i < ARRAY_SIZE(indices); i++) {
		if (!streq(indices[i].tablename, td->name))
			continue;
		if (!have_indices) {
			json_array_start(js, "indices");
			have_indices = true;
		}
		json_array_start(js, NULL);
		for (size_t j = 0; j < ARRAY_SIZE(indices[i].fields); j++) {
			if (indices[i].fields[j])
				json_add_string(js, NULL, indices[i].fields[j]);
		}
		json_array_end(js);
	}
	if (have_indices)
		json_array_end(js);
	json_object_end(js);
}

static bool add_one_schema(const char *member, struct table_desc *td,
			   struct json_stream *js)
{
	json_add_schema(js, td);
	return true;
}

static struct command_result *json_listsqlschemas(struct command *cmd,
						  const char *buffer,
						  const jsmntok_t *params)
{
	struct sql *sql = sql_of(cmd->plugin);
	struct table_desc *td;
	struct json_stream *ret;

	if (!param(cmd, buffer, params,
		   p_opt("table", param_tablename, &td),
		   NULL))
		return command_param_failed();

	ret = jsonrpc_stream_success(cmd);
	json_array_start(ret, "schemas");
	if (td)
		json_add_schema(ret, td);
	else
		strmap_iterate(&sql->tablemap, add_one_schema, ret);
	json_array_end(ret);
	return command_finished(cmd, ret);
}

/* Adds a sub_object to this sql statement (and sub-sub etc) */
static void add_sub_object(char **update_stmt, char **create_stmt,
			   const char **sep, struct table_desc *sub)
{
	/* sub-arrays are a completely separate table. */
	if (!sub->is_subobject)
		return;

	/* sub-objects are folded into this table. */
	for (size_t j = 0; j < tal_count(sub->columns); j++) {
		const struct column *subcol = sub->columns[j];

		if (subcol->sub) {
			add_sub_object(update_stmt, create_stmt, sep,
				       subcol->sub);
			continue;
		}
		tal_append_fmt(update_stmt, "%s?", *sep);
		tal_append_fmt(create_stmt, "%s%s %s",
			       *sep,
			       subcol->dbname,
			       fieldtypemap[subcol->ftype].sqltype);
		*sep = ",";
	}
}

/* We use created_index as INTEGER PRIMARY KEY, if it exists.
 * Otherwise, we make an explicit rowid (implicit rowids cannot be
 * used as a foreign key). */
static const char *primary_key_name(const struct table_desc *td)
{
	if (td->has_created_index)
		return "created_index";

	return "rowid";
}

/* Creates sql statements, initializes table */
static void finish_td(struct plugin *plugin, struct table_desc *td)
{
	struct sql *sql = sql_of(plugin);
	char *create_stmt;
	int err;
	char *errmsg;
	const char *sep = "";

	/* subobject are separate at JSON level, folded at db level! */
	if (td->is_subobject)
		/* But it might have sub-sub objects! */
		goto do_subtables;

	create_stmt = tal_fmt(tmpctx, "CREATE TABLE %s (", td->name);
	td->update_stmt = tal_fmt(td, "INSERT INTO %s VALUES (", td->name);
	/* If no created_index, create explicit rowid */
	if (!td->has_created_index) {
		tal_append_fmt(&create_stmt, "rowid INTEGER PRIMARY KEY, ");
		tal_append_fmt(&td->update_stmt, "?, ");
	}

	/* If we're a child array, we reference the parent column */
	if (td->parent) {
		/* But if parent is a subobject, we reference the outer! */
		struct table_desc *parent = td->parent;
		while (parent->is_subobject)
			parent = parent->parent;
		tal_append_fmt(&create_stmt,
			       "row INTEGER REFERENCES %s(%s) ON DELETE CASCADE,"
			       " arrindex INTEGER",
			       parent->name, primary_key_name(parent));
		tal_append_fmt(&td->update_stmt, "?,?");
		sep = ",";
	}

	for (size_t i = 0; i < tal_count(td->columns); i++) {
		const struct column *col = td->columns[i];

		if (col->sub) {
			add_sub_object(&td->update_stmt, &create_stmt,
				       &sep, col->sub);
			continue;
		}
		tal_append_fmt(&td->update_stmt, "%s?", sep);
		tal_append_fmt(&create_stmt, "%s%s %s",
			       sep,
			       col->dbname,
			       fieldtypemap[col->ftype].sqltype);
		/* created_index serves as primary key if it exists */
		if (streq(col->dbname, "created_index"))
			tal_append_fmt(&create_stmt, " INTEGER PRIMARY KEY");
		sep = ",";
	}
	tal_append_fmt(&create_stmt, ");");
	tal_append_fmt(&td->update_stmt, ");");

	err = sqlite3_exec(sql->db, create_stmt, NULL, NULL, &errmsg);
	if (err != SQLITE_OK)
		plugin_err(plugin, "Could not create %s: %s", td->name, errmsg);

do_subtables:
	/* Now do any children */
	for (size_t i = 0; i < tal_count(td->columns); i++) {
		const struct column *col = td->columns[i];
		if (col->sub)
			finish_td(plugin, col->sub);
	}
}

/* Don't use SQL keywords as column names: sure, you can use quotes,
 * but it's a PITA. */
static const char *db_column_name(const tal_t *ctx,
				  const struct table_desc *td,
				  const jsmntok_t *nametok)
{
	const char *name = json_strdup(tmpctx, schemas, nametok);

	if (streq(name, "index"))
		name = tal_strdup(tmpctx, "idx");

	/* Prepend td->name to make column unique in table. */
	if (td->is_subobject)
		return tal_fmt(ctx, "%s_%s", td->cmdname, name);

	return tal_steal(ctx, name);
}

/* Remove 'list', turn - into _ in name */
static const char *db_table_name(const tal_t *ctx, const char *cmdname)
{
	const char *list = strstr(cmdname, "list");
	char *ret = tal_arr(ctx, char, strlen(cmdname) + 1), *dst = ret;
	const char *src = cmdname;

	while (*src) {
		if (src == list)
			src += strlen("list");
		else if (cisalnum(*src))
			*(dst++) = *(src++);
		else {
			(*dst++) = '_';
			src++;
		}
	}
	*dst = '\0';
	return ret;
}

#define LIMIT_PER_LIST 10000

static struct command_result *limited_list_done(struct command *cmd,
						const char *method,
						const char *buf,
						const jsmntok_t *result,
						struct db_query *dbq)
{
	struct table_desc *td = dbq->tables[0];
	struct command_result *ret;
	size_t num_entries;

	ret = process_json_result(cmd, buf, result, td,
				  &td->last_created_index,
				  &td->last_updated_index,
				  &num_entries);
	if (ret)
		return ret;

	/* If we got the number we asked for, we need to ask again. */
	return one_refresh_done(cmd, dbq, num_entries == LIMIT_PER_LIST);
}

/* The simplest case: append-only lists */
static struct command_result *refresh_by_created_index(struct command *cmd,
						       struct table_desc *td,
						       struct db_query *dbq)
{
	struct out_req *req;

	/* Since we're relying on watches, mark refreshing unnecessary to start */
	assert(td->refresh_needs != REFRESH_UNNECESSARY);
	td->refresh_needs = REFRESH_UNNECESSARY;

	req = jsonrpc_request_start(cmd, td->cmdname,
				    limited_list_done, forward_error,
				    dbq);
	json_add_string(req->js, "index", "created");
	json_add_u64(req->js, "start", td->last_created_index + 1);
	json_add_u64(req->js, "limit", LIMIT_PER_LIST);
	return send_outreq(req);
}

struct refresh_funcs {
	const char *cmdname;
	struct command_result *(*refresh)(struct command *cmd,
					  struct table_desc *td,
					  struct db_query *dbq);
	const char *waitname;
};

static const struct refresh_funcs refresh_funcs[] = {
	/* These are special, using gossmap */
	{ "listchannels", channels_refresh, NULL },
	{ "listnodes", nodes_refresh, NULL },
	/* FIXME: These support wait and full pagination,  but we need to watch for deletes, too! */
	{ "listhtlcs", default_refresh, NULL },
	{ "listforwards", default_refresh, NULL },
	{ "listinvoices", default_refresh, NULL },
	{ "listsendpays", default_refresh, NULL },
	/* These are never changed or deleted */
	{ "listchainmoves", refresh_by_created_index, "chainmoves" },
	{ "listchannelmoves", refresh_by_created_index, "channelmoves" },
	/* No pagination support */
	{ "listoffers", default_refresh, NULL },
	{ "listpeers", default_refresh, NULL },
	{ "listpeerchannels", default_refresh, NULL },
	{ "listclosedchannels", default_refresh, NULL },
	{ "listtransactions", default_refresh, NULL },
	{ "bkpr-listaccountevents", default_refresh, NULL },
	{ "bkpr-listincome", default_refresh, NULL },
	{ "listnetworkevents", default_refresh, NULL },
};

static const struct refresh_funcs *find_command_refresh(const char *cmdname)
{
	for (size_t i = 0; i < ARRAY_SIZE(refresh_funcs); i++) {
		if (streq(refresh_funcs[i].cmdname, cmdname))
			return &refresh_funcs[i];
	}
	abort();
}

static struct table_desc *new_table_desc(const tal_t *ctx,
					 tablemap *tablemap,
					 struct table_desc *parent,
					 const jsmntok_t *cmd,
					 const jsmntok_t *arrname,
					 bool is_subobject)
{
	struct table_desc *td;
	const char *name;
	const struct refresh_funcs *refresh_func;

	td = tal(ctx, struct table_desc);
	td->cmdname = json_strdup(td, schemas, cmd);
	name = db_table_name(tmpctx, td->cmdname);
	if (!parent)
		td->name = tal_steal(td, name);
	else
		td->name = tal_fmt(td, "%s_%s", parent->name, name);
	td->parent = parent;
	td->is_subobject = is_subobject;
	td->arrname = json_strdup(td, schemas, arrname);
	td->columns = tal_arr(td, struct column *, 0);
	td->last_created_index = 0;
	td->last_updated_index = 0;
	td->has_created_index = false;
	td->refresh_needs = REFRESH_ALWAYS;
	td->refreshing = false;
	td->populated = false;
	list_head_init(&td->refresh_waiters);

	/* Only top-levels have refresh functions */
	if (!parent) {
		refresh_func = find_command_refresh(td->cmdname);
		td->refresh = refresh_func->refresh;
		td->waitname = refresh_func->waitname;
	}

	/* sub-objects are a JSON thing, not a real table! */
	if (!td->is_subobject)
		strmap_add(tablemap, td->name, td);

	return td;
}

/* Recursion */
static void add_table_object(tablemap *tablemap,
			     struct table_desc *td, const jsmntok_t *tok);

/* Simple case for arrays of a simple type. */
static void add_table_singleton(struct table_desc *td,
				const jsmntok_t *name,
				const jsmntok_t *tok)
{
	struct column *col = tal(td->columns, struct column);
	const jsmntok_t *type;

	/* FIXME: We would need to return false here and delete table! */
	assert(!ignore_column(td, tok));
	type = json_get_member(schemas, tok, "type");

	col->ftype = find_fieldtype(type);
	col->sub = NULL;
	/* We name column after the JSON parent field; but jsonname is NULL so we
	 * know to expect an array not a member. */
	col->dbname = db_column_name(col, td, name);
	col->jsonname = NULL;
	tal_arr_expand(&td->columns, col);
}

static bool add_deprecated(const char *buffer, const jsmntok_t *tok,
			   struct column *col)
{
	const char *err;
	u32 vnum;

	col->depr_start = col->depr_end = NULL;
	err = json_scan(tmpctx, schemas, tok,
			"{deprecated?:[0:%,1:%]}",
			JSON_SCAN_TAL(col, json_strdup, &col->depr_start),
			JSON_SCAN_TAL(col, json_strdup, &col->depr_end));
	assert(!err);
	if (!col->depr_start)
		return true;

	/* If it was deprecated before our release, we don't want it at all. */
	vnum = version_to_number(col->depr_start);
	assert(vnum);
	if (vnum <= version_to_number("v23.02"))
		return false;

	return true;
}

static void add_table_properties(tablemap *tablemap,
				 struct table_desc *td,
				 const jsmntok_t *properties)
{
	const jsmntok_t *t;
	size_t i;

	json_for_each_obj(i, t, properties) {
		const jsmntok_t *type;
		struct column *col;

		if (ignore_column(td, t))
			continue;
		type = json_get_member(schemas, t+1, "type");
		/* Stub properties don't have types, it should exist in
		 * another branch with actual types, so ignore this */
		if (!type)
			continue;

		col = tal(td->columns, struct column);

		/* Some things are so old we ignore them. */
		if (!add_deprecated(schemas, t+1, col)) {
			tal_free(col);
			continue;
		}

		if (json_tok_streq(schemas, type, "array")) {
			const jsmntok_t *items;

			items = json_get_member(schemas, t+1, "items");
			type = json_get_member(schemas, items, "type");

			col->sub = new_table_desc(col, tablemap, td, t, t, false);
			/* Array of primitives?  Treat as single-entry obj */
			if (!json_tok_streq(schemas, type, "object"))
				add_table_singleton(col->sub, t, items);
			else
				add_table_object(tablemap, col->sub, items);
		} else if (json_tok_streq(schemas, type, "object")) {
			col->sub = new_table_desc(col, tablemap, td, t, t, true);
			add_table_object(tablemap, col->sub, t+1);
		} else {
			col->ftype = find_fieldtype(type);
			col->sub = NULL;
		}
		col->dbname = db_column_name(col, td, t);
		/* Some schemas repeat, assume they're the same */
		if (find_column(td, col->dbname)) {
			tal_free(col);
		} else {
			col->jsonname = json_strdup(col, schemas, t);
			tal_arr_expand(&td->columns, col);
		}
	}
}

/* tok is the JSON schema member for an object */
static void add_table_object(tablemap *tablemap,
			     struct table_desc *td, const jsmntok_t *tok)
{
	const jsmntok_t *t, *properties, *allof, *cond;
	size_t i;

	/* This might not exist inside allOf, for example */
	properties = json_get_member(schemas, tok, "properties");
	if (properties)
		add_table_properties(tablemap, td, properties);

	allof = json_get_member(schemas, tok, "allOf");
	if (allof) {
		json_for_each_arr(i, t, allof)
			add_table_object(tablemap, td, t);
	}
	/* We often find interesting things in then and else branches! */
	cond = json_get_member(schemas, tok, "then");
	if (cond)
		add_table_object(tablemap, td, cond);
	cond = json_get_member(schemas, tok, "else");
	if (cond)
		add_table_object(tablemap, td, cond);
}

/* plugin is NULL if we're just doing --print-docs */
static void init_tablemap(struct plugin *plugin, tablemap *tablemap)
{
	const jsmntok_t *toks, *t;
	const tal_t *ctx;
	size_t i;

	if (plugin)
		ctx = plugin;
	else
		ctx = tmpctx;

	strmap_init(tablemap);

	toks = json_parse_simple(tmpctx, schemas, strlen(schemas));
	json_for_each_obj(i, t, toks) {
		struct table_desc *td;
		const jsmntok_t *cmd, *items, *type;

		/* First member of properties object is command. */
		cmd = json_get_member(schemas, t+1, "properties") + 1;

		/* We assume it's an object containing an array of objects */
		items = json_get_member(schemas, cmd + 1, "items");
		type = json_get_member(schemas, items, "type");
		assert(json_tok_streq(schemas, type, "object"));

		td = new_table_desc(ctx, tablemap, NULL, t, cmd, false);
		add_table_object(tablemap, td, items);
		td->has_created_index = find_column(td, "created_index");

		if (plugin)
			finish_td(plugin, td);
	}
}

static void memleak_mark_tablemap(struct plugin *p, struct htable *memtable)
{
	struct sql *sql = sql_of(p);
	memleak_scan_strmap(memtable, &sql->tablemap);
}

static const char *init(struct command *init_cmd,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	struct plugin *plugin = init_cmd->plugin;
	struct sql *sql = sql_of(plugin);
	sql->db = sqlite_setup(plugin);
	init_tablemap(plugin, &sql->tablemap);
	sql->waitcmd = aux_command(init_cmd);

	plugin_set_memleak_handler(plugin, memleak_mark_tablemap);
	return NULL;
}

static const struct plugin_command commands[] = { {
		"sql",
		json_sql,
	},
	{
		"listsqlschemas",
		json_listsqlschemas,
	},
};

static const char *fmt_indexes(const tal_t *ctx, const char *table)
{
	char *ret = NULL;

	for (size_t i = 0; i < ARRAY_SIZE(indices); i++) {
		if (!streq(indices[i].tablename, table))
			continue;
		if (!ret)
			ret = tal_fmt(ctx, " indexed by ");
		else
			tal_append_fmt(&ret, ", also indexed by ");
		BUILD_ASSERT(ARRAY_SIZE(indices[i].fields) == 2);
		if (indices[i].fields[1])
			tal_append_fmt(&ret, "`%s` and `%s`",
				       indices[i].fields[0],
				       indices[i].fields[1]);
		else
			tal_append_fmt(&ret, "`%s`",
				       indices[i].fields[0]);
	}
	if (!ret)
		return "";
	return ret;
}

static const char *json_prefix(const tal_t *ctx,
			       const struct table_desc *td)
{
	if (td->is_subobject)
		return tal_fmt(ctx, "%s%s.", json_prefix(tmpctx, td->parent), td->cmdname);
	return "";
}

static void print_columns(const struct table_desc *td, const char *indent,
			  const char *objsrc)
{
	for (size_t i = 0; i < tal_count(td->columns); i++) {
		const char *origin;
		if (td->columns[i]->sub) {
			const struct table_desc *subtd = td->columns[i]->sub;

			if (!subtd->is_subobject) {
				const char *subindent;

				subindent = tal_fmt(tmpctx, "%s  ", indent);
				printf("%s- related table `%s`%s\n",
				       indent, subtd->name, objsrc);
				printf("%s- `row` (reference to `%s.%s`, sqltype `INTEGER`)\n"
				       "%s- `arrindex` (index within array, sqltype `INTEGER`)\n",
				       subindent, td->name, primary_key_name(td),
				       subindent);
				print_columns(subtd, subindent, "");
			} else {
				const char *subobjsrc;

				subobjsrc = tal_fmt(tmpctx,
						    ", from JSON object `%s%s`",
						    json_prefix(tmpctx, td),
						    td->columns[i]->jsonname);
				print_columns(subtd, indent, subobjsrc);
			}
			continue;
		}

		if (streq(objsrc, "")
		    && td->columns[i]->jsonname
		    && !streq(td->columns[i]->dbname, td->columns[i]->jsonname)) {
			origin = tal_fmt(tmpctx, ", from JSON field `%s%s`",
					 json_prefix(tmpctx, td),
					 td->columns[i]->jsonname);
		} else
			origin = "";
		printf("%s- `%s` (type `%s`, sqltype `%s%s`%s%s)\n",
		       indent, td->columns[i]->dbname,
		       fieldtypemap[td->columns[i]->ftype].name,
		       fieldtypemap[td->columns[i]->ftype].sqltype,
		       streq(td->columns[i]->dbname, "created_index")
		       ? " PRIMARY KEY" : "",
		       origin, objsrc);
	}
}

static bool print_one_table(const char *member,
			    struct table_desc *td,
			    void *unused)
{
	if (td->parent)
		return true;

	printf("- `%s`%s (see lightning-%s(7))\n",
	       member, fmt_indexes(tmpctx, member), td->cmdname);

	print_columns(td, "  ", "");
	printf("\n");
	return true;
}

int main(int argc, char *argv[])
{
	struct sql *sql;
	setup_locale();

	if (argc == 2 && streq(argv[1], "--print-docs")) {
		tablemap tablemap;
		common_setup(argv[0]);

		/* plugin is NULL, so just sets up tables */
		init_tablemap(NULL, &tablemap);

		printf("The following tables are currently supported:\n");
		strmap_iterate(&tablemap, print_one_table, NULL);
		common_shutdown();
		return 0;
	}

	sql = tal(NULL, struct sql);
	sql->dbfilename = NULL;
	sql->gosstore_fd = -1;
	sql->gosstore_nodes_off = sql->gosstore_channels_off = 0;
	sql->next_rowid = 1;
	plugin_main(argv, init, take(sql), PLUGIN_RESTARTABLE, true, NULL, commands, ARRAY_SIZE(commands),
	            NULL, 0, NULL, 0, NULL, 0,
		    plugin_option_dev("dev-sqlfilename",
				      "string",
				      "Use on-disk sqlite3 file instead of in memory (e.g. debugging)",
				      charp_option, NULL, &sql->dbfilename),
		    NULL);
}
