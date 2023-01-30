/* Brilliant or insane?  You decide! */
#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/strmap/strmap.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <plugins/libplugin.h>
#include <sqlite3.h>

/* TODO:
 * 1. Generate from schemas.
 * 2. Refresh time in API.
 * 3. Colnames API to return dict.
 * 4. sql-schemas command.
 * 5. documentation.
 * 6. test on mainnet.
 * 7. Some cool query for documentation.
 * 8. time_msec fields.
 * 9. Primary key in schema?
 * 10. Pagination API
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
};

struct column {
	const char *name;
	enum fieldtype ftype;
};

struct db_query {
	sqlite3_stmt *stmt;
	struct table_desc **tables;
	const char *authfail;
};

struct table_desc {
	/* e.g. peers for listpeers */
	const char *name;
	struct column *columns;
	char *update_stmt;
};
static STRMAP(struct table_desc *) tablemap;
static size_t max_dbmem = 500000000;
static struct sqlite3 *db;
static const char *dbfilename;

static struct sqlite3 *sqlite_setup(struct plugin *plugin)
{
	int err;
	struct sqlite3 *db;
	char *errmsg;

	if (dbfilename) {
		err = sqlite3_open_v2(dbfilename, &db,
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

	/* Default is now 4k pages, so allow 500MB */
	err = sqlite3_exec(db, tal_fmt(tmpctx, "PRAGMA max_page_count = %zu;",
				       max_dbmem / 4096),
			   NULL, NULL, &errmsg);
	if (err != SQLITE_OK)
		plugin_err(plugin, "Could not set max_page_count: %s", errmsg);

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

	/* You can do a column read: takes a table name */
	if (code == SQLITE_READ) {
		struct table_desc *td = strmap_get(&tablemap, a);
		if (!td) {
			dbq->authfail = tal_fmt(dbq, "Unknown table %s", a);
			return SQLITE_DENY;
		}
		if (!has_table_desc(dbq->tables, td))
			tal_arr_expand(&dbq->tables, td);
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
				 sqlite3_errmsg(db));

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

/* Recursion */
static struct command_result *refresh_tables(struct command *cmd,
					     struct db_query *dbq);

static struct command_result *one_refresh_done(struct command *cmd,
					       struct db_query *dbq)
{
	/* Remove that, iterate */
	tal_arr_remove(&dbq->tables, 0);
	return refresh_tables(cmd, dbq);
}

/* Returns NULL on success, otherwise has failed cmd. */
static struct command_result *process_json_obj(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *t,
					       const struct table_desc *td,
					       size_t row,
					       const u64 *rowid,
					       size_t *sqloff,
					       sqlite3_stmt *stmt)
{
	int err;

	/* FIXME: This is O(n^2): hash td->columns and look up the other way. */
	for (size_t i = 0; i < tal_count(td->columns); i++) {
		const struct column *col = &td->columns[i];
		const jsmntok_t *coltok;

		if (!t)
			coltok = NULL;
		else
			coltok = json_get_member(buf, t, col->name);

		if (!coltok)
			sqlite3_bind_null(stmt, (*sqloff)++);
		else {
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

	err = sqlite3_step(stmt);
	if (err != SQLITE_DONE) {
		return command_fail(cmd, LIGHTNINGD,
				    "Error executing %s on row %zu: %s",
				    td->update_stmt,
				    row,
				    sqlite3_errmsg(db));
	}
	return NULL;
}

static struct command_result *process_json_list(struct command *cmd,
						const char *buf,
						const jsmntok_t *result,
						const struct table_desc *td)
{
	size_t i;
	const jsmntok_t *t, *arr = json_get_member(buf, result, td->name);
	int err;
	sqlite3_stmt *stmt;
	struct command_result *ret = NULL;

	err = sqlite3_prepare_v2(db, td->update_stmt, -1, &stmt, NULL);
	if (err != SQLITE_OK) {
		return command_fail(cmd, LIGHTNINGD, "preparing '%s' failed: %s",
				    td->update_stmt,
				    sqlite3_errmsg(db));
	}

 	json_for_each_arr(i, t, arr) {
		/* sqlite3 columns are 1-based! */
		size_t off = 1;
		ret = process_json_obj(cmd, buf, t, td, i, NULL, &off, stmt);
		if (ret)
			break;
		sqlite3_reset(stmt);
	}
	sqlite3_finalize(stmt);
	return ret;
}

static struct command_result *default_list_done(struct command *cmd,
						const char *buf,
						const jsmntok_t *result,
						struct db_query *dbq)
{
	const struct table_desc *td = dbq->tables[0];
	struct command_result *ret;
	int err;
	char *errmsg;

	/* FIXME: this is where a wait / pagination API is useful! */
	err = sqlite3_exec(db, tal_fmt(tmpctx, "DELETE FROM %s;", td->name),
			   NULL, NULL, &errmsg);
	if (err != SQLITE_OK) {
		return command_fail(cmd, LIGHTNINGD, "cleaning '%s' failed: %s",
				    td->name, errmsg);
	}

	ret = process_json_list(cmd, buf, result, td);
	if (ret)
		return ret;

	return one_refresh_done(cmd, dbq);
}

static struct command_result *default_refresh(struct command *cmd,
					      const struct table_desc *td,
					      struct db_query *dbq)
{
	struct out_req *req;
	req = jsonrpc_request_start(cmd->plugin, cmd,
				    tal_fmt(tmpctx, "list%s", td->name),
				    default_list_done, forward_error,
				    dbq);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *refresh_tables(struct command *cmd,
					    struct db_query *dbq)
{
	const struct table_desc *td;

	if (tal_count(dbq->tables) == 0)
		return refresh_complete(cmd, dbq);

	td = dbq->tables[0];
	return default_refresh(cmd, td, dbq);
}

static struct command_result *json_sql(struct command *cmd,
				       const char *buffer,
				       const jsmntok_t *params)
{
	struct db_query *dbq = tal(cmd, struct db_query);
	const char *query;
	int err;

	if (!param(cmd, buffer, params,
		   p_req("query", param_string, &query),
		   NULL))
		return command_param_failed();

	dbq->tables = tal_arr(dbq, struct table_desc *, 0);
	dbq->authfail = NULL;

	/* This both checks we're not altering, *and* tells us what
	 * tables to refresh. */
	err = sqlite3_set_authorizer(db, sqlite_authorize, dbq);
	if (err != SQLITE_OK) {
		plugin_err(cmd->plugin, "Could not set authorizer: %s",
			   sqlite3_errmsg(db));
	}

	err = sqlite3_prepare_v2(db, query, -1, &dbq->stmt, NULL);
	sqlite3_set_authorizer(db, NULL, NULL);

	if (err != SQLITE_OK) {
		char *errmsg = tal_fmt(tmpctx, "query failed with %s", sqlite3_errmsg(db));
		if (dbq->authfail)
			tal_append_fmt(&errmsg, " (%s)", dbq->authfail);
		return command_fail(cmd, LIGHTNINGD, "%s", errmsg);
	}

	return refresh_tables(cmd, dbq);
}

static void init_tablemap(struct plugin *plugin)
{
	struct table_desc *td;
	char *create_stmt;
	int err;
	char *errmsg;
	struct column col;

	strmap_init(&tablemap);

	/* FIXME: Load from schemas! */
	td = tal(NULL, struct table_desc);
	td->name = "forwards";
	td->columns = tal_arr(td, struct column, 0);
	col.name = "in_htlc_id";
	col.ftype = FIELD_U64;
	tal_arr_expand(&td->columns, col);
	col.name = "in_channel";
	col.ftype = FIELD_SCID;
	tal_arr_expand(&td->columns, col);
	col.name = "in_msat";
	col.ftype = FIELD_MSAT;
	tal_arr_expand(&td->columns, col);
	col.name = "status";
	col.ftype = FIELD_STRING;
	tal_arr_expand(&td->columns, col);
	col.name = "received_time";
	col.ftype = FIELD_NUMBER;
	tal_arr_expand(&td->columns, col);
	col.name = "out_channel";
	col.ftype = FIELD_SCID;
	tal_arr_expand(&td->columns, col);
	col.name = "out_htlc_id";
	col.ftype = FIELD_U64;
	tal_arr_expand(&td->columns, col);
	col.name = "style";
	col.ftype = FIELD_STRING;
	tal_arr_expand(&td->columns, col);
	col.name = "fee_msat";
	col.ftype = FIELD_MSAT;
	tal_arr_expand(&td->columns, col);
	col.name = "out_msat";
	col.ftype = FIELD_MSAT;
	tal_arr_expand(&td->columns, col);
	col.name = "resolved_time";
	col.ftype = FIELD_NUMBER;
	tal_arr_expand(&td->columns, col);

	/* FIXME: Primary key from schema? */
	create_stmt = tal_fmt(tmpctx, "CREATE TABLE %s (", td->name);
	td->update_stmt = tal_fmt(td, "INSERT INTO %s VALUES (", td->name);
	for (size_t i = 0; i < tal_count(td->columns); i++) {
		tal_append_fmt(&td->update_stmt, "%s?",
			       i == 0 ? "" : ",");
		tal_append_fmt(&create_stmt, "%s%s %s",
			       i == 0 ? "" : ",",
			       td->columns[i].name,
			       fieldtypemap[td->columns[i].ftype].sqltype);
	}
	tal_append_fmt(&create_stmt, ");");
	tal_append_fmt(&td->update_stmt, ");");

	err = sqlite3_exec(db, create_stmt, NULL, NULL, &errmsg);
	if (err != SQLITE_OK)
		plugin_err(plugin, "Could not create %s: %s", td->name, errmsg);

	strmap_add(&tablemap, td->name, td);
}

#if DEVELOPER
static void memleak_mark_tablemap(struct plugin *p, struct htable *memtable)
{
	memleak_ptr(memtable, dbfilename);
	memleak_scan_strmap(memtable, &tablemap);
}
#endif

static const char *init(struct plugin *plugin,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	db = sqlite_setup(plugin);
	init_tablemap(plugin);

#if DEVELOPER
	plugin_set_memleak_handler(plugin, memleak_mark_tablemap);
#endif
	return NULL;
}

static const struct plugin_command commands[] = { {
	"sql",
	"misc",
	"Run {query} and return result",
	"This is the greatest plugin command ever!",
	json_sql,
	},
};

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_RESTARTABLE, true, NULL, commands, ARRAY_SIZE(commands),
	            NULL, 0, NULL, 0, NULL, 0,
		    plugin_option("sqlfilename",
				  "string",
				  "Use on-disk sqlite3 file instead of in memory (e.g. debugging)",
				  charp_option, &dbfilename),
		    NULL);
}
