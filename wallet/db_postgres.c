#include <wallet/db_common.h>
#include "gen_db_postgres.c"
#include <ccan/ccan/tal/str/str.h>
#include <ccan/endian/endian.h>
#include <lightningd/log.h>
#include <sqlite3.h>
#include <stdio.h>

#if HAVE_POSTGRES
/* Indented in order not to trigger the inclusion order check */
  #include <libpq-fe.h>

/* Cherry-picked from here: libpq/src/interfaces/ecpg/ecpglib/pg_type.h */
#define BYTEAOID		17
#define INT8OID			20
#define INT4OID			23
#define TEXTOID			25

static bool db_postgres_setup(struct db *db)
{
	db->conn = PQconnectdb(db->filename);

	if (PQstatus(db->conn) != CONNECTION_OK) {
		db->error = tal_fmt(db, "Could not connect to %s: %s", db->filename, PQerrorMessage(db->conn));
		db->conn = NULL;
		return false;
	}
	return true;
}

static bool db_postgres_begin_tx(struct db *db)
{
	assert(db->conn);
	PGresult *res;
	res = PQexec(db->conn, "BEGIN;");
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		db->error = tal_fmt(db, "BEGIN command failed: %s",
				    PQerrorMessage(db->conn));
		PQclear(res);
		return false;
	}
	PQclear(res);
	return true;
}

static bool db_postgres_commit_tx(struct db *db)
{
	assert(db->conn);
	PGresult *res;
	res = PQexec(db->conn, "COMMIT;");
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		db->error = tal_fmt(db, "COMMIT command failed: %s",
				    PQerrorMessage(db->conn));
		PQclear(res);
		return false;
	}
	PQclear(res);
	return true;
}

static PGresult *db_postgres_do_exec(struct db_stmt *stmt)
{
	int slots = stmt->query->placeholders;
	const char *paramValues[slots];
	int paramLengths[slots];
	int paramFormats[slots];
	Oid paramTypes[slots];
	int resultFormat = 1; /* We always want binary results. */

	/* Since we pass in raw pointers to elements converted to network
	 * byte-order we need a place to temporarily stash them. */
	s32 ints[slots];
	u64 u64s[slots];

	for (size_t i=0; i<slots; i++) {
		struct db_binding *b = &stmt->bindings[i];

		switch (b->type) {
		case DB_BINDING_UNINITIALIZED:
			db_fatal("DB binding not initialized: position=%zu, "
				 "query=\"%s\n",
				 i, stmt->query->query);
		case DB_BINDING_UINT64:
			paramLengths[i] = 8;
			paramFormats[i] = 1;
			u64s[i] = cpu_to_be64(b->v.u64);
			paramValues[i] = (char*)&u64s[i];
			paramTypes[i] = INT8OID;
			break;
		case DB_BINDING_INT:
			paramLengths[i] = 4;
			paramFormats[i] = 1;
			ints[i] = cpu_to_be32(b->v.i);
			paramValues[i] = (char*)&ints[i];
			paramTypes[i] = INT4OID;
			break;
		case DB_BINDING_BLOB:
			paramLengths[i] = b->len;
			paramFormats[i] = 1;
			paramValues[i] = (char*)b->v.blob;
			paramTypes[i] = BYTEAOID;
			break;
		case DB_BINDING_TEXT:
			paramLengths[i] = b->len;
			paramFormats[i] = 1;
			paramValues[i] = (char*)b->v.text;
			paramTypes[i] = TEXTOID;
			break;
		case DB_BINDING_NULL:
			paramLengths[i] = 0;
			paramFormats[i] = 1;
			paramValues[i] = NULL;
			paramTypes[i] = 0;
			break;
		}
	}
	return PQexecParams(stmt->db->conn, stmt->query->query, slots,
			    paramTypes, paramValues, paramLengths, paramFormats,
			    resultFormat);
}

static bool db_postgres_query(struct db_stmt *stmt)
{
	stmt->inner_stmt = db_postgres_do_exec(stmt);
	int res;
	res = PQresultStatus(stmt->inner_stmt);

	if (res != PGRES_EMPTY_QUERY && res != PGRES_TUPLES_OK) {
		stmt->error = PQerrorMessage(stmt->db->conn);
		PQclear(stmt->inner_stmt);
		stmt->inner_stmt = NULL;
		return false;
	}
	stmt->row = -1;
	return true;
}

static bool db_postgres_step(struct db_stmt *stmt)
{
	stmt->row++;
	if (stmt->row >= PQntuples(stmt->inner_stmt)) {
		return false;
	}
	return true;
}

static bool db_postgres_column_is_null(struct db_stmt *stmt, int col)
{
	PGresult *res = (PGresult*)stmt->inner_stmt;
	return PQgetisnull(res, stmt->row, col);
}

static u64 db_postgres_column_u64(struct db_stmt *stmt, int col)
{
	PGresult *res = (PGresult*)stmt->inner_stmt;
	be64 bin;
	size_t expected = sizeof(bin), actual = PQgetlength(res, stmt->row, col);

	if (expected != actual)
		db_fatal(
		    "u64 field doesn't match size: expected %zu, actual %zu\n",
		    expected, actual);

	memcpy(&bin, PQgetvalue(res, stmt->row, col), sizeof(bin));
	return be64_to_cpu(bin);
}

static s64 db_postgres_column_int(struct db_stmt *stmt, int col)
{
	PGresult *res = (PGresult*)stmt->inner_stmt;
	be32 bin;
	size_t expected = sizeof(bin), actual = PQgetlength(res, stmt->row, col);

	if (expected != actual)
		db_fatal(
		    "s32 field doesn't match size: expected %zu, actual %zu\n",
		    expected, actual);

	memcpy(&bin, PQgetvalue(res, stmt->row, col), sizeof(bin));
	return be32_to_cpu(bin);
}

static size_t db_postgres_column_bytes(struct db_stmt *stmt, int col)
{
	PGresult *res = (PGresult *)stmt->inner_stmt;
	return PQgetlength(res, stmt->row, col);
}

static const void *db_postgres_column_blob(struct db_stmt *stmt, int col)
{
	PGresult *res = (PGresult*)stmt->inner_stmt;
	return PQgetvalue(res, stmt->row, col);
}

static const unsigned char *db_postgres_column_text(struct db_stmt *stmt, int col)
{
	PGresult *res = (PGresult*)stmt->inner_stmt;
	return (unsigned char*)PQgetvalue(res, stmt->row, col);
}

static void db_postgres_stmt_free(struct db_stmt *stmt)
{
	if (stmt->inner_stmt)
		PQclear(stmt->inner_stmt);
	stmt->inner_stmt = NULL;
}

static bool db_postgres_exec(struct db_stmt *stmt)
{
	bool ok;
	stmt->inner_stmt = db_postgres_do_exec(stmt);
	ok = PQresultStatus(stmt->inner_stmt) == PGRES_COMMAND_OK;

	if (!ok)
		stmt->error = PQerrorMessage(stmt->db->conn);

	return ok;
}

static u64 db_postgres_last_insert_id(struct db_stmt *stmt)
{
	PGresult *res = PQexec(stmt->db->conn, "SELECT lastval()");
	int id = atoi(PQgetvalue(res, 0, 0));
	PQclear(res);
	return id;
}

static size_t db_postgres_count_changes(struct db_stmt *stmt)
{
	PGresult *res = (PGresult*)stmt->inner_stmt;
	char *count = PQcmdTuples(res);
	return atoi(count);
}

static void db_postgres_teardown(struct db *db)
{
}

struct db_config db_postgres_config = {
    .name = "postgres",
    .queries = db_postgres_queries,
    .num_queries = DB_POSTGRES_QUERY_COUNT,
    .exec_fn = db_postgres_exec,
    .query_fn = db_postgres_query,
    .step_fn = db_postgres_step,
    .begin_tx_fn = &db_postgres_begin_tx,
    .commit_tx_fn = &db_postgres_commit_tx,
    .stmt_free_fn = db_postgres_stmt_free,

    .column_is_null_fn = db_postgres_column_is_null,
    .column_u64_fn = db_postgres_column_u64,
    .column_int_fn = db_postgres_column_int,
    .column_bytes_fn = db_postgres_column_bytes,
    .column_blob_fn = db_postgres_column_blob,
    .column_text_fn = db_postgres_column_text,

    .last_insert_id_fn = db_postgres_last_insert_id,
    .count_changes_fn = db_postgres_count_changes,
    .setup_fn = db_postgres_setup,
    .teardown_fn = db_postgres_teardown,
};

AUTODATA(db_backends, &db_postgres_config);

#endif
