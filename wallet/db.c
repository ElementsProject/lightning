#include "db.h"

#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <inttypes.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>

#define DB_FILE "lightningd.sqlite3"

/* Do not reorder or remove elements from this array, it is used to
 * migrate existing databases from a previous state, based on the
 * string indices */
char *dbmigrations[] = {
    "CREATE TABLE version (version INTEGER)",
    "INSERT INTO version VALUES (1)",
    "CREATE TABLE outputs ( \
       prev_out_tx CHAR(64),			 \
       prev_out_index INTEGER,			 \
       value INTEGER,				 \
       type INTEGER,				 \
       status INTEGER,				 \
       keyindex INTEGER,			 \
       PRIMARY KEY (prev_out_tx, prev_out_index) \
    );",
    "CREATE TABLE vars (name VARCHAR(32), val VARCHAR(255), PRIMARY KEY (name));",
    "CREATE TABLE shachains (                    \
       id INTEGER,				 \
       min_index INTEGER,			 \
       num_valid INTEGER,			 \
       PRIMARY KEY (id));",
    "CREATE TABLE shachain_known (                                      \
       shachain_id INTEGER REFERENCES shachains(id) ON DELETE CASCADE,	\
       pos INTEGER,							\
       idx INTEGER,							\
       hash BLOB,							\
       PRIMARY KEY (shachain_id, pos));",
    "CREATE TABLE channels ("
    "  id INTEGER," /* chan->id */
    "  peer_id INTEGER REFERENCES peers(id) ON DELETE CASCADE,"
    "  short_channel_id BLOB,"
    "  channel_config_local INTEGER,"
    "  channel_config_remote INTEGER,"
    "  state INTEGER,"
    "  funder INTEGER,"
    "  channel_flags INTEGER,"
    "  minimum_depth INTEGER,"
    "  next_index_local INTEGER,"
    "  next_index_remote INTEGER,"
    "  next_htlc_id INTEGER, "
    "  funding_tx_id BLOB,"
    "  funding_tx_outnum INTEGER,"
    "  funding_satoshi INTEGER,"
    "  funding_locked_remote INTEGER,"
    "  push_msatoshi INTEGER,"
    "  msatoshi_local INTEGER," /* our_msatoshi */
    /* START channel_info */
    "  fundingkey_remote BLOB,"
    "  revocation_basepoint_remote BLOB,"
    "  payment_basepoint_remote BLOB,"
    "  htlc_basepoint_remote BLOB,"
    "  delayed_payment_basepoint_remote BLOB,"
    "  per_commit_remote BLOB,"
    "  old_per_commit_remote BLOB,"
    "  local_feerate_per_kw INTEGER,"
    "  remote_feerate_per_kw INTEGER,"
    /* END channel_info */
    "  shachain_remote_id INTEGER,"
    "  shutdown_scriptpubkey_remote BLOB,"
    "  shutdown_keyidx_local INTEGER,"
    "  last_sent_commit_state INTEGER,"
    "  last_sent_commit_id INTEGER,"
    "  last_tx BLOB,"
    "  last_sig BLOB,"
    "  closing_fee_received INTEGER,"
    "  closing_sig_received BLOB,"
    "  PRIMARY KEY (id)"
    ");",
    "CREATE TABLE peers ("
    "  id INTEGER,"
    "  node_id BLOB UNIQUE," /* pubkey */
    "  address TEXT,"
    "  PRIMARY KEY (id)"
    ");",
    "CREATE TABLE channel_configs ("
    "  id INTEGER,"
    "  dust_limit_satoshis INTEGER,"
    "  max_htlc_value_in_flight_msat INTEGER,"
    "  channel_reserve_satoshis INTEGER,"
    "  htlc_minimum_msat INTEGER,"
    "  to_self_delay INTEGER,"
    "  max_accepted_htlcs INTEGER,"
    "  PRIMARY KEY (id)"
    ");",
    "CREATE TABLE channel_htlcs ("
    "  id INTEGER,"
    "  channel_id INTEGER REFERENCES channels(id) ON DELETE CASCADE,"
    "  channel_htlc_id INTEGER,"
    "  direction INTEGER,"
    "  origin_htlc INTEGER,"
    "  msatoshi INTEGER,"
    "  cltv_expiry INTEGER,"
    "  payment_hash BLOB,"
    "  payment_key BLOB,"
    "  routing_onion BLOB,"
    "  failuremsg BLOB,"
    "  malformed_onion INTEGER,"
    "  hstate INTEGER,"
    "  shared_secret BLOB,"
    "  PRIMARY KEY (id),"
    "  UNIQUE (channel_id, channel_htlc_id, direction)"
    ");",
    "CREATE TABLE invoices ("
    "  id INTEGER,"
    "  state INTEGER,"
    "  msatoshi INTEGER,"
    "  payment_hash BLOB,"
    "  payment_key BLOB,"
    "  label TEXT,"
    "  PRIMARY KEY (id),"
    "  UNIQUE (label),"
    "  UNIQUE (payment_hash)"
    ");",
    "CREATE TABLE payments ("
    "  id INTEGER,"
    "  timestamp INTEGER,"
    "  status INTEGER,"
    "  payment_hash BLOB,"
    /* FIXME: Direction is now always 1 (OUTGOING), can be removed */
    "  direction INTEGER,"
    "  destination BLOB,"
    "  msatoshi INTEGER,"
    "  PRIMARY KEY (id),"
    "  UNIQUE (payment_hash)"
    ");",
    /* Add expiry field to invoices (effectively infinite). */
    "ALTER TABLE invoices ADD expiry_time INTEGER;",
    "UPDATE invoices SET expiry_time=9223372036854775807;",
    /* Add pay_index field to paid invoices (initially, same order as id). */
    "ALTER TABLE invoices ADD pay_index INTEGER;",
    "CREATE UNIQUE INDEX invoices_pay_index"
    "  ON invoices(pay_index);",
    "UPDATE invoices SET pay_index=id WHERE state=1;", /* only paid invoice */
    /* Create next_pay_index variable (highest pay_index). */
    "INSERT OR REPLACE INTO vars(name, val)"
    "  VALUES('next_pay_index', "
    "    COALESCE((SELECT MAX(pay_index) FROM invoices WHERE state=1), 0) + 1"
    "  );",
    /* Create first_block field; initialize from channel id if any.
     * This fails for channels still awaiting lockin, but that only applies to
     * pre-release software, so it's forgivable. */
    "ALTER TABLE channels ADD first_blocknum INTEGER;",
    "UPDATE channels SET first_blocknum=CAST(short_channel_id AS INTEGER) WHERE short_channel_id IS NOT NULL;",
    "ALTER TABLE outputs ADD COLUMN channel_id INTEGER;",
    "ALTER TABLE outputs ADD COLUMN peer_id BLOB;",
    "ALTER TABLE outputs ADD COLUMN commitment_point BLOB;",
    "ALTER TABLE invoices ADD COLUMN msatoshi_received INTEGER;",
    /* Normally impossible, so at least we'll know if databases are ancient. */
    "UPDATE invoices SET msatoshi_received=0 WHERE state=1;",
    "ALTER TABLE channels ADD COLUMN last_was_revoke INTEGER;",
    NULL,
};

sqlite3_stmt *db_prepare_(const char *caller, struct db *db, const char *query)
{
	int err;
	sqlite3_stmt *stmt;

	assert(db->in_transaction);

	err = sqlite3_prepare_v2(db->sql, query, -1, &stmt, NULL);

	if (err != SQLITE_OK)
		fatal("%s: %s: %s", caller, query, sqlite3_errmsg(db->sql));

	return stmt;
}

void db_exec_prepared_(const char *caller, struct db *db, sqlite3_stmt *stmt)
{
	assert(db->in_transaction);

	if (sqlite3_step(stmt) !=  SQLITE_DONE)
		fatal("%s: %s", caller, sqlite3_errmsg(db->sql));

	sqlite3_finalize(stmt);
}

/* This one doesn't check if we're in a transaction. */
static void db_do_exec(const char *caller, struct db *db, const char *cmd)
{
	char *errmsg;
	int err;

	err = sqlite3_exec(db->sql, cmd, NULL, NULL, &errmsg);
	if (err != SQLITE_OK) {
		fatal("%s:%s:%s:%s", caller, sqlite3_errstr(err), cmd, errmsg);
		/* Only reached in testing */
		sqlite3_free(errmsg);
	}
}

static void PRINTF_FMT(3, 4)
    db_exec(const char *caller, struct db *db, const char *fmt, ...)
{
	va_list ap;
	char *cmd;

	assert(db->in_transaction);

	va_start(ap, fmt);
	cmd = tal_vfmt(db, fmt, ap);
	va_end(ap);

	db_do_exec(caller, db, cmd);
	tal_free(cmd);
}

bool db_exec_prepared_mayfail_(const char *caller, struct db *db, sqlite3_stmt *stmt)
{
	assert(db->in_transaction);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		goto fail;
	}

	sqlite3_finalize(stmt);
	return true;
fail:
	sqlite3_finalize(stmt);
	return false;
}

sqlite3_stmt *PRINTF_FMT(3, 4)
    db_query(const char *caller, struct db *db, const char *fmt, ...)
{
	va_list ap;
	char *query;
	sqlite3_stmt *stmt;

	assert(db->in_transaction);

	va_start(ap, fmt);
	query = tal_vfmt(db, fmt, ap);
	va_end(ap);

	/* Sets stmt to NULL if not SQLITE_OK */
	sqlite3_prepare_v2(db->sql, query, -1, &stmt, NULL);
	tal_free(query);
	return stmt;
}

static void close_db(struct db *db) { sqlite3_close(db->sql); }

void db_begin_transaction_(struct db *db, const char *location)
{
	if (db->in_transaction)
		fatal("Already in transaction from %s", db->in_transaction);

	db_do_exec(location, db, "BEGIN TRANSACTION;");
	db->in_transaction = location;
}

void db_commit_transaction(struct db *db)
{
	assert(db->in_transaction);
	db_exec(__func__, db, "COMMIT;");
	db->in_transaction = NULL;
}

/**
 * db_open - Open or create a sqlite3 database
 */
static struct db *db_open(const tal_t *ctx, char *filename)
{
	int err;
	struct db *db;
	sqlite3 *sql;

	if (SQLITE_VERSION_NUMBER != sqlite3_libversion_number())
		fatal("SQLITE version mismatch: compiled %u, now %u",
		      SQLITE_VERSION_NUMBER, sqlite3_libversion_number());

	int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
	err = sqlite3_open_v2(filename, &sql, flags, NULL);

	if (err != SQLITE_OK) {
		fatal("failed to open database %s: %s", filename,
		      sqlite3_errstr(err));
	}

	db = tal(ctx, struct db);
	db->filename = tal_dup_arr(db, char, filename, strlen(filename), 0);
	db->sql = sql;
	tal_add_destructor(db, close_db);
	db->in_transaction = NULL;
	db_do_exec(__func__, db, "PRAGMA foreign_keys = ON;");

	return db;
}

/**
 * db_get_version - Determine the current DB schema version
 *
 * Will attempt to determine the current schema version of the
 * database @db by querying the `version` table. If the table does not
 * exist it'll return schema version -1, so that migration 0 is
 * applied, which should create the `version` table.
 */
static int db_get_version(struct db *db)
{
	int err;
	u64 res = -1;
	sqlite3_stmt *stmt =
	    db_query(__func__, db, "SELECT version FROM version LIMIT 1");

	if (!stmt)
		return -1;

	err = sqlite3_step(stmt);
	if (err != SQLITE_ROW) {
		sqlite3_finalize(stmt);
		return -1;
	} else {
		res = sqlite3_column_int64(stmt, 0);
		sqlite3_finalize(stmt);
		return res;
	}
}

/**
 * db_migration_count - Count how many migrations are available
 *
 * Returns the maximum migration index, i.e., the version number of an
 * up-to-date database schema.
 */
static int db_migration_count(void)
{
	int count = 0;
	while (dbmigrations[count] != NULL)
		count++;
	return count - 1;
}

/**
 * db_migrate - Apply all remaining migrations from the current version
 */
static void db_migrate(struct db *db, struct log *log)
{
	/* Attempt to read the version from the database */
	int current, available;

	db_begin_transaction(db);

	current = db_get_version(db);
	available = db_migration_count();

	if (current == -1)
		log_info(log, "Creating database");
	else if (current != available)
		log_info(log, "Updating database from version %u to %u",
			 current, available);

	while (++current <= available)
		db_exec(__func__, db, "%s", dbmigrations[current]);

	/* Finally update the version number in the version table */
	db_exec(__func__, db, "UPDATE version SET version=%d;", available);

	db_commit_transaction(db);
}

struct db *db_setup(const tal_t *ctx, struct log *log)
{
	struct db *db = db_open(ctx, DB_FILE);

	db_migrate(db, log);
	return db;
}

s64 db_get_intvar(struct db *db, char *varname, s64 defval)
{
	int err;
	s64 res = defval;
	const unsigned char *stringvar;
	sqlite3_stmt *stmt =
	    db_query(__func__, db,
		     "SELECT val FROM vars WHERE name='%s' LIMIT 1", varname);

	if (!stmt)
		return defval;

	err = sqlite3_step(stmt);
	if (err == SQLITE_ROW) {
		stringvar = sqlite3_column_text(stmt, 0);
		res = atol((const char *)stringvar);
	}
	sqlite3_finalize(stmt);
	return res;
}

void db_set_intvar(struct db *db, char *varname, s64 val)
{
	/* Attempt to update */
	db_exec(__func__, db,
		"UPDATE vars SET val='%" PRId64 "' WHERE name='%s';", val,
		varname);
	if (sqlite3_changes(db->sql) == 0)
		db_exec(
		    __func__, db,
		    "INSERT INTO vars (name, val) VALUES ('%s', '%" PRId64
		    "');",
		    varname, val);
}

bool sqlite3_bind_short_channel_id(sqlite3_stmt *stmt, int col,
				   const struct short_channel_id *id)
{
	char *ser = short_channel_id_to_str(id, id);
	sqlite3_bind_blob(stmt, col, ser, strlen(ser), SQLITE_TRANSIENT);
	tal_free(ser);
	return true;
}

bool sqlite3_column_short_channel_id(sqlite3_stmt *stmt, int col,
				     struct short_channel_id *dest)
{
	const char *source = sqlite3_column_blob(stmt, col);
	size_t sourcelen = sqlite3_column_bytes(stmt, col);
	return short_channel_id_from_str(source, sourcelen, dest);
}

bool sqlite3_bind_tx(sqlite3_stmt *stmt, int col, const struct bitcoin_tx *tx)
{
	u8 *ser = linearize_tx(NULL, tx);
	sqlite3_bind_blob(stmt, col, ser, tal_len(ser), SQLITE_TRANSIENT);
	tal_free(ser);
	return true;
}

struct bitcoin_tx *sqlite3_column_tx(const tal_t *ctx, sqlite3_stmt *stmt,
				     int col)
{
	const u8 *src = sqlite3_column_blob(stmt, col);
	size_t len = sqlite3_column_bytes(stmt, col);
	return pull_bitcoin_tx(ctx, &src, &len);
}
bool sqlite3_bind_signature(sqlite3_stmt *stmt, int col,
			    const secp256k1_ecdsa_signature *sig)
{
	bool ok;
	u8 buf[64];
	ok = secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx, buf,
							 sig) == 1;
	sqlite3_bind_blob(stmt, col, buf, sizeof(buf), SQLITE_TRANSIENT);
	return ok;
}

bool sqlite3_column_signature(sqlite3_stmt *stmt, int col,
			      secp256k1_ecdsa_signature *sig)
{
	assert(sqlite3_column_bytes(stmt, col) == 64);
	return secp256k1_ecdsa_signature_parse_compact(
		   secp256k1_ctx, sig, sqlite3_column_blob(stmt, col)) == 1;
}

bool sqlite3_column_pubkey(sqlite3_stmt *stmt, int col,  struct pubkey *dest)
{
	assert(sqlite3_column_bytes(stmt, col) == PUBKEY_DER_LEN);
	return pubkey_from_der(sqlite3_column_blob(stmt, col), PUBKEY_DER_LEN, dest);
}

bool sqlite3_bind_pubkey(sqlite3_stmt *stmt, int col, const struct pubkey *pk)
{
	u8 der[PUBKEY_DER_LEN];
	pubkey_to_der(der, pk);
	sqlite3_bind_blob(stmt, col, der, sizeof(der), SQLITE_TRANSIENT);
	return true;
}

bool sqlite3_column_preimage(sqlite3_stmt *stmt, int col,  struct preimage *dest)
{
	assert(sqlite3_column_bytes(stmt, col) == sizeof(struct preimage));
	return memcpy(dest, sqlite3_column_blob(stmt, col), sizeof(struct preimage));
}

bool sqlite3_bind_preimage(sqlite3_stmt *stmt, int col, const struct preimage *p)
{
	sqlite3_bind_blob(stmt, col, p, sizeof(struct preimage), SQLITE_TRANSIENT);
	return true;
}

bool sqlite3_column_sha256(sqlite3_stmt *stmt, int col,  struct sha256 *dest)
{
	assert(sqlite3_column_bytes(stmt, col) == sizeof(struct sha256));
	return memcpy(dest, sqlite3_column_blob(stmt, col), sizeof(struct sha256));
}

bool sqlite3_bind_sha256(sqlite3_stmt *stmt, int col, const struct sha256 *p)
{
	sqlite3_bind_blob(stmt, col, p, sizeof(struct sha256), SQLITE_TRANSIENT);
	return true;
}

bool sqlite3_column_sha256_double(sqlite3_stmt *stmt, int col,  struct sha256_double *dest)
{
	assert(sqlite3_column_bytes(stmt, col) == sizeof(struct sha256_double));
	return memcpy(dest, sqlite3_column_blob(stmt, col), sizeof(struct sha256_double));
}

bool sqlite3_bind_sha256_double(sqlite3_stmt *stmt, int col, const struct sha256_double *p)
{
	sqlite3_bind_blob(stmt, col, p, sizeof(struct sha256_double), SQLITE_TRANSIENT);
	return true;
}
