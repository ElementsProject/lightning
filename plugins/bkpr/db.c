#include "config.h"
#include <ccan/array_size/array_size.h>
#include <db/bindings.h>
#include <db/common.h>
#include <db/exec.h>
#include <db/utils.h>
#include <plugins/bkpr/db.h>
#include <plugins/libplugin.h>
#include <stdio.h>

struct migration {
	const char *sql;
	void (*func)(struct plugin *p, struct db *db);
};

static struct plugin *plugin;

/* Do not reorder or remove elements from this array.
 * It is used to migrate existing databases from a prevoius state, based on
 * string indicies */
static struct migration db_migrations[] = {
	{SQL("CREATE TABLE version (version INTEGER);"), NULL},
	{SQL("INSERT INTO version VALUES (1);"), NULL},
	{SQL("CREATE TABLE vars ("
		"  name TEXT"
		", val TEXT"
		", intval INTEGER"
		", blobval BLOB"
		", PRIMARY KEY (name)"
		");"),
	NULL},
	{SQL("INSERT INTO vars ("
		"  name"
		", intval"
		") VALUES ("
		" 'data_version'"
		", 0"
		");"),
	NULL},
	{SQL("CREATE TABLE accounts ("
		"  id BIGSERIAL"
		", name TEXT"
		", peer_id BLOB"
		", opened_event_id BIGINT"
		", closed_event_id BIGINT"
		", onchain_resolved_block INTEGER"
		", is_wallet INTEGER"
		", we_opened INTEGER"
		", leased INTEGER"
		", PRIMARY KEY (id)"
		");"),
	NULL},
	{SQL("CREATE TABLE chain_events ("
		"  id BIGSERIAL"
		", account_id BIGINT REFERENCES accounts(id)"
		", tag TEXT"
		", credit BIGINT"
		", debit BIGINT"
		", output_value BIGINT"
		", currency TEXT"
		", timestamp BIGINT"
		", blockheight INTEGER"
		", utxo_txid BLOB"
		", outnum INTEGER"
		", payment_id BLOB"
		", spending_txid BLOB"
		", PRIMARY KEY (id)"
		");"),
	NULL},
	{SQL("CREATE TABLE channel_events ("
		"  id BIGSERIAL"
		", account_id BIGINT REFERENCES accounts(id)"
		", tag TEXT"
		", credit BIGINT"
		", debit BIGINT"
		", fees BIGINT"
		", currency TEXT"
		", payment_id BLOB"
		", part_id INTEGER"
		", timestamp BIGINT"
		", PRIMARY KEY (id)"
		");"),
	NULL},
	{SQL("CREATE TABLE onchain_fees ("
		"account_id BIGINT REFERENCES accounts(id)"
		", txid BLOB"
		", credit BIGINT"
		", debit BIGINT"
		", currency TEXT"
		", timestamp BIGINT"
		", update_count INT"
		", PRIMARY KEY (account_id, txid, update_count)"
		");"),
	NULL},
	{SQL("ALTER TABLE chain_events ADD origin TEXT;"), NULL},
	{SQL("ALTER TABLE accounts ADD closed_count INTEGER DEFAULT 0;"), NULL},
	{SQL("ALTER TABLE chain_events ADD ignored INTEGER;"), NULL},
	{SQL("ALTER TABLE chain_events ADD stealable INTEGER;"), NULL},
	{SQL("ALTER TABLE chain_events ADD ev_desc TEXT DEFAULT NULL;"), NULL},
	{SQL("ALTER TABLE channel_events ADD ev_desc TEXT DEFAULT NULL;"), NULL},
};

static bool db_migrate(struct plugin *p, struct db *db)
{
	/* Read current version from database */
	int current, orig, available;
	struct db_stmt *stmt;

	orig = current = db_get_version(db);
	available = ARRAY_SIZE(db_migrations) - 1;

	if (current == -1)
		plugin_log(p, LOG_INFORM, "Creating database");
	else if (available < current)
		plugin_err(p,
			   "Refusing to migrate down from version %u to %u",
			   current, available);
	else if (current != available)
		plugin_log(p, LOG_INFORM,
			   "Updating database from version %u to %u",
			   current, available);

	while (current < available) {
		current++;
		if (db_migrations[current].sql) {
			struct db_stmt *stmt =
				db_prepare_v2(db, db_migrations[current].sql);
			db_exec_prepared_v2(take(stmt));
		}
		if (db_migrations[current].func)
			db_migrations[current].func(p, db);
	}

	/* Finally, update the version number in the version table */
	stmt = db_prepare_v2(db, SQL("UPDATE version SET version=?;"));
	db_bind_int(stmt, 0, available);
	db_exec_prepared_v2(take(stmt));

	return current != orig;
}

/* Implement db_fatal, as a wrapper around fatal.
 * We use a ifndef block so that it can get be
 * implemented in a test file first, if necessary */
#ifndef DB_FATAL
#define DB_FATAL
void db_fatal(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	plugin_errv(plugin, fmt, ap);
	/* Won't actually exit, but va_end() required to balance va_start in standard. */
	va_end(ap);
}
#endif /* DB_FATAL */

struct db *db_setup(const tal_t *ctx, struct plugin *p, char *db_dsn)
{
	bool migrated;
	struct db *db;

	/* Set global for db_fatal */
	plugin = p;
	db = db_open(ctx, db_dsn);
	db->report_changes_fn = NULL;

	db_begin_transaction(db);
	migrated = db_migrate(p, db);
	db->data_version = db_data_version_get(db);
	db_commit_transaction(db);

	/* This needs to be done outside a transaction, apparently.
	 * It's a good idea to do this every so often, and on db
	 * upgrade is a reasonable time. */
	if (migrated && !db->config->vacuum_fn(db))
		db_fatal("Error vacuuming db: %s", db->error);

	return db;
}
