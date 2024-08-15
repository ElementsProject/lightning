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

static void migration_remove_dupe_lease_fees(struct plugin *p, struct db *db);
static void migration_maybe_add_chainevents_spliced(struct plugin *p, struct db *db);

/* Do not reorder or remove elements from this array.
 * It is used to migrate existing databases from a prevoius state, based on
 * string indices */
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
	{SQL("ALTER TABLE channel_events ADD rebalance_id BIGINT DEFAULT NULL;"), NULL},
	{SQL("ALTER TABLE chain_events ADD spliced INTEGER DEFAULT 0;"), NULL},
	{NULL, migration_remove_dupe_lease_fees},
	{NULL, migration_maybe_add_chainevents_spliced}
};

static bool db_migrate(struct plugin *p, struct db *db)
{
	/* Read current version from database */
	int current, orig, available;
	struct db_stmt *stmt;

	orig = current = db_get_version(db);
	available = ARRAY_SIZE(db_migrations) - 1;

	if (current == -1) {
		plugin_log(p, LOG_INFORM, "Creating database");
	} else if (available < current)
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
			stmt = db_prepare_v2(db, db_migrations[current].sql);
			db_exec_prepared_v2(take(stmt));
		}
		if (db_migrations[current].func)
			db_migrations[current].func(p, db);
	}

	/* Finally, update the version number in the version table */
	stmt = db_prepare_v2(db, SQL("UPDATE version SET version=?;"));
	db_bind_int(stmt, available);
	db_exec_prepared_v2(take(stmt));

	return current != orig;
}

static void migration_remove_dupe_lease_fees(struct plugin *p, struct db *db)
{
	struct db_stmt *stmt, *del_stmt;
	u64 *last_acct_id;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     "  id"
				     ", account_id"
				     " FROM channel_events"
				     " WHERE tag = 'lease_fee'"
				     " ORDER BY account_id"));
	db_query_prepared(stmt);
	last_acct_id = NULL;
	while (db_step(stmt)) {
		u64 id, acct_id;
		id = db_col_u64(stmt, "id");
		acct_id = db_col_u64(stmt, "account_id");

		if (!last_acct_id) {
			last_acct_id = tal(stmt, u64);
			*last_acct_id = acct_id;
			continue;
		}

		if (*last_acct_id != acct_id) {
			*last_acct_id = acct_id;
			continue;
		}

		plugin_log(p, LOG_INFORM,
			   "Duplicate 'lease_fee' found for"
			   " account %"PRIu64", deleting dupe",
			   id);

		/* same acct as last, we found a duplicate */
		del_stmt = db_prepare_v2(db, SQL("DELETE FROM channel_events"
						 " WHERE id=?"));
		db_bind_u64(del_stmt, id);
		db_exec_prepared_v2(take(del_stmt));
	}
	tal_free(stmt);
}

/* OK, funny story.  We added the "ALTER TABLE chain_events ADD spliced INTEGER DEFAULT 0;"
 * migration in the wrong place, NOT at the end.  So if you are migrating from an old version,
 * "migration_remove_dupe_lease_fees" ran (again), which is harmless, but this migration
 * never got added. */
static void migration_maybe_add_chainevents_spliced(struct plugin *p, struct db *db)
{
	struct db_stmt *stmt;
	bool col_exists;

	stmt = db_prepare_v2(db, SQL("SELECT spliced FROM chain_events"));
	col_exists = db_query_prepared_canfail(stmt);
	tal_free(stmt);
	if (col_exists)
		return;

	plugin_log(p, LOG_INFORM,
		   "Database fixup: adding spliced column to chain_events table");
	stmt = db_prepare_v2(db, SQL("ALTER TABLE chain_events ADD spliced INTEGER DEFAULT 0;"));
	db_exec_prepared_v2(take(stmt));
}

static void db_error(struct plugin *plugin, bool fatal, const char *fmt, va_list ap)
{
	if (fatal)
		plugin_errv(plugin, fmt, ap);
	else
		plugin_logv(plugin, LOG_BROKEN, fmt, ap);
}

struct db *db_setup(const tal_t *ctx, struct plugin *p,
		    const char *db_dsn)
{
	bool migrated;
	struct db *db;

	db = db_open(ctx, db_dsn, plugin_developer_mode(p), db_error, p);
	db->report_changes_fn = NULL;

	db_begin_transaction(db);
	migrated = db_migrate(p, db);
	db->data_version = db_data_version_get(db);
	db_commit_transaction(db);

	/* This needs to be done outside a transaction, apparently.
	 * It's a good idea to do this every so often, and on db
	 * upgrade is a reasonable time. */
	if (migrated && !db->config->vacuum_fn(db))
		db_fatal(db, "Error vacuuming db: %s", db->error);

	return db;
}
