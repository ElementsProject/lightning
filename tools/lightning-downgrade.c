/* Tool for limited downgrade of an offline node */
#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/configdir.h>
#include <common/node_id.h>
#include <common/utils.h>
#include <db/bindings.h>
#include <db/common.h>
#include <db/exec.h>
#include <db/utils.h>
#include <plugins/askrene/datastore_wire.h>
#include <stdio.h>
#include <unistd.h>
#include <wallet/datastore.h>
#include <wallet/migrations.h>
#include <wire/wire.h>

#define ERROR_DBVERSION 1
#define ERROR_DBFAIL 2
#define ERROR_USAGE 3
#define ERROR_INTERNAL 99

#define PREV_VERSION stringify(CLN_PREV_VERSION)

struct db_version {
	const char *name;
	size_t db_height;
	const char *(*downgrade_datastore)(const tal_t *ctx, struct db *db);
	bool gossip_store_compatible;
};

struct layer {
	const char **key;
	const u8 *data;
};

static void copy_data(u8 **out, const u8 *in, size_t len)
{
	size_t oldlen = tal_bytelen(*out);

	tal_resize(out, oldlen + len);
	memcpy(*out + oldlen, in, len);
}

/* askrene added DSTORE_CHANNEL_BIAS_V2 (convertable) and
 * DSTORE_NODE_BIAS (not convertable) */
static const char *convert_layer_data(const tal_t *ctx,
				      const char *layername,
				      const u8 *data_in,
				      const u8 **data_out)
{
	size_t len = tal_bytelen(data_in);
	struct node_id n;
 	struct short_channel_id scid;
	struct amount_msat msat, *msat_ptr;
 	struct short_channel_id_dir scidd;
	bool *bool_ptr;
	u64 timestamp;
	u32 *u32_ptr;
	u16 *u16_ptr;
	s8 bias;
	const char *string;
	u8 *out = tal_arr(ctx, u8, 0);

	/* Unfortunately, there are no explicit lengths, so we have
	 * to read all records even if we don't care about them. */
	while (len != 0) {
		enum dstore_layer_type type;
		const u8 *olddata = data_in;
		type = fromwire_peektypen(data_in, len);

		switch (type) {
		/* These are all simply digested and copied */
		case DSTORE_CHANNEL:
			if (fromwire_dstore_channel(&data_in, &len,
						    &n, &n, &scid, &msat))
				copy_data(&out, data_in, olddata - data_in);
			continue;
		case DSTORE_CHANNEL_UPDATE:
			if (fromwire_dstore_channel_update(tmpctx, &data_in, &len,
							   &scidd, &bool_ptr,
							   &msat_ptr, &msat_ptr, &msat_ptr,
							   &u32_ptr, &u16_ptr))
				copy_data(&out, data_in, olddata - data_in);
			continue;
		case DSTORE_CHANNEL_CONSTRAINT:
			if (fromwire_dstore_channel_constraint(tmpctx, &data_in, &len,
							       &scidd, &timestamp,
							       &msat_ptr, &msat_ptr))
				copy_data(&out, data_in, olddata - data_in);
			continue;
		case DSTORE_CHANNEL_BIAS:
			if (fromwire_dstore_channel_bias(tmpctx, &data_in, &len,
							 &scidd, &bias,
							 &string))
				copy_data(&out, data_in, olddata - data_in);
			continue;
		case DSTORE_DISABLED_NODE:
			if (fromwire_dstore_disabled_node(&data_in, &len, &n))
				copy_data(&out, data_in, olddata - data_in);
			continue;

		/* Convert back, lose timestamp */
		case DSTORE_CHANNEL_BIAS_V2:
			if (fromwire_dstore_channel_bias_v2(tmpctx, &data_in, &len,
							    &scidd, &bias,
							    &string, &timestamp)) {
				towire_dstore_channel_bias(&out, &scidd, bias, string);
			}
			continue;

		case DSTORE_NODE_BIAS:
			return "Askrene has a node bias, which is not supported in v25.09";
		}

		return tal_fmt(ctx, "Unknown askrene layer record %u in %s", type, layername);
	}

	if (!data_in)
		return tal_fmt(ctx, "Corrupt askrene layer record for %s", layername);

	*data_out = out;
	return NULL;
}

static const char *downgrade_askrene_layers(const tal_t *ctx, struct db *db)
{
	const char **base, **k;
	const u8 *data;
	struct db_stmt *stmt;
	struct layer **layers = tal_arr(tmpctx, struct layer *, 0);

	base = tal_arr(tmpctx, const char *, 2);
	base[0] = "askrene";
	base[1] = "layers";

	/* Gather and convert */
	for (stmt = db_datastore_first(tmpctx, db, base,
				       &k, &data, NULL);
	     stmt;
	     stmt = db_datastore_next(tmpctx, stmt, base,
				      &k, &data, NULL)) {
		struct layer *layer;
		const char *err;

		if (!data)
			continue;
		layer = tal(layers, struct layer);
		layer->key = tal_steal(layer, k);
		err = convert_layer_data(layer, k[2], data, &layer->data);
		if (err) {
			tal_free(stmt);
			return err;
		}
		tal_arr_expand(&layers, layer);
	}

	/* Write back */
	for (size_t i = 0; i < tal_count(layers); i++)
		db_datastore_update(db, layers[i]->key, layers[i]->data);
	return NULL;
}

static const struct db_version db_versions[] = {
	{ "v25.09", 276, downgrade_askrene_layers, false },
	{ "v25.12", 280, NULL, true },
};

static const struct db_version *version_db(const char *version)
{
	for (size_t i = 0; i < ARRAY_SIZE(db_versions); i++) {
		if (streq(db_versions[i].name, version))
			return &db_versions[i];
	}
	errx(ERROR_INTERNAL, "Unknown version %s", version);
}

static void db_error(void *unused, bool fatal, const char *fmt, va_list ap)
{
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	if (fatal)
		exit(ERROR_DBFAIL);
}

/* The standard opt_log_stderr_exit exits with status 1 */
static void opt_log_stderr_exit_usage(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(ERROR_USAGE);
}

int main(int argc, char *argv[])
{
	char *config_filename, *base_dir, *net_dir, *rpc_filename, *wallet_dsn = NULL;
	const struct db_version *prev_version;
	size_t current, num_migrations;
	struct db *db;
	const struct db_migration *migrations;
	struct db_stmt *stmt;

	setup_locale();
	err_set_progname(argv[0]);

	minimal_config_opts(tmpctx, argc, argv, &config_filename, &base_dir,
			    &net_dir, &rpc_filename);
	opt_register_early_arg("--wallet", opt_set_talstr, NULL,
			       &wallet_dsn,
			       "Location of the wallet database.");
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "A tool to downgrade an offline Core Lightning Node to " PREV_VERSION,
			   "Print this message.");
	opt_early_parse(argc, argv, opt_log_stderr_exit_usage);
	opt_parse(&argc, argv, opt_log_stderr_exit_usage);

	if (argc != 1)
		opt_usage_exit_fail("No arguments expected");

	if (!wallet_dsn)
		wallet_dsn = tal_fmt(tmpctx, "sqlite3://%s/lightningd.sqlite3", net_dir);

	if (path_is_file(path_join(tmpctx, base_dir,
				   tal_fmt(tmpctx, "lightningd-%s.pid",
					   chainparams->network_name)))) {
		errx(ERROR_USAGE,
		     "Lightningd PID file exists, aborting: lightningd must not be running");
	}

	migrations = get_db_migrations(&num_migrations);
	prev_version = version_db(PREV_VERSION);

	/* Do this even if the db hasn't changed. */
	if (!version_db(PREV_VERSION)->gossip_store_compatible) {
		printf("Deleting incompatible gossip_store\n");
		unlink(path_join(tmpctx, net_dir, "gossip_store"));
	}

	/* Open db, check it's the expected version */
	db = db_open(tmpctx, wallet_dsn, false, false, db_error, NULL);
	if (!db)
		err(1, "Could not open database %s", wallet_dsn);
	db->report_changes_fn = NULL;

	db_begin_transaction(db);
	db->data_version = db_data_version_get(db);
	current = db_get_version(db);

	if (current < prev_version->db_height)
		errx(ERROR_DBVERSION, "Database version %zu already less than %zu expected for %s",
		     current, prev_version->db_height, PREV_VERSION);
	if (current == prev_version->db_height) {
		printf("Already compatible with %s\n", PREV_VERSION);
		exit(0);
	}
	if (current >= num_migrations)
		errx(ERROR_DBVERSION, "Unknown database version %zu: I only know up to %zu (%s)",
		     current, num_migrations, stringify(CLN_NEXT_VERSION));

	/* current version is the last migration we did. */
	while (current > prev_version->db_height) {
		if (migrations[current].revertsql) {
			stmt = db_prepare_v2(db, migrations[current].revertsql);
			db_exec_prepared_v2(stmt);
			tal_free(stmt);
		}
		if (migrations[current].revertfn) {
			const char *error = migrations[current].revertfn(tmpctx, db);
			if (error)
				errx(ERROR_DBFAIL, "Downgrade failed: %s", error);
		}
		current--;
	}

	if (prev_version->downgrade_datastore) {
		const char *error = prev_version->downgrade_datastore(tmpctx, db);
		if (error)
			errx(ERROR_DBFAIL, "Downgrade failed: %s", error);
	}

	/* Finally update the version number in the version table */
	stmt = db_prepare_v2(db, SQL("UPDATE version SET version=?;"));
	db_bind_int(stmt, current);
	db_exec_prepared_v2(stmt);
	tal_free(stmt);

	printf("Downgrade to %s succeeded.  Committing.\n", PREV_VERSION);
	db_commit_transaction(db);
	tal_free(db);
}

/*** We don't actually perform migrations, so these are stubs which abort. ***/
/* Remake with `make update-mocks` or `make update-mocks/tools/lightning-downgrade.c` */

/* AUTOGENERATED MOCKS START */
/* Generated stub for fillin_missing_channel_blockheights */
void fillin_missing_channel_blockheights(struct lightningd *ld UNNEEDED,
					 struct db *db UNNEEDED)
{ fprintf(stderr, "fillin_missing_channel_blockheights called!\n"); abort(); }
/* Generated stub for fillin_missing_channel_id */
void fillin_missing_channel_id(struct lightningd *ld UNNEEDED, struct db *db UNNEEDED)
{ fprintf(stderr, "fillin_missing_channel_id called!\n"); abort(); }
/* Generated stub for fillin_missing_lease_satoshi */
void fillin_missing_lease_satoshi(struct lightningd *ld UNNEEDED,
				  struct db *db UNNEEDED)
{ fprintf(stderr, "fillin_missing_lease_satoshi called!\n"); abort(); }
/* Generated stub for fillin_missing_local_basepoints */
void fillin_missing_local_basepoints(struct lightningd *ld UNNEEDED,
				     struct db *db UNNEEDED)
{ fprintf(stderr, "fillin_missing_local_basepoints called!\n"); abort(); }
/* Generated stub for fillin_missing_scriptpubkeys */
void fillin_missing_scriptpubkeys(struct lightningd *ld UNNEEDED, struct db *db UNNEEDED)
{ fprintf(stderr, "fillin_missing_scriptpubkeys called!\n"); abort(); }
/* Generated stub for insert_addrtype_to_addresses */
void insert_addrtype_to_addresses(struct lightningd *ld UNNEEDED,
				  struct db *db UNNEEDED)
{ fprintf(stderr, "insert_addrtype_to_addresses called!\n"); abort(); }
/* Generated stub for migrate_channels_scids_as_integers */
void migrate_channels_scids_as_integers(struct lightningd *ld UNNEEDED,
					struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_channels_scids_as_integers called!\n"); abort(); }
/* Generated stub for migrate_convert_old_channel_keyidx */
void migrate_convert_old_channel_keyidx(struct lightningd *ld UNNEEDED,
					struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_convert_old_channel_keyidx called!\n"); abort(); }
/* Generated stub for migrate_datastore_commando_runes */
void migrate_datastore_commando_runes(struct lightningd *ld UNNEEDED, struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_datastore_commando_runes called!\n"); abort(); }
/* Generated stub for migrate_fail_pending_payments_without_htlcs */
void migrate_fail_pending_payments_without_htlcs(struct lightningd *ld UNNEEDED,
						 struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_fail_pending_payments_without_htlcs called!\n"); abort(); }
/* Generated stub for migrate_fill_in_channel_type */
void migrate_fill_in_channel_type(struct lightningd *ld UNNEEDED,
				  struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_fill_in_channel_type called!\n"); abort(); }
/* Generated stub for migrate_forwards_add_rowid */
void migrate_forwards_add_rowid(struct lightningd *ld UNNEEDED,
				struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_forwards_add_rowid called!\n"); abort(); }
/* Generated stub for migrate_from_account_db */
void migrate_from_account_db(struct lightningd *ld UNNEEDED, struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_from_account_db called!\n"); abort(); }
/* Generated stub for migrate_inflight_last_tx_to_psbt */
void migrate_inflight_last_tx_to_psbt(struct lightningd *ld UNNEEDED, struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_inflight_last_tx_to_psbt called!\n"); abort(); }
/* Generated stub for migrate_initialize_alias_local */
void migrate_initialize_alias_local(struct lightningd *ld UNNEEDED,
				    struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_initialize_alias_local called!\n"); abort(); }
/* Generated stub for migrate_initialize_channel_htlcs_wait_indexes_and_fixup_forwards */
void migrate_initialize_channel_htlcs_wait_indexes_and_fixup_forwards(struct lightningd *ld UNNEEDED,
								      struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_initialize_channel_htlcs_wait_indexes_and_fixup_forwards called!\n"); abort(); }
/* Generated stub for migrate_initialize_forwards_wait_indexes */
void migrate_initialize_forwards_wait_indexes(struct lightningd *ld UNNEEDED,
					      struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_initialize_forwards_wait_indexes called!\n"); abort(); }
/* Generated stub for migrate_initialize_invoice_wait_indexes */
void migrate_initialize_invoice_wait_indexes(struct lightningd *ld UNNEEDED,
					     struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_initialize_invoice_wait_indexes called!\n"); abort(); }
/* Generated stub for migrate_initialize_payment_wait_indexes */
void migrate_initialize_payment_wait_indexes(struct lightningd *ld UNNEEDED,
					     struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_initialize_payment_wait_indexes called!\n"); abort(); }
/* Generated stub for migrate_invalid_last_tx_psbts */
void migrate_invalid_last_tx_psbts(struct lightningd *ld UNNEEDED,
				   struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_invalid_last_tx_psbts called!\n"); abort(); }
/* Generated stub for migrate_invoice_created_index_var */
void migrate_invoice_created_index_var(struct lightningd *ld UNNEEDED,
				       struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_invoice_created_index_var called!\n"); abort(); }
/* Generated stub for migrate_last_tx_to_psbt */
void migrate_last_tx_to_psbt(struct lightningd *ld UNNEEDED, struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_last_tx_to_psbt called!\n"); abort(); }
/* Generated stub for migrate_normalize_invstr */
void migrate_normalize_invstr(struct lightningd *ld UNNEEDED,
			      struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_normalize_invstr called!\n"); abort(); }
/* Generated stub for migrate_our_funding */
void migrate_our_funding(struct lightningd *ld UNNEEDED, struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_our_funding called!\n"); abort(); }
/* Generated stub for migrate_payments_scids_as_integers */
void migrate_payments_scids_as_integers(struct lightningd *ld UNNEEDED,
					struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_payments_scids_as_integers called!\n"); abort(); }
/* Generated stub for migrate_pr2342_feerate_per_channel */
void migrate_pr2342_feerate_per_channel(struct lightningd *ld UNNEEDED, struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_pr2342_feerate_per_channel called!\n"); abort(); }
/* Generated stub for migrate_remove_chain_moves_duplicates */
void migrate_remove_chain_moves_duplicates(struct lightningd *ld UNNEEDED, struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_remove_chain_moves_duplicates called!\n"); abort(); }
/* Generated stub for migrate_runes_idfix */
void migrate_runes_idfix(struct lightningd *ld UNNEEDED, struct db *db UNNEEDED)
{ fprintf(stderr, "migrate_runes_idfix called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */
