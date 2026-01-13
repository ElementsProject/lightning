#include "config.h"
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/utils.h>
#include <common/version.h>
#include <db/bindings.h>
#include <db/common.h>
#include <db/exec.h>
#include <db/utils.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/channel.h>
#include <lightningd/hsm_control.h>
#include <lightningd/plugin_hook.h>
#include <wallet/account_migration.h>
#include <wallet/db.h>
#include <wallet/migrations.h>
#include <wallet/psbt_fixup.h>
#include <wire/wire_sync.h>

/**
 * db_migrate - Apply all remaining migrations from the current version
 */
static bool db_migrate(struct lightningd *ld, struct db *db,
		       const struct ext_key *bip32_base)
{
	/* Attempt to read the version from the database */
	int current, orig, available;
	size_t num_migrations;
	char *err_msg;
	struct db_stmt *stmt;
	const struct db_migration *dbmigrations = get_db_migrations(&num_migrations);

	/* This is the final number, not the count! */
	available = num_migrations - 1;
	orig = current = db_get_version(db);

	/* Disable STRICT for upgrades: legacy data may have wrong type affinity. */
	db->in_migration = (current != -1);

	if (current == -1)
		log_info(ld->log, "Creating database");
	else if (available < current) {
		err_msg = tal_fmt(tmpctx, "Refusing to migrate down from version %u to %u",
			 current, available);
		db_fatal(db, "%s", err_msg);
	} else if (current != available) {
		if (ld->db_upgrade_ok && *ld->db_upgrade_ok == false) {
			db_fatal(db,
				 "Refusing to upgrade db from version %u to %u (database-upgrade=false)",
				 current, available);
		} else if (!ld->db_upgrade_ok && !is_released_version()) {
			db_fatal(db, "Refusing to irreversibly upgrade db from version %u to %u in non-final version %s (use --database-upgrade=true to override)",
				 current, available, version());
		}
		log_info(ld->log, "Updating database from version %u to %u",
			 current, available);
	}

	while (current < available) {
		current++;
		if (dbmigrations[current].sql) {
			stmt = db_prepare_v2(db, dbmigrations[current].sql);
			db_exec_prepared_v2(stmt);
			tal_free(stmt);
		}
		if (dbmigrations[current].func)
			dbmigrations[current].func(ld, db);
	}

	/* Finally update the version number in the version table */
	stmt = db_prepare_v2(db, SQL("UPDATE version SET version=?;"));
	db_bind_int(stmt, available);
	db_exec_prepared_v2(stmt);
	tal_free(stmt);

	/* Annotate that we did upgrade, if any. */
	if (current != orig) {
		stmt = db_prepare_v2(
		    db, SQL("INSERT INTO db_upgrades VALUES (?, ?);"));
		db_bind_int(stmt, orig);
		db_bind_text(stmt, version());
		db_exec_prepared_v2(stmt);
		tal_free(stmt);
	}

	return current != orig;
}

static void db_error(struct lightningd *ld, bool fatal, const char *fmt, va_list ap)
{
	va_list ap2;

	va_copy(ap2, ap);
	logv(ld->log, LOG_BROKEN, NULL, true, fmt, ap);

	if (fatal)
		fatal_vfmt(fmt, ap2);
	va_end(ap2);
}

struct db *db_setup(const tal_t *ctx, struct lightningd *ld,
		    const struct ext_key *bip32_base)
{
	struct db *db = db_open(ctx, ld->wallet_dsn, ld->developer, true,
				db_error, ld);
	bool migrated;

	db->report_changes_fn = plugin_hook_db_sync;

	db_begin_transaction(db);
	db->data_version = db_data_version_get(db);

	migrated = db_migrate(ld, db, bip32_base);

	db_commit_transaction(db);

	db->in_migration = false;

	/* This needs to be done outside a transaction, apparently.
	 * It's a good idea to do this every so often, and on db
	 * upgrade is a reasonable time. */
	if (migrated && !db->config->vacuum_fn(db))
		db_fatal(db, "Error vacuuming db: %s", db->error);

	return db;
}

/* Will apply the current config fee settings to all channels */
void migrate_pr2342_feerate_per_channel(struct lightningd *ld, struct db *db)
{
	struct db_stmt *stmt = db_prepare_v2(
	    db, SQL("UPDATE channels SET feerate_base = ?, feerate_ppm = ?;"));

	db_bind_int(stmt, ld->config.fee_base);
	db_bind_int(stmt, ld->config.fee_per_satoshi);

	db_exec_prepared_v2(stmt);
	tal_free(stmt);
}

/* We've added a column `our_funding_satoshis`, since channels can now
 * have funding for either channel participant. We need to 'backfill' this
 * data, however. We can do this using the fact that our_funding_satoshi
 * is the same as the funding_satoshi for every channel where we are
 * the `funder`
 */
void migrate_our_funding(struct lightningd *ld, struct db *db)
{
	struct db_stmt *stmt;

	/* Statement to update record */
	stmt = db_prepare_v2(db, SQL("UPDATE channels"
				     " SET our_funding_satoshi = funding_satoshi"
				     " WHERE funder = 0;")); /* 0 == LOCAL */
	db_exec_prepared_v2(stmt);
	if (stmt->error)
		db_fatal(stmt->db,
			 "Error migrating funding satoshis to our_funding (%s)",
			 stmt->error);

	tal_free(stmt);
}

void fillin_missing_scriptpubkeys(struct lightningd *ld, struct db *db)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     " type"
				     ", keyindex"
				     ", prev_out_tx"
				     ", prev_out_index"
				     ", channel_id"
				     ", peer_id"
				     ", commitment_point"
				     " FROM outputs"
				     " WHERE scriptpubkey IS NULL;"));

	db_query_prepared(stmt);
	while (db_step(stmt)) {
		int type;
		u8 *scriptPubkey;
		struct bitcoin_txid txid;
		u32 outnum, keyindex;
		struct pubkey key;
		struct db_stmt *update_stmt;

		type = db_col_int(stmt, "type");
		keyindex = db_col_int(stmt, "keyindex");
		db_col_txid(stmt, "prev_out_tx", &txid);
		outnum = db_col_int(stmt, "prev_out_index");

		/* This indiciates whether or not we have 'close_info' */
		if (!db_col_is_null(stmt, "channel_id")) {
			struct pubkey *commitment_point;
			struct node_id peer_id;
			u64 channel_id;
			u8 *msg;

			channel_id = db_col_u64(stmt, "channel_id");
			db_col_node_id(stmt, "peer_id", &peer_id);
			commitment_point = db_col_optional(stmt, stmt, "commitment_point", pubkey);

			/* Have to go ask the HSM to derive the pubkey for us */
			msg = towire_hsmd_get_output_scriptpubkey(NULL,
								 channel_id,
								 &peer_id,
								 commitment_point);
			if (!wire_sync_write(ld->hsm_fd, take(msg)))
				fatal("Could not write to HSM: %s", strerror(errno));
			msg = wire_sync_read(stmt, ld->hsm_fd);
			if (!fromwire_hsmd_get_output_scriptpubkey_reply(stmt, msg,
									&scriptPubkey))
				fatal("HSM gave bad hsm_get_output_scriptpubkey_reply %s",
				      tal_hex(msg, msg));
		} else {
			db_col_ignore(stmt, "peer_id");
			db_col_ignore(stmt, "commitment_point");
			bip32_pubkey(ld, &key, keyindex);
			if (type == WALLET_OUTPUT_P2SH_WPKH) {
				u8 *redeemscript = bitcoin_redeem_p2sh_p2wpkh(stmt, &key);
				scriptPubkey = scriptpubkey_p2sh(tmpctx, redeemscript);
			} else
				scriptPubkey = scriptpubkey_p2wpkh(stmt, &key);
		}

		update_stmt = db_prepare_v2(db, SQL("UPDATE outputs"
						    " SET scriptpubkey = ?"
						    " WHERE prev_out_tx = ? "
						    "   AND prev_out_index = ?"));
		db_bind_blob(update_stmt, scriptPubkey, tal_bytelen(scriptPubkey));
		db_bind_txid(update_stmt, &txid);
		db_bind_int(update_stmt, outnum);
		db_exec_prepared_v2(update_stmt);
		tal_free(update_stmt);
	}

	tal_free(stmt);
}

/*
 * V2 channel open has a different channel_id format than v1. prior to this, we
 * could simply derive the channel_id whenever it was required, but since there
 * are now two ways to do it, we save the derived channel id.
 */
void fillin_missing_channel_id(struct lightningd *ld, struct db *db)
{

	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT"
				     " id"
				     ", funding_tx_id"
				     ", funding_tx_outnum"
				     " FROM channels;"));

	db_query_prepared(stmt);
	while (db_step(stmt)) {
		struct db_stmt *update_stmt;
		size_t id;
		struct bitcoin_outpoint funding;
		struct channel_id cid;

		id = db_col_u64(stmt, "id");
		db_col_txid(stmt, "funding_tx_id", &funding.txid);
		funding.n = db_col_int(stmt, "funding_tx_outnum");
		derive_channel_id(&cid, &funding);

		update_stmt = db_prepare_v2(db, SQL("UPDATE channels"
						    " SET full_channel_id = ?"
						    " WHERE id = ?;"));
		db_bind_channel_id(update_stmt, &cid);
		db_bind_u64(update_stmt, id);

		db_exec_prepared_v2(update_stmt);
		tal_free(update_stmt);
	}

	tal_free(stmt);
}

void fillin_missing_local_basepoints(struct lightningd *ld,
				     struct db *db)
{

	struct db_stmt *stmt;
	stmt = db_prepare_v2(
		db,
		SQL("SELECT"
		    "  channels.id"
		    ", peers.node_id "
		    "FROM"
		    "  channels JOIN"
		    "  peers "
		    "ON (peers.id = channels.peer_id)"));

	db_query_prepared(stmt);
	while (db_step(stmt)) {
		struct node_id peer_id;
		u64 dbid;
		u8 *msg;
		struct db_stmt *upstmt;
		struct basepoints base;
		struct pubkey funding_pubkey;

		dbid = db_col_u64(stmt, "channels.id");
		db_col_node_id(stmt, "peers.node_id", &peer_id);

		if (!wire_sync_write(ld->hsm_fd,
				     towire_hsmd_get_channel_basepoints(
					 tmpctx, &peer_id, dbid)))
			fatal("could not retrieve basepoint from hsmd");

		msg = wire_sync_read(tmpctx, ld->hsm_fd);
		if (!fromwire_hsmd_get_channel_basepoints_reply(
			msg, &base, &funding_pubkey))
			fatal("malformed hsmd_get_channel_basepoints_reply "
			      "from hsmd");

		upstmt = db_prepare_v2(
			db,
			SQL("UPDATE channels SET"
			    "  revocation_basepoint_local = ?"
			    ", payment_basepoint_local = ?"
			    ", htlc_basepoint_local = ?"
			    ", delayed_payment_basepoint_local = ?"
			    ", funding_pubkey_local = ? "
			    "WHERE id = ?;"));
		db_bind_pubkey(upstmt, &base.revocation);
		db_bind_pubkey(upstmt, &base.payment);
		db_bind_pubkey(upstmt, &base.htlc);
		db_bind_pubkey(upstmt, &base.delayed_payment);
		db_bind_pubkey(upstmt, &funding_pubkey);

		db_bind_u64(upstmt, dbid);

		db_exec_prepared_v2(take(upstmt));
	}

	tal_free(stmt);
}

/* New 'channel_blockheights' table, every existing channel gets a
 * 'initial blockheight' of 0 */
void fillin_missing_channel_blockheights(struct lightningd *ld,
					 struct db *db)
{
	struct db_stmt *stmt;

	/* Set all existing channels to 0 */
	/* If we're funder (LOCAL=0):
	 *   Then our blockheight is set last (SENT_ADD_ACK_REVOCATION = 4) */
	stmt = db_prepare_v2(db,
			     SQL("INSERT INTO channel_blockheights"
				 "  (channel_id, hstate, blockheight)"
				 " SELECT id, 4, 0 FROM channels"
				 " WHERE funder = 0;"));
	db_exec_prepared_v2(take(stmt));
	/* If they're funder (REMOTE=1):
	 *   Then their blockheight is last (RCVD_ADD_ACK_REVOCATION = 14) */
	stmt = db_prepare_v2(db,
			     SQL("INSERT INTO channel_blockheights"
				 "  (channel_id, hstate, blockheight)"
				 " SELECT id, 14, 0 FROM channels"
				 " WHERE funder = 1;"));
	db_exec_prepared_v2(take(stmt));
}

void
migrate_inflight_last_tx_to_psbt(struct lightningd *ld, struct db *db)
{
	struct db_stmt *stmt, *update_stmt;
	stmt = db_prepare_v2(db, SQL("SELECT "
				     "  c.id"
				     ", p.node_id"
				     ", c.fundingkey_remote"
				     ", inflight.last_tx"
				     ", inflight.last_sig"
				     ", inflight.funding_satoshi"
				     ", inflight.funding_tx_id"
				     " FROM channels c"
				     "  LEFT OUTER JOIN peers p"
				     "   ON p.id = c.peer_id"
				     "  LEFT OUTER JOIN"
				     "   channel_funding_inflights inflight"
				     "   ON c.id = inflight.channel_id"
				     " WHERE inflight.last_tx IS NOT NULL;"));

	db_query_prepared(stmt);
	while (db_step(stmt)) {
		struct bitcoin_tx *last_tx;
		struct bitcoin_txid funding_txid;
		struct amount_sat funding_sat;
		struct node_id peer_id;
		struct pubkey local_funding_pubkey, remote_funding_pubkey;
		struct basepoints local_basepoints UNUSED;
		struct bitcoin_signature last_sig;
		u64 cdb_id;
		u8 *funding_wscript;

		cdb_id = db_col_u64(stmt, "c.id");
		last_tx = db_col_tx(stmt, stmt, "inflight.last_tx");
		assert(last_tx != NULL);

		/* FIXME: This is only needed inside the select? */
		db_col_ignore(stmt, "inflight.last_tx");

		/* If we've forgotten about the peer_id
		 * because we closed / forgot the channel,
		 * we can skip this. */
		if (db_col_is_null(stmt, "p.node_id")) {
			db_col_ignore(stmt, "inflight.last_sig");
			db_col_ignore(stmt, "inflight.funding_satoshi");
			db_col_ignore(stmt, "inflight.funding_tx_id");
			continue;
		}
		db_col_node_id(stmt, "p.node_id", &peer_id);
		funding_sat = db_col_amount_sat(stmt, "inflight.funding_satoshi");
		db_col_pubkey(stmt, "c.fundingkey_remote", &remote_funding_pubkey);
		db_col_txid(stmt, "inflight.funding_tx_id", &funding_txid);

		get_channel_basepoints(ld, &peer_id, cdb_id,
				       &local_basepoints, &local_funding_pubkey);

		funding_wscript = bitcoin_redeem_2of2(stmt, &local_funding_pubkey,
						      &remote_funding_pubkey);


		psbt_input_set_wit_utxo(last_tx->psbt, 0,
					scriptpubkey_p2wsh(last_tx->psbt, funding_wscript),
					funding_sat);
		psbt_input_set_witscript(last_tx->psbt, 0, funding_wscript);

		if (!db_col_signature(stmt, "inflight.last_sig", &last_sig.s))
			abort();

		last_sig.sighash_type = SIGHASH_ALL;
		if (!psbt_input_set_signature(last_tx->psbt, 0,
					      &remote_funding_pubkey, &last_sig))
			abort();
		psbt_input_add_pubkey(last_tx->psbt, 0,
		    &local_funding_pubkey, false /* is_taproot */);
		psbt_input_add_pubkey(last_tx->psbt, 0,
		    &remote_funding_pubkey, false /* is_taproot */);

		update_stmt = db_prepare_v2(db,
				SQL("UPDATE channel_funding_inflights"
				    " SET last_tx = ?"
				    " WHERE channel_id = ?"
				    "   AND funding_tx_id = ?;"));
		db_bind_psbt(update_stmt, last_tx->psbt);
		db_bind_int(update_stmt, cdb_id);
		db_bind_txid(update_stmt, &funding_txid);
		db_exec_prepared_v2(update_stmt);
		tal_free(update_stmt);
	}

	tal_free(stmt);
}

void load_indexes(struct db *db, struct indexes *indexes)
{
	for (size_t s = 0; s < NUM_WAIT_SUBSYSTEM; s++) {
		for (size_t i = 0; i < NUM_WAIT_INDEX; i++) {
			const char *fname = tal_fmt(tmpctx, "last_%s_%s_index",
						    wait_subsystem_name(s),
						    wait_index_name(i));
			indexes[s].i[i] = db_get_intvar(db, fname, 0);
		}
	}
}

/* We're moving everything over to PSBTs from tx's, particularly our last_tx's
 * which are commitment transactions for channels.
 * This migration loads all of the last_tx's and 're-formats' them into psbts,
 * adds the required input witness utxo information, and then saves it back to disk
 * */
void migrate_last_tx_to_psbt(struct lightningd *ld, struct db *db)
{
	struct db_stmt *stmt, *update_stmt;

	stmt = db_prepare_v2(db, SQL("SELECT "
				     "  c.id"
				     ", p.node_id"
				     ", c.last_tx"
				     ", c.funding_satoshi"
				     ", c.fundingkey_remote"
				     ", c.last_sig"
				     " FROM channels c"
				     "  LEFT OUTER JOIN peers p"
				     "  ON p.id = c.peer_id;"));

	db_query_prepared(stmt);
	while (db_step(stmt)) {
		struct bitcoin_tx *last_tx;
		struct amount_sat funding_sat;
		struct node_id peer_id;
		struct pubkey local_funding_pubkey, remote_funding_pubkey;
		struct basepoints local_basepoints UNUSED;
		struct bitcoin_signature last_sig;
		u64 cdb_id;
		u8 *funding_wscript;

		cdb_id = db_col_u64(stmt, "c.id");
		last_tx = db_col_tx(stmt, stmt, "c.last_tx");
		assert(last_tx != NULL);

		/* If we've forgotten about the peer_id
		 * because we closed / forgot the channel,
		 * we can skip this. */
		if (db_col_is_null(stmt, "p.node_id")) {
			db_col_ignore(stmt, "c.funding_satoshi");
			db_col_ignore(stmt, "c.fundingkey_remote");
			db_col_ignore(stmt, "c.last_sig");
			continue;
		}

		db_col_node_id(stmt, "p.node_id", &peer_id);
		funding_sat = db_col_amount_sat(stmt, "c.funding_satoshi");
		db_col_pubkey(stmt, "c.fundingkey_remote", &remote_funding_pubkey);

		get_channel_basepoints(ld, &peer_id, cdb_id,
				       &local_basepoints, &local_funding_pubkey);

		funding_wscript = bitcoin_redeem_2of2(stmt, &local_funding_pubkey,
						      &remote_funding_pubkey);


		psbt_input_set_wit_utxo(last_tx->psbt, 0,
					scriptpubkey_p2wsh(last_tx->psbt, funding_wscript),
					funding_sat);
		psbt_input_set_witscript(last_tx->psbt, 0, funding_wscript);
		if (is_elements(chainparams)) {
			/*FIXME: persist asset tags */
			struct amount_asset asset;
			asset = amount_sat_to_asset(&funding_sat,
						    chainparams->fee_asset_tag);
			psbt_elements_input_set_asset(last_tx->psbt, 0, &asset);
		}


		if (!db_col_signature(stmt, "c.last_sig", &last_sig.s))
			abort();

		last_sig.sighash_type = SIGHASH_ALL;
		if (!psbt_input_set_signature(last_tx->psbt, 0,
					      &remote_funding_pubkey, &last_sig))
			abort();
		psbt_input_add_pubkey(last_tx->psbt, 0,
		    &local_funding_pubkey, false /* is_taproot */);
		psbt_input_add_pubkey(last_tx->psbt, 0,
		    &remote_funding_pubkey, false /* is_taproot */);

		update_stmt = db_prepare_v2(db, SQL("UPDATE channels"
						    " SET last_tx = ?"
						    " WHERE id = ?;"));
		db_bind_psbt(update_stmt, last_tx->psbt);
		db_bind_int(update_stmt, cdb_id);
		db_exec_prepared_v2(update_stmt);
		tal_free(update_stmt);
	}

	tal_free(stmt);
}

/* We used to store scids as strings... */
void migrate_channels_scids_as_integers(struct lightningd *ld,
					struct db *db)
{
	struct db_stmt *stmt;
	char **scids = tal_arr(tmpctx, char *, 0);
	size_t changes;

	stmt = db_prepare_v2(db, SQL("SELECT short_channel_id FROM channels"));
	db_query_prepared(stmt);
	while (db_step(stmt)) {
		if (db_col_is_null(stmt, "short_channel_id"))
			continue;
		tal_arr_expand(&scids,
			       db_col_strdup(scids, stmt, "short_channel_id"));
	}
	tal_free(stmt);

	changes = 0;
	for (size_t i = 0; i < tal_count(scids); i++) {
		struct short_channel_id scid;
		if (!short_channel_id_from_str(scids[i], strlen(scids[i]), &scid))
			db_fatal(db, "Cannot convert invalid channels.short_channel_id '%s'",
				 scids[i]);

		stmt = db_prepare_v2(db, SQL("UPDATE channels"
					     " SET scid = ?"
					     " WHERE short_channel_id = ?"));
		db_bind_short_channel_id(stmt, scid);
		db_bind_text(stmt, scids[i]);
		db_exec_prepared_v2(stmt);

		/* This was reported to happen with an (old, closed) channel: that we'd have
		 * more than one change here!  That's weird, but just log about it. */
		if (db_count_changes(stmt) != 1)
			log_broken(ld->log,
				   "migrate_channels_scids_as_integers: converting channels.short_channel_id '%s' gave %zu changes != 1!",
				   scids[i], db_count_changes(stmt));
		changes += db_count_changes(stmt);
		tal_free(stmt);
	}

	if (changes != tal_count(scids))
		log_broken(ld->log, "migrate_channels_scids_as_integers: only converted %zu of %zu scids!",
			   changes, tal_count(scids));

	/* FIXME: We cannot use ->delete_columns to remove
	 * short_channel_id, as other tables reference the channels
	 * (and sqlite3 has them referencing a now-deleted table!).
	 * When we can assume sqlite3 version 3.35.5 (2021-04-19),
	 * we can simply use DROP COLUMN (yay!) */

	/* So null-out the unused column, at least! */
	stmt = db_prepare_v2(db, SQL("UPDATE channels"
				     " SET short_channel_id = NULL;"));
	db_exec_prepared_v2(take(stmt));
}

void migrate_payments_scids_as_integers(struct lightningd *ld,
					struct db *db)
{
	struct db_stmt *stmt;
	const char *colnames[] = {"failchannel"};

	stmt = db_prepare_v2(db, SQL("SELECT id, failchannel FROM payments"));
	db_query_prepared(stmt);
	while (db_step(stmt)) {
		struct db_stmt *update_stmt;
		struct short_channel_id scid;
		const char *str;

		if (db_col_is_null(stmt, "failchannel")) {
			db_col_ignore(stmt, "id");
			continue;
		}

		str = db_col_strdup(tmpctx, stmt, "failchannel");
		if (!short_channel_id_from_str(str, strlen(str), &scid))
			db_fatal(db, "Cannot convert invalid payments.failchannel '%s'",
				 str);
		update_stmt = db_prepare_v2(db, SQL("UPDATE payments SET"
						    " failscid = ?"
						    " WHERE id = ?"));
		db_bind_short_channel_id(update_stmt, scid);
		db_bind_u64(update_stmt, db_col_u64(stmt, "id"));
		db_exec_prepared_v2(update_stmt);
		tal_free(update_stmt);
	}
	tal_free(stmt);

	if (!db->config->delete_columns(db, "payments", colnames, ARRAY_SIZE(colnames)))
		db_fatal(db, "Could not delete payments.failchannel");
}

void fillin_missing_lease_satoshi(struct lightningd *ld,
				  struct db *db)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("UPDATE channel_funding_inflights"
				     " SET lease_satoshi = 0"
				     " WHERE lease_satoshi IS NULL;"));
	db_exec_prepared_v2(stmt);
	tal_free(stmt);
}

void migrate_fill_in_channel_type(struct lightningd *ld,
				  struct db *db)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT id, local_static_remotekey_start, option_anchor_outputs, channel_flags, alias_remote, minimum_depth FROM channels"));
	db_query_prepared(stmt);
	while (db_step(stmt)) {
		struct db_stmt *update_stmt;
		struct channel_type *type;
		u64 id = db_col_u64(stmt, "id");
		int channel_flags = db_col_int(stmt, "channel_flags");

		if (db_col_int(stmt, "option_anchor_outputs")) {
			db_col_ignore(stmt, "local_static_remotekey_start");
			type = channel_type_anchor_outputs_obsolete(tmpctx);
		} else if (db_col_u64(stmt, "local_static_remotekey_start") != 0x7FFFFFFFFFFFFFFFULL)
			type = channel_type_static_remotekey(tmpctx);
		else
			type = channel_type_none_obsolete(tmpctx);

		/* We didn't keep type in db, so assume all private
		 * channels which support aliases don't want us to fwd
		 * unless using alias, which is how we behaved
		 * before. */
		if (!db_col_is_null(stmt, "alias_remote")
		    && !(channel_flags & CHANNEL_FLAGS_ANNOUNCE_CHANNEL))
			channel_type_set_scid_alias(type);

		if (db_col_int(stmt, "minimum_depth") == 0)
			channel_type_set_zeroconf(type);

		update_stmt = db_prepare_v2(db, SQL("UPDATE channels SET"
						    " channel_type = ?"
						    " WHERE id = ?"));
		db_bind_channel_type(update_stmt, type);
		db_bind_u64(update_stmt, id);
		db_exec_prepared_v2(update_stmt);
		tal_free(update_stmt);
	}
	tal_free(stmt);
}

void migrate_initialize_invoice_wait_indexes(struct lightningd *ld,
					     struct db *db)
{
	struct db_stmt *stmt;
	bool res;

	/* "invoices.id" serves as the created_index.  It's never 0. */
	stmt = db_prepare_v2(db, SQL("SELECT MAX(id) FROM invoices;"));
	db_query_prepared(stmt);
	res = db_step(stmt);
	assert(res);

	if (!db_col_is_null(stmt, "MAX(id)"))
		db_set_intvar(db, "last_invoice_created_index",
			      db_col_u64(stmt, "MAX(id)"));
	tal_free(stmt);
}

void migrate_invoice_created_index_var(struct lightningd *ld, struct db *db)
{
	struct db_stmt *stmt;
	s64 badindex, realindex;

	/* Prior migration had a typo!  But we might have run since
	 * then and created an invoice, so we have to set the real one
	 * to the max of the two... */
	badindex = db_get_intvar(db, "last_invoice_created_index", -1);
	realindex = db_get_intvar(db, "last_invoices_created_index", -1);

	/* Bad index does not exist?  Fine */
	if (badindex < 0)
		return;

	/* Bad index exists, real index doesn't?  Rename */
	if (badindex >= 0 && realindex < 0) {
		stmt = db_prepare_v2(db, SQL("UPDATE vars"
					     " SET name = 'last_invoices_created_index'"
					     " WHERE name = 'last_invoice_created_index'"));
		db_exec_prepared_v2(stmt);
		tal_free(stmt);
		return;
	}

	/* Both exist.  Correct value is the higher one. */
	if (badindex > realindex)
		realindex = badindex;

	/* Update correct one, remove bad one. */
	db_set_intvar(db, "last_invoices_created_index", realindex);
	stmt = db_prepare_v2(db, SQL("DELETE FROM vars"
				     " WHERE name = 'last_invoice_created_index'"));
	db_exec_prepared_v2(stmt);
	tal_free(stmt);
}

/* We expect to have a few of these... */
static void migrate_initialize_wait_indexes(struct db *db,
					    enum wait_subsystem subsystem,
					    enum wait_index index,
					    const char *query,
					    const char *colname)
{
	struct db_stmt *stmt;
	bool res;

	stmt = db_prepare_v2(db, query);
	db_query_prepared(stmt);
	res = db_step(stmt);
	assert(res);

	if (!db_col_is_null(stmt, colname))
		db_set_intvar(db,
			      tal_fmt(tmpctx, "last_%s_%s_index",
				      wait_subsystem_name(subsystem),
				      wait_index_name(index)),
			      db_col_u64(stmt, colname));
	tal_free(stmt);
}

void migrate_initialize_payment_wait_indexes(struct lightningd *ld,
					     struct db *db)
{
	migrate_initialize_wait_indexes(db,
					WAIT_SUBSYSTEM_SENDPAY,
					WAIT_INDEX_CREATED,
					SQL("SELECT MAX(id) FROM payments;"),
					"MAX(id)");
}

void migrate_forwards_add_rowid(struct lightningd *ld,
				struct db *db)
{
	struct db_stmt *stmt;

	/* sqlite3 has implicit "rowid" column already */
	if (streq(db->config->name, "sqlite3"))
		return;

	stmt = db_prepare_v2(db, SQL("ALTER TABLE forwards ADD rowid BIGINT"));
	db_exec_prepared_v2(take(stmt));

	/* Yes, I got ChatGPT to write this for me! */
	stmt = db_prepare_v2(db, SQL("WITH numbered_rows AS ("
				     " SELECT in_channel_scid, in_htlc_id, row_number() OVER () AS rn"
				     " FROM forwards)"
				     " UPDATE forwards"
				     " SET rowid = numbered_rows.rn"
				     " FROM numbered_rows"
				     " WHERE forwards.in_channel_scid = numbered_rows.in_channel_scid"
				     " AND forwards.in_htlc_id = numbered_rows.in_htlc_id;"));
	db_exec_prepared_v2(take(stmt));

	stmt = db_prepare_v2(db, SQL("CREATE INDEX forwards_created_idx ON forwards (rowid)"));
	db_exec_prepared_v2(take(stmt));
}

void migrate_initialize_forwards_wait_indexes(struct lightningd *ld,
					      struct db *db)
{
	migrate_initialize_wait_indexes(db,
					WAIT_SUBSYSTEM_FORWARD,
					WAIT_INDEX_CREATED,
					SQL("SELECT MAX(rowid) FROM forwards;"),
					"MAX(rowid)");
}

void migrate_initialize_channel_htlcs_wait_indexes_and_fixup_forwards(struct lightningd *ld,
								      struct db *db)
{
	/* A previous badly-written migration (now NULL-ed out) set
	 * the forwards, not htlc index!  Set the htlcs migration, and fixup forwards. */
	migrate_initialize_wait_indexes(db,
					WAIT_SUBSYSTEM_HTLCS,
					WAIT_INDEX_CREATED,
					SQL("SELECT MAX(id) FROM channel_htlcs;"),
					"MAX(id)");
	migrate_initialize_forwards_wait_indexes(ld, db);
}

static void complain_unfixed(struct lightningd *ld,
			     enum channel_state state,
			     u64 id,
			     const u8 *bytes,
			     const char *why)
{
	/* This is OK on closed channels */
	if (state != CLOSED) {
		log_broken(ld->log,
			   "%s channel id %"PRIu64" PSBT hex '%s'",
			   why, id, tal_hex(tmpctx, bytes));
	} else {
		log_debug(ld->log,
			  "%s on closed channel id %"PRIu64" PSBT hex '%s'",
			  why, id, tal_hex(tmpctx, bytes));
	}
}

void migrate_invalid_last_tx_psbts(struct lightningd *ld, struct db *db)
{
	struct db_stmt *stmt;

	/* We try all of them, but note that last_tx used to be a tx,
	 * and migrate_last_tx_to_psbt didn't convert channels which had
	 * already been closed, so we expect some failures. */
	stmt = db_prepare_v2(db, SQL("SELECT "
				     "  id"
				     ", state"
				     ", last_tx"
				     " FROM channels"));

	db_query_prepared(stmt);
	while (db_step(stmt)) {
		struct db_stmt *update_stmt;
		const u8 *bytes, *fixed;
		enum channel_state state;
		u64 id;
		struct wally_psbt *psbt;

		state = db_col_int(stmt, "state");
		id = db_col_u64(stmt, "id");

		/* Parses fine? */
		if (db_col_psbt(tmpctx, stmt, "last_tx"))
			continue;

		/* Can we fix it? */
		bytes = db_col_arr(tmpctx, stmt, "last_tx", u8);
		fixed = psbt_fixup(tmpctx, bytes);
		if (!fixed) {
			complain_unfixed(ld, state, id, bytes, "Could not fix");
			continue;
		}
		psbt = psbt_from_bytes(tmpctx, fixed, tal_bytelen(fixed));
		if (!psbt) {
			complain_unfixed(ld, state, id, fixed, "Fix made invalid psbt");
			continue;
		}

		log_broken(ld->log, "Forced database repair of psbt %s -> %s",
			   tal_hex(tmpctx, bytes), tal_hex(tmpctx, fixed));
		update_stmt = db_prepare_v2(db, SQL("UPDATE channels"
						    " SET last_tx = ?"
						    " WHERE id = ?;"));
		db_bind_psbt(update_stmt, psbt);
		db_bind_u64(update_stmt, id);
		db_exec_prepared_v2(update_stmt);
		tal_free(update_stmt);
	}
	tal_free(stmt);
}
/**
 * We store the bolt11 string in several places with the `lightning:` prefix, so
 * we update one by one by lowering and normalize the string in a canonical one.
 *
 * See also `to_canonical_invstr` in `common/bolt11.c` the definition of
 * canonical invoice.
 */
void migrate_normalize_invstr(struct lightningd *ld, struct db *db)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("SELECT bolt11, id"
				     " FROM invoices"
				     " WHERE bolt11 IS NOT NULL;"));
	db_query_prepared(stmt);
	while (db_step(stmt)) {
		u64 id;
		const char *invstr;
		struct db_stmt *update_stmt;

		id = db_col_u64(stmt, "id");
		invstr = db_col_strdup(tmpctx, stmt, "bolt11");
		invstr = to_canonical_invstr(tmpctx, invstr);

		update_stmt = db_prepare_v2(db, SQL("UPDATE invoices"
						    " SET bolt11 = ?"
						    " WHERE id = ?;"));
		db_bind_text(update_stmt, invstr);
		db_bind_u64(update_stmt, id);
		db_exec_prepared_v2(update_stmt);

		tal_free(update_stmt);
	}
	tal_free(stmt);

	stmt = db_prepare_v2(db, SQL("SELECT bolt11, id"
				     " FROM payments"
				     " WHERE bolt11 IS NOT NULL;"));
	db_query_prepared(stmt);
	while (db_step(stmt)) {
		u64 id;
		const char *invstr;
		struct db_stmt *update_stmt;

		id = db_col_u64(stmt, "id");
		invstr = db_col_strdup(tmpctx, stmt, "bolt11");
		invstr = to_canonical_invstr(tmpctx, invstr);

		update_stmt = db_prepare_v2(db, SQL("UPDATE payments"
						    " SET bolt11 = ?"
						    " WHERE id = ?;"));
		db_bind_text(update_stmt, invstr);
		db_bind_u64(update_stmt, id);
		db_exec_prepared_v2(update_stmt);

		tal_free(update_stmt);
	}
	tal_free(stmt);
}

/* We required local aliases to be set on established channels,
 * but we forgot about already-existing ones in the db! */
void migrate_initialize_alias_local(struct lightningd *ld,
				    struct db *db)
{
	struct db_stmt *stmt;
	u64 *ids = tal_arr(tmpctx, u64, 0);

	stmt = db_prepare_v2(db, SQL("SELECT id FROM channels"
				     " WHERE alias_local IS NULL;"));
	db_query_prepared(stmt);
	while (db_step(stmt))
		tal_arr_expand(&ids, db_col_u64(stmt, "id"));
	tal_free(stmt);

	for (size_t i = 0; i < tal_count(ids); i++) {
		stmt = db_prepare_v2(db, SQL("UPDATE channels"
					     " SET alias_local = ?"
					     " WHERE id = ?;"));
		/* We don't even check for clashes! */
		db_bind_short_channel_id(stmt, random_scid());
		db_bind_u64(stmt, ids[i]);
		db_exec_prepared_v2(stmt);
		tal_free(stmt);
	}
}

/* Insert address type as `ADDR_ALL` for issued addresses */
void insert_addrtype_to_addresses(struct lightningd *ld,
				  struct db *db)
{
	struct db_stmt *stmt;
	u64 bip32_max_index = db_get_intvar(db, "bip32_max_index", 0);
	for (u64 newidx = 1; newidx <= bip32_max_index; newidx++) {
		stmt = db_prepare_v2(db,
					SQL("INSERT INTO addresses ("
					"  keyidx"
					", addrtype"
					") VALUES (?, ?);"));
		db_bind_u64(stmt, newidx);
		db_bind_int(stmt, wallet_addrtype_in_db(ADDR_ALL));
		db_exec_prepared_v2(stmt);
		tal_free(stmt);
	}
}

/* If we said a channel final key was taproot-only, but actually the peer
 * didn't support `option_shutdown_anysegwit`, we used the p2wpkh instead.  We
 * don't have access to the peers' features in the db, so instead convert all
 * the keys to ADDR_ALL.  Users with closed channels may still need to
 * rescan! */
void migrate_convert_old_channel_keyidx(struct lightningd *ld,
					struct db *db)
{
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("UPDATE addresses"
				     " SET addrtype = ?"
				     " WHERE keyidx IN (SELECT shutdown_keyidx_local FROM channels"
				     "                  WHERE state != ?"
				     "                  AND state != ?"
				     "                  AND state != ?)"));
	db_bind_int(stmt, wallet_addrtype_in_db(ADDR_ALL));
	/* If we might have already seen onchain funds, we need to rescan */
	db_bind_int(stmt, channel_state_in_db(FUNDING_SPEND_SEEN));
	db_bind_int(stmt, channel_state_in_db(ONCHAIN));
	db_bind_int(stmt, channel_state_in_db(CLOSED));
	db_exec_prepared_v2(take(stmt));
}

void migrate_fail_pending_payments_without_htlcs(struct lightningd *ld,
						 struct db *db)
{
	/* If channeld died or was offline at the right moment, we
	 * could register a payment as pending, but then not create an
	 * HTLC.  Clean those up. */
	struct db_stmt *stmt;

	stmt = db_prepare_v2(db, SQL("UPDATE payments AS p"
				     " SET status = ?"
				     " WHERE p.status = ?"
				     "   AND NOT EXISTS ("
				     "     SELECT 1"
				     "     FROM channel_htlcs AS h"
				     "     WHERE h.payment_hash = p.payment_hash"
				     "       AND h.groupid = p.groupid"
				     "       AND h.partid  = p.partid);"));
	db_bind_int(stmt, payment_status_in_db(PAYMENT_FAILED));
	db_bind_int(stmt, payment_status_in_db(PAYMENT_PENDING));
	db_exec_prepared_v2(take(stmt));
}

void migrate_fix_payments_faildetail_type(struct lightningd *ld UNUSED,
					  struct db *db)
{
	struct db_stmt *stmt;

	/* sqlite3 may have BLOB in TEXT column due to type affinity */
	if (!streq(db->config->name, "sqlite3"))
		return;

	stmt = db_prepare_v2(db, SQL("SELECT id, faildetail "
				     "FROM payments "
				     "WHERE typeof(faildetail) = 'blob'"));
	db_query_prepared(stmt);

	while (db_step(stmt)) {
		u64 id = db_col_u64(stmt, "id");
		const u8 *blob = db_col_blob(stmt, "faildetail");
		size_t len = db_col_bytes(stmt, "faildetail");
		struct db_stmt *upd;

		if (!utf8_check(blob, len)) {
			upd = db_prepare_v2(db,
				SQL("UPDATE payments "
				    "SET faildetail = NULL "
				    "WHERE id = ?"));
			db_bind_u64(upd, id);
			db_exec_prepared_v2(take(upd));
			continue;
		}

		char *text = tal_strndup(tmpctx, (char *)blob, len);
		upd = db_prepare_v2(db,
			SQL("UPDATE payments "
			    "SET faildetail = ? "
			    "WHERE id = ?"));
		db_bind_text(upd, text);
		db_bind_u64(upd, id);
		db_exec_prepared_v2(take(upd));
	}

	tal_free(stmt);
}

