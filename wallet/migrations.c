#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/channel_id.h>
#include <common/htlc_state.h>
#include <db/bindings.h>
#include <db/common.h>
#include <db/exec.h>
#include <db/utils.h>
#include <wallet/account_migration.h>
#include <wallet/db.h>
#include <wallet/migrations.h>

static const char *revert_too_early(const tal_t *ctx, struct db *db)
{
	return tal_strdup(ctx, "Downgrade to before v25.09 not supported");
}

/* Don't allow downgrade if they've *used* the withheld column. */
static const char *revert_withheld_column(const tal_t *ctx, struct db *db)
{
	struct db_stmt *stmt;
	struct channel_id *cid;
	struct short_channel_id *scid;

	stmt = db_prepare_v2(db, SQL("SELECT full_channel_id, scid FROM channels WHERE withheld != 0"));
	db_query_prepared(stmt);
	if (db_step(stmt)) {
		cid = tal(tmpctx, struct channel_id);
		db_col_channel_id(stmt, "full_channel_id", cid);
		if (db_col_is_null(stmt, "scid"))
			scid = NULL;
		else {
			scid = tal(tmpctx, struct short_channel_id);
			*scid = db_col_short_channel_id(stmt, "scid");
		}
	} else {
		cid = NULL;
		scid = NULL;
	}
	tal_free(stmt);

	if (cid) {
		return tal_fmt(tmpctx, "Channel %s (%s) used v25.12's withheld flag",
			       fmt_channel_id(tmpctx, cid),
			       scid ? fmt_short_channel_id(tmpctx, *scid) : "no short channel id");
	}

	/* For sqlite3 needs "2021-03-12 (3.35.0)" or above */
	stmt = db_prepare_v2(db, SQL("ALTER TABLE channels DROP COLUMN withheld"));
	db_exec_prepared_v2(take(stmt));
	return NULL;
}

/* Do not reorder or remove elements from this array, it is used to
 * migrate existing databases from a previous state, based on the
 * string indices */
static const struct db_migration dbmigrations[] = {
    {SQL("CREATE TABLE version (version INTEGER)"), NULL},
    {SQL("INSERT INTO version VALUES (1)"), NULL},
    {SQL("CREATE TABLE outputs ("
	 "  prev_out_tx BLOB"
	 ", prev_out_index INTEGER"
	 ", value BIGINT"
	 ", type INTEGER"
	 ", status INTEGER"
	 ", keyindex INTEGER"
	 ", PRIMARY KEY (prev_out_tx, prev_out_index));"),
     NULL},
    {SQL("CREATE TABLE vars ("
	 "  name VARCHAR(32)"
	 ", val VARCHAR(255)"
	 ", PRIMARY KEY (name)"
	 ");"),
     NULL},
    {SQL("CREATE TABLE shachains ("
	 "  id BIGSERIAL"
	 ", min_index BIGINT"
	 ", num_valid BIGINT"
	 ", PRIMARY KEY (id)"
	 ");"),
     NULL},
    {SQL("CREATE TABLE shachain_known ("
	 "  shachain_id BIGINT REFERENCES shachains(id) ON DELETE CASCADE"
	 ", pos INTEGER"
	 ", idx BIGINT"
	 ", hash BLOB"
	 ", PRIMARY KEY (shachain_id, pos)"
	 ");"),
     NULL},
    {SQL("CREATE TABLE peers ("
	 "  id BIGSERIAL"
	 ", node_id BLOB UNIQUE" /* pubkey */
	 ", address TEXT"
	 ", PRIMARY KEY (id)"
	 ");"),
     NULL},
    {SQL("CREATE TABLE channels ("
	 "  id BIGSERIAL," /* chan->id */
	 /* FIXME: We deliberately never delete a peer with channels, so this constraint is
	  * unnecessary! */
	 "  peer_id BIGINT REFERENCES peers(id) ON DELETE CASCADE,"
	 "  short_channel_id TEXT,"
	 "  channel_config_local BIGINT,"
	 "  channel_config_remote BIGINT,"
	 "  state INTEGER,"
	 "  funder INTEGER,"
	 "  channel_flags INTEGER,"
	 "  minimum_depth INTEGER,"
	 "  next_index_local BIGINT,"
	 "  next_index_remote BIGINT,"
	 "  next_htlc_id BIGINT,"
	 "  funding_tx_id BLOB,"
	 "  funding_tx_outnum INTEGER,"
	 "  funding_satoshi BIGINT,"
	 "  funding_locked_remote INTEGER,"
	 "  push_msatoshi BIGINT,"
	 "  msatoshi_local BIGINT," /* our_msatoshi */
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
	 "  shachain_remote_id BIGINT,"
	 "  shutdown_scriptpubkey_remote BLOB,"
	 "  shutdown_keyidx_local BIGINT,"
	 "  last_sent_commit_state BIGINT,"
	 "  last_sent_commit_id INTEGER,"
	 "  last_tx BLOB,"
	 "  last_sig BLOB,"
	 "  closing_fee_received INTEGER,"
	 "  closing_sig_received BLOB,"
	 "  PRIMARY KEY (id)"
	 ");"),
     NULL},
    {SQL("CREATE TABLE channel_configs ("
	 "  id BIGSERIAL,"
	 "  dust_limit_satoshis BIGINT,"
	 "  max_htlc_value_in_flight_msat BIGINT,"
	 "  channel_reserve_satoshis BIGINT,"
	 "  htlc_minimum_msat BIGINT,"
	 "  to_self_delay INTEGER,"
	 "  max_accepted_htlcs INTEGER,"
	 "  PRIMARY KEY (id)"
	 ");"),
     NULL},
    {SQL("CREATE TABLE channel_htlcs ("
	 "  id BIGSERIAL,"
	 "  channel_id BIGINT REFERENCES channels(id) ON DELETE CASCADE,"
	 "  channel_htlc_id BIGINT,"
	 "  direction INTEGER,"
	 "  origin_htlc BIGINT,"
	 "  msatoshi BIGINT,"
	 "  cltv_expiry INTEGER,"
	 "  payment_hash BLOB,"
	 "  payment_key BLOB,"
	 "  routing_onion BLOB,"
	 "  failuremsg BLOB," /* Note: This is in fact the failure onionreply,
			       * but renaming columns is hard! */
	 "  malformed_onion INTEGER,"
	 "  hstate INTEGER,"
	 "  shared_secret BLOB,"
	 "  PRIMARY KEY (id),"
	 "  UNIQUE (channel_id, channel_htlc_id, direction)"
	 ");"),
     NULL},
    {SQL("CREATE TABLE invoices ("
	 "  id BIGSERIAL,"
	 "  state INTEGER,"
	 "  msatoshi BIGINT,"
	 "  payment_hash BLOB,"
	 "  payment_key BLOB,"
	 "  label TEXT,"
	 "  PRIMARY KEY (id),"
	 "  UNIQUE (label),"
	 "  UNIQUE (payment_hash)"
	 ");"),
     NULL},
    {SQL("CREATE TABLE payments ("
	 "  id BIGSERIAL,"
	 "  timestamp INTEGER,"
	 "  status INTEGER,"
	 "  payment_hash BLOB,"
	 "  direction INTEGER,"
	 "  destination BLOB,"
	 "  msatoshi BIGINT,"
	 "  PRIMARY KEY (id),"
	 "  UNIQUE (payment_hash)"
	 ");"),
     NULL},
    /* Add expiry field to invoices (effectively infinite). */
    {SQL("ALTER TABLE invoices ADD expiry_time BIGINT;"), NULL},
    {SQL("UPDATE invoices SET expiry_time=9223372036854775807;"), NULL},
    /* Add pay_index field to paid invoices (initially, same order as id). */
    {SQL("ALTER TABLE invoices ADD pay_index BIGINT;"), NULL},
    {SQL("CREATE UNIQUE INDEX invoices_pay_index ON invoices(pay_index);"),
     NULL},
    {SQL("UPDATE invoices SET pay_index=id WHERE state=1;"),
     NULL}, /* only paid invoice */
    /* Create next_pay_index variable (highest pay_index). */
    {SQL("INSERT INTO vars(name, val)"
	 "  VALUES('next_pay_index', "
	 "    COALESCE((SELECT MAX(pay_index) FROM invoices WHERE state=1), 0) "
	 "+ 1"
	 "  );"),
     NULL},
    /* Create first_block field; initialize from channel id if any.
     * This fails for channels still awaiting lockin, but that only applies to
     * pre-release software, so it's forgivable. */
    {SQL("ALTER TABLE channels ADD first_blocknum BIGINT;"), NULL},
    {SQL("UPDATE channels SET first_blocknum=1 WHERE short_channel_id IS NOT NULL;"),
     NULL},
    {SQL("ALTER TABLE outputs ADD COLUMN channel_id BIGINT;"), NULL},
    {SQL("ALTER TABLE outputs ADD COLUMN peer_id BLOB;"), NULL},
    {SQL("ALTER TABLE outputs ADD COLUMN commitment_point BLOB;"), NULL},
    {SQL("ALTER TABLE invoices ADD COLUMN msatoshi_received BIGINT;"), NULL},
    /* Normally impossible, so at least we'll know if databases are ancient. */
    {SQL("UPDATE invoices SET msatoshi_received=0 WHERE state=1;"), NULL},
    {SQL("ALTER TABLE channels ADD COLUMN last_was_revoke INTEGER;"), NULL},
    /* We no longer record incoming payments: invoices cover that.
     * Without ALTER_TABLE DROP COLUMN support we need to do this by
     * rename & copy, which works because there are no triggers etc. */
    {SQL("ALTER TABLE payments RENAME TO temp_payments;"), NULL},
    {SQL("CREATE TABLE payments ("
	 "  id BIGSERIAL,"
	 "  timestamp INTEGER,"
	 "  status INTEGER,"
	 "  payment_hash BLOB,"
	 "  destination BLOB,"
	 "  msatoshi BIGINT,"
	 "  PRIMARY KEY (id),"
	 "  UNIQUE (payment_hash)"
	 ");"),
     NULL},
    {SQL("INSERT INTO payments SELECT id, timestamp, status, payment_hash, "
	 "destination, msatoshi FROM temp_payments WHERE direction=1;"),
     NULL},
    {SQL("DROP TABLE temp_payments;"), NULL},
    /* We need to keep the preimage in case they ask to pay again. */
    {SQL("ALTER TABLE payments ADD COLUMN payment_preimage BLOB;"), NULL},
    /* We need to keep the shared secrets to decode error returns. */
    {SQL("ALTER TABLE payments ADD COLUMN path_secrets BLOB;"), NULL},
    /* Create time-of-payment of invoice, default already-paid
     * invoices to current time. */
    {SQL("ALTER TABLE invoices ADD paid_timestamp BIGINT;"), NULL},
    {SQL("UPDATE invoices"
	 "   SET paid_timestamp = CURRENT_TIMESTAMP()"
	 " WHERE state = 1;"),
     NULL},
    /* We need to keep the route node pubkeys and short channel ids to
     * correctly mark routing failures. We separate short channel ids
     * because we cannot safely save them as blobs due to byteorder
     * concerns. */
    {SQL("ALTER TABLE payments ADD COLUMN route_nodes BLOB;"), NULL},
    {SQL("ALTER TABLE payments ADD COLUMN route_channels BLOB;"), NULL},
    {SQL("CREATE TABLE htlc_sigs (channelid INTEGER REFERENCES channels(id) ON "
	 "DELETE CASCADE, signature BLOB);"),
     NULL},
    {SQL("CREATE INDEX channel_idx ON htlc_sigs (channelid)"), NULL},
    /* Get rid of OPENINGD entries; we don't put them in db any more */
    {SQL("DELETE FROM channels WHERE state=1"), NULL},
    /* Keep track of db upgrades, for debugging */
    {SQL("CREATE TABLE db_upgrades (upgrade_from INTEGER, lightning_version "
	 "TEXT);"),
     NULL},
    /* We used not to clean up peers when their channels were gone. */
    {SQL("DELETE FROM peers WHERE id NOT IN (SELECT peer_id FROM channels);"),
     NULL},
    /* The ONCHAIND_CHEATED/THEIR_UNILATERAL/OUR_UNILATERAL/MUTUAL are now one
     */
    {SQL("UPDATE channels SET STATE = 8 WHERE state > 8;"), NULL},
    /* Add bolt11 to invoices table*/
    {SQL("ALTER TABLE invoices ADD bolt11 TEXT;"), NULL},
    /* What do we think the head of the blockchain looks like? Used
     * primarily to track confirmations across restarts and making
     * sure we handle reorgs correctly. */
    {SQL("CREATE TABLE blocks (height INT, hash BLOB, prev_hash BLOB, "
	 "UNIQUE(height));"),
     NULL},
    /* ON DELETE CASCADE would have been nice for confirmation_height,
     * so that we automatically delete outputs that fall off the
     * blockchain and then we rediscover them if they are included
     * again. However, we have the their_unilateral/to_us which we
     * can't simply recognize from the chain without additional
     * hints. So we just mark them as unconfirmed should the block
     * die. */
    {SQL("ALTER TABLE outputs ADD COLUMN confirmation_height INTEGER "
	 "REFERENCES blocks(height) ON DELETE SET NULL;"),
     NULL},
    {SQL("ALTER TABLE outputs ADD COLUMN spend_height INTEGER REFERENCES "
	 "blocks(height) ON DELETE SET NULL;"),
     NULL},
    /* Create a covering index that covers both fields */
    {SQL("CREATE INDEX output_height_idx ON outputs (confirmation_height, "
	 "spend_height);"),
     NULL},
    {SQL("CREATE TABLE utxoset ("
	 " txid BLOB,"
	 " outnum INT,"
	 " blockheight INT REFERENCES blocks(height) ON DELETE CASCADE,"
	 " spendheight INT REFERENCES blocks(height) ON DELETE SET NULL,"
	 " txindex INT,"
	 " scriptpubkey BLOB,"
	 " satoshis BIGINT,"
	 " PRIMARY KEY(txid, outnum));"),
     NULL},
    {SQL("CREATE INDEX short_channel_id ON utxoset (blockheight, txindex, "
	 "outnum)"),
     NULL},
    /* Necessary index for long rollbacks of the blockchain, otherwise we're
     * doing table scans for every block removed. */
    {SQL("CREATE INDEX utxoset_spend ON utxoset (spendheight)"), NULL},
    /* Assign key 0 to unassigned shutdown_keyidx_local. */
    {SQL("UPDATE channels SET shutdown_keyidx_local=0 WHERE "
	 "shutdown_keyidx_local = -1;"),
     NULL},
    /* FIXME: We should rename shutdown_keyidx_local to final_key_index */
    /* -- Payment routing failure information -- */
    /* BLOB if failure was due to unparseable onion, NULL otherwise */
    {SQL("ALTER TABLE payments ADD failonionreply BLOB;"), NULL},
    /* 0 if we could theoretically retry, 1 if PERM fail at payee */
    {SQL("ALTER TABLE payments ADD faildestperm INTEGER;"), NULL},
    /* Contents of routing_failure (only if not unparseable onion) */
    {SQL("ALTER TABLE payments ADD failindex INTEGER;"),
     NULL}, /* erring_index */
    {SQL("ALTER TABLE payments ADD failcode INTEGER;"), NULL}, /* failcode */
    {SQL("ALTER TABLE payments ADD failnode BLOB;"), NULL},    /* erring_node */
    {SQL("ALTER TABLE payments ADD failchannel TEXT;"),
     NULL}, /* erring_channel */
    {SQL("ALTER TABLE payments ADD failupdate BLOB;"),
     NULL}, /* channel_update - can be NULL*/
    /* -- Payment routing failure information ends -- */
    /* Delete route data for already succeeded or failed payments */
    {SQL("UPDATE payments"
	 "   SET path_secrets = NULL"
	 "     , route_nodes = NULL"
	 "     , route_channels = NULL"
	 " WHERE status <> 0;"),
     NULL}, /* PAYMENT_PENDING */
    /* -- Routing statistics -- */
    {SQL("ALTER TABLE channels ADD in_payments_offered INTEGER DEFAULT 0;"), NULL},
    {SQL("ALTER TABLE channels ADD in_payments_fulfilled INTEGER DEFAULT 0;"), NULL},
    {SQL("ALTER TABLE channels ADD in_msatoshi_offered BIGINT DEFAULT 0;"), NULL},
    {SQL("ALTER TABLE channels ADD in_msatoshi_fulfilled BIGINT DEFAULT 0;"), NULL},
    {SQL("ALTER TABLE channels ADD out_payments_offered INTEGER DEFAULT 0;"), NULL},
    {SQL("ALTER TABLE channels ADD out_payments_fulfilled INTEGER DEFAULT 0;"), NULL},
    {SQL("ALTER TABLE channels ADD out_msatoshi_offered BIGINT DEFAULT 0;"), NULL},
    {SQL("ALTER TABLE channels ADD out_msatoshi_fulfilled BIGINT DEFAULT 0;"), NULL},
    {SQL("UPDATE channels"
	 "   SET  in_payments_offered = 0,  in_payments_fulfilled = 0"
	 "     ,  in_msatoshi_offered = 0,  in_msatoshi_fulfilled = 0"
	 "     , out_payments_offered = 0, out_payments_fulfilled = 0"
	 "     , out_msatoshi_offered = 0, out_msatoshi_fulfilled = 0"
	 "     ;"),
     NULL},
    /* -- Routing statistics ends --*/
    /* Record the msatoshi actually sent in a payment. */
    {SQL("ALTER TABLE payments ADD msatoshi_sent BIGINT;"), NULL},
    {SQL("UPDATE payments SET msatoshi_sent = msatoshi;"), NULL},
    /* Delete dangling utxoset entries due to Issue #1280  */
    {SQL("DELETE FROM utxoset WHERE blockheight IN ("
	 "  SELECT DISTINCT(blockheight)"
	 "  FROM utxoset LEFT OUTER JOIN blocks on (blockheight = "
	 "blocks.height) "
	 "  WHERE blocks.hash IS NULL"
	 ");"),
     NULL},
    /* Record feerate range, to optimize onchaind grinding actual fees. */
    {SQL("ALTER TABLE channels ADD min_possible_feerate INTEGER;"), NULL},
    {SQL("ALTER TABLE channels ADD max_possible_feerate INTEGER;"), NULL},
    /* https://bitcoinfees.github.io/#1d says Dec 17 peak was ~1M sat/kb
     * which is 250,000 sat/Sipa */
    {SQL("UPDATE channels SET min_possible_feerate=0, "
	 "max_possible_feerate=250000;"),
     NULL},
    /* -- Min and max msatoshi_to_us -- */
    {SQL("ALTER TABLE channels ADD msatoshi_to_us_min BIGINT;"), NULL},
    {SQL("ALTER TABLE channels ADD msatoshi_to_us_max BIGINT;"), NULL},
    {SQL("UPDATE channels"
	 "   SET msatoshi_to_us_min = msatoshi_local"
	 "     , msatoshi_to_us_max = msatoshi_local"
	 "     ;"),
     NULL},
    /* -- Min and max msatoshi_to_us ends -- */
    /* Transactions we are interested in. Either we sent them ourselves or we
     * are watching them. We don't cascade block height deletes so we don't
     * forget any of them by accident.*/
    {SQL("CREATE TABLE transactions ("
	 "  id BLOB"
	 ", blockheight INTEGER REFERENCES blocks(height) ON DELETE SET NULL"
	 ", txindex INTEGER"
	 ", rawtx BLOB"
	 ", PRIMARY KEY (id)"
	 ");"),
     NULL},
    /* -- Detailed payment failure -- */
    {SQL("ALTER TABLE payments ADD faildetail TEXT;"), NULL},
    {SQL("UPDATE payments"
	 "   SET faildetail = 'unspecified payment failure reason'"
	 " WHERE status = 2;"),
     NULL}, /* PAYMENT_FAILED */
    /* -- Detailed payment faiure ends -- */
    {SQL("CREATE TABLE channeltxs ("
	 /* The id serves as insertion order and short ID */
	 "  id BIGSERIAL"
	 ", channel_id BIGINT REFERENCES channels(id) ON DELETE CASCADE"
	 ", type INTEGER"
	 ", transaction_id BLOB REFERENCES transactions(id) ON DELETE CASCADE"
	 /* The input_num is only used by the txo_watch, 0 if txwatch */
	 ", input_num INTEGER"
	 /* The height at which we sent the depth notice */
	 ", blockheight INTEGER REFERENCES blocks(height) ON DELETE CASCADE"
	 ", PRIMARY KEY(id)"
	 ");"),
     NULL},
    /* -- Set the correct rescan height for PR #1398 -- */
    /* Delete blocks that are higher than our initial scan point, this is a
     * no-op if we don't have a channel. */
    {SQL("DELETE FROM blocks WHERE height > (SELECT MIN(first_blocknum) FROM "
	 "channels);"),
     NULL},
    /* Now make sure we have the lower bound block with the first_blocknum
     * height. This may introduce a block with NULL height if we didn't have any
     * blocks, remove that in the next. */
    {SQL("INSERT INTO blocks (height) VALUES ((SELECT "
	 "MIN(first_blocknum) FROM channels)) "
	 "ON CONFLICT(height) DO NOTHING;"),
     NULL},
    {SQL("DELETE FROM blocks WHERE height IS NULL;"), NULL},
    /* -- End of  PR #1398 -- */
    {SQL("ALTER TABLE invoices ADD description TEXT;"), NULL},
    /* FIXME: payments table 'description' is really a 'label' */
    {SQL("ALTER TABLE payments ADD description TEXT;"), NULL},
    /* future_per_commitment_point if other side proves we're out of date -- */
    {SQL("ALTER TABLE channels ADD future_per_commitment_point BLOB;"), NULL},
    /* last_sent_commit array fix */
    {SQL("ALTER TABLE channels ADD last_sent_commit BLOB;"), NULL},
    /* Stats table to track forwarded HTLCs. The values in the HTLCs
     * and their states are replicated here and the entries are not
     * deleted when the HTLC entries or the channel entries are
     * deleted to avoid unexpected drops in statistics. */
    {SQL("CREATE TABLE forwarded_payments ("
	 "  in_htlc_id BIGINT REFERENCES channel_htlcs(id) ON DELETE SET NULL"
	 ", out_htlc_id BIGINT REFERENCES channel_htlcs(id) ON DELETE SET NULL"
	 ", in_channel_scid BIGINT"
	 ", out_channel_scid BIGINT"
	 ", in_msatoshi BIGINT"
	 ", out_msatoshi BIGINT"
	 ", state INTEGER"
	 ", UNIQUE(in_htlc_id, out_htlc_id)"
	 ");"),
     NULL},
    /* Add a direction for failed payments. */
    {SQL("ALTER TABLE payments ADD faildirection INTEGER;"),
     NULL}, /* erring_direction */
    /* Fix dangling peers with no channels. */
    {SQL("DELETE FROM peers WHERE id NOT IN (SELECT peer_id FROM channels);"),
     NULL},
    {SQL("ALTER TABLE outputs ADD scriptpubkey BLOB;"), NULL},
    /* Keep bolt11 string for payments. */
    {SQL("ALTER TABLE payments ADD bolt11 TEXT;"), NULL},
    /* PR #2342 feerate per channel */
    {SQL("ALTER TABLE channels ADD feerate_base INTEGER;"), NULL},
    {SQL("ALTER TABLE channels ADD feerate_ppm INTEGER;"), NULL},
    {NULL, migrate_pr2342_feerate_per_channel},
    {SQL("ALTER TABLE channel_htlcs ADD received_time BIGINT"), NULL},
    {SQL("ALTER TABLE forwarded_payments ADD received_time BIGINT"), NULL},
    {SQL("ALTER TABLE forwarded_payments ADD resolved_time BIGINT"), NULL},
    {SQL("ALTER TABLE channels ADD remote_upfront_shutdown_script BLOB;"),
     NULL},
    /* PR #2524: Add failcode into forward_payment */
    {SQL("ALTER TABLE forwarded_payments ADD failcode INTEGER;"), NULL},
    /* remote signatures for channel announcement */
    {SQL("ALTER TABLE channels ADD remote_ann_node_sig BLOB;"), NULL},
    {SQL("ALTER TABLE channels ADD remote_ann_bitcoin_sig BLOB;"), NULL},
    /* FIXME: We now use the transaction_annotations table to type each
     * input and output instead of type and channel_id! */
    /* Additional information for transaction tracking and listing */
    {SQL("ALTER TABLE transactions ADD type BIGINT;"), NULL},
    /* Not a foreign key on purpose since we still delete channels from
     * the DB which would remove this. It is mainly used to group payments
     * in the list view anyway, e.g., show all close and htlc transactions
     * as a single bundle. */
    {SQL("ALTER TABLE transactions ADD channel_id BIGINT;"), NULL},
    /* Convert pre-Adelaide short_channel_ids */
    {SQL("UPDATE channels"
	 " SET short_channel_id = REPLACE(short_channel_id, ':', 'x')"
	 " WHERE short_channel_id IS NOT NULL;"), NULL },
    {SQL("UPDATE payments SET failchannel = REPLACE(failchannel, ':', 'x')"
	 " WHERE failchannel IS NOT NULL;"), NULL },
    /* option_static_remotekey is nailed at creation time. */
    {SQL("ALTER TABLE channels ADD COLUMN option_static_remotekey INTEGER"
	 " DEFAULT 0;"), NULL },
    {SQL("ALTER TABLE vars ADD COLUMN intval INTEGER"), NULL},
    {SQL("ALTER TABLE vars ADD COLUMN blobval BLOB"), NULL},
    {SQL("UPDATE vars SET intval = CAST(val AS INTEGER) WHERE name IN ('bip32_max_index', 'last_processed_block', 'next_pay_index')"), NULL},
    {SQL("UPDATE vars SET blobval = CAST(val AS BLOB) WHERE name = 'genesis_hash'"), NULL},
    {SQL("CREATE TABLE transaction_annotations ("
	 /* Not making this a reference since we usually filter the TX by
	  * walking its inputs and outputs, and only afterwards storing it in
	  * the DB. Having a reference here would point into the void until we
	  * add the matching TX. */
	 "  txid BLOB"
	 ", idx INTEGER" /* 0 when location is the tx, the index of the output or input otherwise */
	 ", location INTEGER" /* The transaction itself, the output at idx, or the input at idx */
	 ", type INTEGER"
	 ", channel BIGINT REFERENCES channels(id)"
	 ", UNIQUE(txid, idx)"
	 ");"), NULL},
    {SQL("ALTER TABLE channels ADD shutdown_scriptpubkey_local BLOB;"),
	 NULL},
    /* See https://github.com/ElementsProject/lightning/issues/3189 */
    {SQL("UPDATE forwarded_payments SET received_time=0 WHERE received_time IS NULL;"),
	 NULL},
    {SQL("ALTER TABLE invoices ADD COLUMN features BLOB DEFAULT '';"), NULL},
   /* We can now have multiple payments in progress for a single hash, so
    * add two fields; combination of payment_hash & partid is unique. */
    {SQL("ALTER TABLE payments RENAME TO temp_payments;"), NULL},
    {SQL("CREATE TABLE payments ("
	 " id BIGSERIAL"
	 ", timestamp INTEGER"
	 ", status INTEGER"
	 ", payment_hash BLOB"
	 ", destination BLOB"
	 ", msatoshi BIGINT"
	 ", payment_preimage BLOB"
	 ", path_secrets BLOB"
	 ", route_nodes BLOB"
	 ", route_channels BLOB"
	 ", failonionreply BLOB"
	 ", faildestperm INTEGER"
	 ", failindex INTEGER"
	 ", failcode INTEGER"
	 ", failnode BLOB"
	 ", failchannel TEXT"
	 ", failupdate BLOB"
	 ", msatoshi_sent BIGINT"
	 ", faildetail TEXT"
	 ", description TEXT"
	 ", faildirection INTEGER"
	 ", bolt11 TEXT"
	 ", total_msat BIGINT"
	 ", partid BIGINT"
	 ", PRIMARY KEY (id)"
	 ", UNIQUE (payment_hash, partid))"), NULL},
    {SQL("INSERT INTO payments ("
	 "id"
	 ", timestamp"
	 ", status"
	 ", payment_hash"
	 ", destination"
	 ", msatoshi"
	 ", payment_preimage"
	 ", path_secrets"
	 ", route_nodes"
	 ", route_channels"
	 ", failonionreply"
	 ", faildestperm"
	 ", failindex"
	 ", failcode"
	 ", failnode"
	 ", failchannel"
	 ", failupdate"
	 ", msatoshi_sent"
	 ", faildetail"
	 ", description"
	 ", faildirection"
	 ", bolt11)"
	 "SELECT id"
	 ", timestamp"
	 ", status"
	 ", payment_hash"
	 ", destination"
	 ", msatoshi"
	 ", payment_preimage"
	 ", path_secrets"
	 ", route_nodes"
	 ", route_channels"
	 ", failonionreply"
	 ", faildestperm"
	 ", failindex"
	 ", failcode"
	 ", failnode"
	 ", failchannel"
	 ", failupdate"
	 ", msatoshi_sent"
	 ", faildetail"
	 ", description"
	 ", faildirection"
	 ", bolt11 FROM temp_payments;"), NULL},
    {SQL("UPDATE payments SET total_msat = msatoshi;"), NULL},
    {SQL("UPDATE payments SET partid = 0;"), NULL},
    {SQL("DROP TABLE temp_payments;"), NULL},
    {SQL("ALTER TABLE channel_htlcs ADD partid BIGINT;"), NULL},
    {SQL("UPDATE channel_htlcs SET partid = 0;"), NULL},
    {SQL("CREATE TABLE channel_feerates ("
	 "  channel_id BIGINT REFERENCES channels(id) ON DELETE CASCADE,"
	 "  hstate INTEGER,"
	 "  feerate_per_kw INTEGER,"
	 "  UNIQUE (channel_id, hstate)"
	 ");"),
     NULL},
    /* Cast old-style per-side feerates into most likely layout for statewise
     * feerates. */
    /* If we're funder (LOCAL=0):
     *   Then our feerate is set last (SENT_ADD_ACK_REVOCATION = 4) */
    {SQL("INSERT INTO channel_feerates(channel_id, hstate, feerate_per_kw)"
	 " SELECT id, 4, local_feerate_per_kw FROM channels WHERE funder = 0;"),
     NULL},
    /*   If different, assume their feerate is in state SENT_ADD_COMMIT = 1 */
    {SQL("INSERT INTO channel_feerates(channel_id, hstate, feerate_per_kw)"
	 " SELECT id, 1, remote_feerate_per_kw FROM channels WHERE funder = 0 and local_feerate_per_kw != remote_feerate_per_kw;"),
     NULL},
    /* If they're funder (REMOTE=1):
     *   Then their feerate is set last (RCVD_ADD_ACK_REVOCATION = 14) */
    {SQL("INSERT INTO channel_feerates(channel_id, hstate, feerate_per_kw)"
	 " SELECT id, 14, remote_feerate_per_kw FROM channels WHERE funder = 1;"),
     NULL},
    /*   If different, assume their feerate is in state RCVD_ADD_COMMIT = 11 */
    {SQL("INSERT INTO channel_feerates(channel_id, hstate, feerate_per_kw)"
	 " SELECT id, 11, local_feerate_per_kw FROM channels WHERE funder = 1 and local_feerate_per_kw != remote_feerate_per_kw;"),
     NULL},
    /* FIXME: Remove now-unused local_feerate_per_kw and remote_feerate_per_kw from channels */
    {SQL("INSERT INTO vars (name, intval) VALUES ('data_version', 0);"), NULL},
    /* For outgoing HTLCs, we now keep a localmsg instead of a failcode.
     * Turn anything in transition into a WIRE_TEMPORARY_NODE_FAILURE. */
    {SQL("ALTER TABLE channel_htlcs ADD localfailmsg BLOB;"), NULL},
    {SQL("UPDATE channel_htlcs SET localfailmsg=decode('2002', 'hex') WHERE malformed_onion != 0 AND direction = 1;"), NULL},
    {SQL("ALTER TABLE channels ADD our_funding_satoshi BIGINT DEFAULT 0;"), migrate_our_funding},
    {SQL("CREATE TABLE penalty_bases ("
	 "  channel_id BIGINT REFERENCES channels(id) ON DELETE CASCADE"
	 ", commitnum BIGINT"
	 ", txid BLOB"
	 ", outnum INTEGER"
	 ", amount BIGINT"
	 ", PRIMARY KEY (channel_id, commitnum)"
	 ");"), NULL},
    /* For incoming HTLCs, we now keep track of whether or not we provided
     * the preimage for it, or not. */
    {SQL("ALTER TABLE channel_htlcs ADD we_filled INTEGER;"), NULL},
    /* We track the counter for coin_moves, as a convenience for notification consumers */
    {SQL("INSERT INTO vars (name, intval) VALUES ('coin_moves_count', 0);"), NULL},
    {NULL, migrate_last_tx_to_psbt},
    {SQL("ALTER TABLE outputs ADD reserved_til INTEGER DEFAULT NULL;"), NULL},
    {NULL, fillin_missing_scriptpubkeys},
    /* option_anchor_outputs is nailed at creation time. */
    {SQL("ALTER TABLE channels ADD COLUMN option_anchor_outputs INTEGER"
	 " DEFAULT 0;"), NULL },
    /* We need to know if it was option_anchor_outputs to spend to_remote */
    {SQL("ALTER TABLE outputs ADD option_anchor_outputs INTEGER"
	 " DEFAULT 0;"), NULL},
    {SQL("ALTER TABLE channels ADD full_channel_id BLOB DEFAULT NULL;"), fillin_missing_channel_id},
    {SQL("ALTER TABLE channels ADD funding_psbt BLOB DEFAULT NULL;"), NULL},
    /* Channel closure reason */
    {SQL("ALTER TABLE channels ADD closer INTEGER DEFAULT 2;"), NULL},
    {SQL("ALTER TABLE channels ADD state_change_reason INTEGER DEFAULT 0;"), NULL},
    {SQL("CREATE TABLE channel_state_changes ("
	 "  channel_id BIGINT REFERENCES channels(id) ON DELETE CASCADE,"
	 "  timestamp BIGINT,"
	 "  old_state INTEGER,"
	 "  new_state INTEGER,"
	 "  cause INTEGER,"
	 "  message TEXT"
	 ");"), NULL},
    {SQL("CREATE TABLE offers ("
	 "  offer_id BLOB"
	 ", bolt12 TEXT"
	 ", label TEXT"
	 ", status INTEGER"
	 ", PRIMARY KEY (offer_id)"
	 ");"), NULL},
    /* A reference into our own offers table, if it was made from one */
    {SQL("ALTER TABLE invoices ADD COLUMN local_offer_id BLOB DEFAULT NULL REFERENCES offers(offer_id);"), NULL},
    /* A reference into our own offers table, if it was made from one */
    {SQL("ALTER TABLE payments ADD COLUMN local_offer_id BLOB DEFAULT NULL REFERENCES offers(offer_id);"), NULL},
    {SQL("ALTER TABLE channels ADD funding_tx_remote_sigs_received INTEGER DEFAULT 0;"), NULL},
    /* Speeds up deletion of one peer from the database, measurements suggest
     * it cuts down the time by 80%.  */
    {SQL("CREATE INDEX forwarded_payments_out_htlc_id"
	 " ON forwarded_payments (out_htlc_id);"), NULL},
    {SQL("UPDATE channel_htlcs SET malformed_onion = 0 WHERE malformed_onion IS NULL"), NULL},
    /*  Speed up forwarded_payments lookup based on state */
    {SQL("CREATE INDEX forwarded_payments_state ON forwarded_payments (state)"), NULL},
    {SQL("CREATE TABLE channel_funding_inflights ("
	 "  channel_id BIGSERIAL REFERENCES channels(id) ON DELETE CASCADE"
	 ", funding_tx_id BLOB"
	 ", funding_tx_outnum INTEGER"
	 ", funding_feerate INTEGER"
	 ", funding_satoshi BIGINT"
	 ", our_funding_satoshi BIGINT"
	 ", funding_psbt BLOB"
	 ", last_tx BLOB"
	 ", last_sig BLOB"
	 ", funding_tx_remote_sigs_received INTEGER"
	 ", PRIMARY KEY (channel_id, funding_tx_id)"
	 ");"),
    NULL},
    {SQL("ALTER TABLE channels ADD revocation_basepoint_local BLOB"), NULL},
    {SQL("ALTER TABLE channels ADD payment_basepoint_local BLOB"), NULL},
    {SQL("ALTER TABLE channels ADD htlc_basepoint_local BLOB"), NULL},
    {SQL("ALTER TABLE channels ADD delayed_payment_basepoint_local BLOB"), NULL},
    {SQL("ALTER TABLE channels ADD funding_pubkey_local BLOB"), NULL},
    {NULL, fillin_missing_local_basepoints},
    /* Oops, can I haz money back plz? */
    {SQL("ALTER TABLE channels ADD shutdown_wrong_txid BLOB DEFAULT NULL"), NULL},
    {SQL("ALTER TABLE channels ADD shutdown_wrong_outnum INTEGER DEFAULT NULL"), NULL},
    {NULL, migrate_inflight_last_tx_to_psbt},
    /* Channels can now change their type at specific commit indexes. */
    {SQL("ALTER TABLE channels ADD local_static_remotekey_start BIGINT DEFAULT 0"),
     NULL},
    {SQL("ALTER TABLE channels ADD remote_static_remotekey_start BIGINT DEFAULT 0"),
     NULL},
    /* Set counter past 2^48 if they don't have option */
    {SQL("UPDATE channels SET"
	 " remote_static_remotekey_start = 9223372036854775807,"
	 " local_static_remotekey_start = 9223372036854775807"
	 " WHERE option_static_remotekey = 0"),
     NULL},
    {SQL("ALTER TABLE channel_funding_inflights ADD lease_commit_sig BLOB DEFAULT NULL"), NULL},
    {SQL("ALTER TABLE channel_funding_inflights ADD lease_chan_max_msat BIGINT DEFAULT NULL"), NULL},
    {SQL("ALTER TABLE channel_funding_inflights ADD lease_chan_max_ppt INTEGER DEFAULT NULL"), NULL},
    {SQL("ALTER TABLE channel_funding_inflights ADD lease_expiry INTEGER DEFAULT 0"), NULL},
    {SQL("ALTER TABLE channel_funding_inflights ADD lease_blockheight_start INTEGER DEFAULT 0"), NULL},
    {SQL("ALTER TABLE channels ADD lease_commit_sig BLOB DEFAULT NULL"), NULL},
    {SQL("ALTER TABLE channels ADD lease_chan_max_msat INTEGER DEFAULT NULL"), NULL},
    {SQL("ALTER TABLE channels ADD lease_chan_max_ppt INTEGER DEFAULT NULL"), NULL},
    {SQL("ALTER TABLE channels ADD lease_expiry INTEGER DEFAULT 0"), NULL},
    {SQL("CREATE TABLE channel_blockheights ("
	 "  channel_id BIGINT REFERENCES channels(id) ON DELETE CASCADE,"
	 "  hstate INTEGER,"
	 "  blockheight INTEGER,"
	 "  UNIQUE (channel_id, hstate)"
	 ");"),
     fillin_missing_channel_blockheights},
    {SQL("ALTER TABLE outputs ADD csv_lock INTEGER DEFAULT 1;"), NULL},
    {SQL("CREATE TABLE datastore ("
	 "  key BLOB,"
	 "  data BLOB,"
	 "  generation BIGINT,"
	 "  PRIMARY KEY (key)"
	 ");"),
     NULL},
    {SQL("CREATE INDEX channel_state_changes_channel_id"
	 " ON channel_state_changes (channel_id);"), NULL},
    /* We need to switch the unique key to cover the groupid as well,
     * so we can attempt payments multiple times. */
    {SQL("ALTER TABLE payments RENAME TO temp_payments;"), NULL},
    {SQL("CREATE TABLE payments ("
	 " id BIGSERIAL"
	 ", timestamp INTEGER"
	 ", status INTEGER"
	 ", payment_hash BLOB"
	 ", destination BLOB"
	 ", msatoshi BIGINT"
	 ", payment_preimage BLOB"
	 ", path_secrets BLOB"
	 ", route_nodes BLOB"
	 ", route_channels BLOB"
	 ", failonionreply BLOB"
	 ", faildestperm INTEGER"
	 ", failindex INTEGER"
	 ", failcode INTEGER"
	 ", failnode BLOB"
	 ", failchannel TEXT"
	 ", failupdate BLOB"
	 ", msatoshi_sent BIGINT"
	 ", faildetail TEXT"
	 ", description TEXT"
	 ", faildirection INTEGER"
	 ", bolt11 TEXT"
	 ", total_msat BIGINT"
	 ", partid BIGINT"
	 ", groupid BIGINT NOT NULL DEFAULT 0"
	 ", local_offer_id BLOB DEFAULT NULL REFERENCES offers(offer_id)"
	 ", PRIMARY KEY (id)"
	 ", UNIQUE (payment_hash, partid, groupid))"), NULL},
    {SQL("INSERT INTO payments ("
	 "id"
	 ", timestamp"
	 ", status"
	 ", payment_hash"
	 ", destination"
	 ", msatoshi"
	 ", payment_preimage"
	 ", path_secrets"
	 ", route_nodes"
	 ", route_channels"
	 ", failonionreply"
	 ", faildestperm"
	 ", failindex"
	 ", failcode"
	 ", failnode"
	 ", failchannel"
	 ", failupdate"
	 ", msatoshi_sent"
	 ", faildetail"
	 ", description"
	 ", faildirection"
	 ", bolt11"
	 ", groupid"
	 ", local_offer_id)"
	 "SELECT id"
	 ", timestamp"
	 ", status"
	 ", payment_hash"
	 ", destination"
	 ", msatoshi"
	 ", payment_preimage"
	 ", path_secrets"
	 ", route_nodes"
	 ", route_channels"
	 ", failonionreply"
	 ", faildestperm"
	 ", failindex"
	 ", failcode"
	 ", failnode"
	 ", failchannel"
	 ", failupdate"
	 ", msatoshi_sent"
	 ", faildetail"
	 ", description"
	 ", faildirection"
	 ", bolt11"
	 ", 0"
	 ", local_offer_id FROM temp_payments;"), NULL},
    {SQL("DROP TABLE temp_payments;"), NULL},
    /* HTLCs also need to carry the groupid around so we can
     * selectively update them. */
    {SQL("ALTER TABLE channel_htlcs ADD groupid BIGINT;"), NULL},
    {SQL("ALTER TABLE channel_htlcs ADD COLUMN"
	 " min_commit_num BIGINT default 0;"), NULL},
    {SQL("ALTER TABLE channel_htlcs ADD COLUMN"
	 " max_commit_num BIGINT default NULL;"), NULL},
    /* Set max_commit_num for dead (RCVD_REMOVE_ACK_REVOCATION or SENT_REMOVE_ACK_REVOCATION) HTLCs based on latest indexes */
    {SQL("UPDATE channel_htlcs SET max_commit_num ="
	 " (SELECT GREATEST(next_index_local, next_index_remote)"
	 "  FROM channels WHERE id=channel_id)"
	 " WHERE (hstate=9 OR hstate=19);"), NULL},
    /* Remove unused fields which take much room in db. */
    {SQL("UPDATE channel_htlcs SET"
	 " payment_key=NULL,"
	 " routing_onion=NULL,"
	 " failuremsg=NULL,"
	 " shared_secret=NULL,"
	 " localfailmsg=NULL"
	 " WHERE (hstate=9 OR hstate=19);"), NULL},
    /* We default to 50k sats */
    {SQL("ALTER TABLE channel_configs ADD max_dust_htlc_exposure_msat BIGINT DEFAULT 50000000"), NULL},
    {SQL("ALTER TABLE channel_htlcs ADD fail_immediate INTEGER DEFAULT 0"), NULL},

    /* Issue #4887: reset the payments.id sequence after the migration above. Since this is a SELECT statement that would otherwise fail, make it an INSERT into the `vars` table.*/
    {SQL("/*PSQL*/INSERT INTO vars (name, intval) VALUES ('payment_id_reset', setval(pg_get_serial_sequence('payments', 'id'), COALESCE((SELECT MAX(id)+1 FROM payments), 1)))"), NULL},

    /* Issue #4901: Partial index speeds up startup on nodes with ~1000 channels.  */
    {&SQL("CREATE INDEX channel_htlcs_speedup_unresolved_idx"
	 "    ON channel_htlcs(channel_id, direction)"
	 " WHERE hstate NOT IN (9, 19);")
	[BUILD_ASSERT_OR_ZERO( 9 == RCVD_REMOVE_ACK_REVOCATION) +
	 BUILD_ASSERT_OR_ZERO(19 == SENT_REMOVE_ACK_REVOCATION)],
     NULL},
    {SQL("ALTER TABLE channel_htlcs ADD fees_msat BIGINT DEFAULT 0"), NULL},
    {SQL("ALTER TABLE channel_funding_inflights ADD lease_fee BIGINT DEFAULT 0"), NULL},
    /* Default is too big; we set to max after loading */
    {SQL("ALTER TABLE channels ADD htlc_maximum_msat BIGINT DEFAULT 2100000000000000"), NULL},
    {SQL("ALTER TABLE channels ADD htlc_minimum_msat BIGINT DEFAULT 0"), NULL},
    {SQL("ALTER TABLE forwarded_payments ADD forward_style INTEGER DEFAULT NULL"), NULL},
    /* "description" is used for label, so we use "paydescription" here */
    {SQL("ALTER TABLE payments ADD paydescription TEXT;"), NULL},
    /* Alias we sent to the remote side, for zeroconf and
     * option_scid_alias, can be a list of short_channel_ids if
     * required, but keeping it a single SCID for now. */
    {SQL("ALTER TABLE channels ADD alias_local BIGINT DEFAULT NULL"), NULL},
    /* Alias we received from the peer, and which we should be using
     * in routehints in invoices. The peer will remember all the
     * aliases, but we only ever need one. */
    {SQL("ALTER TABLE channels ADD alias_remote BIGINT DEFAULT NULL"), NULL},
    /* Cheeky immediate completion as best effort approximation of real completion time */
    {SQL("ALTER TABLE payments ADD completed_at INTEGER DEFAULT NULL;"), NULL},
    {SQL("UPDATE payments SET completed_at = timestamp WHERE status != 0;"), NULL},
    {SQL("CREATE INDEX payments_idx ON payments (payment_hash)"), NULL},
    /* forwards table outlives the channels, so we move there from old forwarded_payments table;
     * but here the ids are the HTLC numbers, not the internal db ids. */
    {SQL("CREATE TABLE forwards ("
	 "in_channel_scid BIGINT"
	 ", in_htlc_id BIGINT"
	 ", out_channel_scid BIGINT"
	 ", out_htlc_id BIGINT"
	 ", in_msatoshi BIGINT"
	 ", out_msatoshi BIGINT"
	 ", state INTEGER"
	 ", received_time BIGINT"
	 ", resolved_time BIGINT"
	 ", failcode INTEGER"
	 ", forward_style INTEGER"
	 ", PRIMARY KEY(in_channel_scid, in_htlc_id))"), NULL},
    {SQL("INSERT INTO forwards SELECT"
	 " in_channel_scid"
	 ", COALESCE("
	 "    (SELECT channel_htlc_id FROM channel_htlcs WHERE id = forwarded_payments.in_htlc_id),"
	 "    -_ROWID_"
	 "  )"
	 ", out_channel_scid"
	 ", (SELECT channel_htlc_id FROM channel_htlcs WHERE id = forwarded_payments.out_htlc_id)"
	 ", in_msatoshi"
	 ", out_msatoshi"
	 ", state"
	 ", received_time"
	 ", resolved_time"
	 ", failcode"
	 ", forward_style"
	 " FROM forwarded_payments"), NULL},
    {SQL("DROP INDEX forwarded_payments_state;"), NULL},
    {SQL("DROP INDEX forwarded_payments_out_htlc_id;"), NULL},
    {SQL("DROP TABLE forwarded_payments;"), NULL},
    /* Adds scid column, then moves short_channel_id across to it */
    {SQL("ALTER TABLE channels ADD scid BIGINT;"), migrate_channels_scids_as_integers},
    {SQL("ALTER TABLE payments ADD failscid BIGINT;"), migrate_payments_scids_as_integers},
    {SQL("ALTER TABLE outputs ADD is_in_coinbase INTEGER DEFAULT 0;"), NULL},
    {SQL("CREATE TABLE invoicerequests ("
	 "  invreq_id BLOB"
	 ", bolt12 TEXT"
	 ", label TEXT"
	 ", status INTEGER"
	 ", PRIMARY KEY (invreq_id)"
	 ");"), NULL},
    /* A reference into our own invoicerequests table, if it was made from one */
    {SQL("ALTER TABLE payments ADD COLUMN local_invreq_id BLOB DEFAULT NULL REFERENCES invoicerequests(invreq_id);"), NULL},
    /* FIXME: Remove payments local_offer_id column! */
    {SQL("ALTER TABLE channel_funding_inflights ADD COLUMN lease_satoshi BIGINT;"), NULL},
    {SQL("ALTER TABLE channels ADD require_confirm_inputs_remote INTEGER DEFAULT 0;"), NULL},
    {SQL("ALTER TABLE channels ADD require_confirm_inputs_local INTEGER DEFAULT 0;"), NULL},
    {NULL, fillin_missing_lease_satoshi},
    {NULL, migrate_invalid_last_tx_psbts},
    {SQL("ALTER TABLE channels ADD channel_type BLOB DEFAULT NULL;"), NULL},
    {NULL, migrate_fill_in_channel_type},
    {SQL("ALTER TABLE peers ADD feature_bits BLOB DEFAULT NULL;"), NULL},
    {NULL, migrate_normalize_invstr},
    {SQL("CREATE TABLE runes (id BIGSERIAL, rune TEXT, PRIMARY KEY (id));"), NULL},
    {SQL("CREATE TABLE runes_blacklist (start_index BIGINT, end_index BIGINT);"), NULL},
    {SQL("ALTER TABLE channels ADD ignore_fee_limits INTEGER DEFAULT 0;"), NULL},
    {NULL, migrate_initialize_invoice_wait_indexes},
    {SQL("ALTER TABLE invoices ADD updated_index BIGINT DEFAULT 0"), NULL},
    {SQL("CREATE INDEX invoice_update_idx ON invoices (updated_index)"), NULL},
    {NULL, migrate_datastore_commando_runes},
    {NULL, migrate_invoice_created_index_var},
    /* Splicing requires us to store HTLC sigs for inflight splices and allows us to discard old sigs after splice confirmation. */
    {SQL("ALTER TABLE htlc_sigs ADD inflight_tx_id BLOB"), NULL},
    {SQL("ALTER TABLE htlc_sigs ADD inflight_tx_outnum INTEGER"), NULL},
    {SQL("ALTER TABLE channel_funding_inflights ADD splice_amnt BIGINT DEFAULT 0"), NULL},
    {SQL("ALTER TABLE channel_funding_inflights ADD i_am_initiator INTEGER DEFAULT 0"), NULL},
    {NULL, migrate_runes_idfix},
    {SQL("ALTER TABLE runes ADD last_used_nsec BIGINT DEFAULT NULL"), NULL},
    {SQL("DELETE FROM vars WHERE name = 'runes_uniqueid'"), NULL},
    {SQL("CREATE TABLE invoice_fallbacks ("
     "  scriptpubkey BLOB,"
     "  invoice_id BIGINT REFERENCES invoices(id) ON DELETE CASCADE,"
     "  PRIMARY KEY (scriptpubkey)"
     ");"),
     NULL},
    {SQL("ALTER TABLE invoices ADD paid_txid BLOB DEFAULT NULL"), NULL},
    {SQL("ALTER TABLE invoices ADD paid_outnum INTEGER DEFAULT NULL"), NULL},
    {SQL("CREATE TABLE local_anchors ("
	 "  channel_id BIGSERIAL REFERENCES channels(id),"
	 "  commitment_index BIGINT,"
	 "  commitment_txid BLOB,"
	 "  commitment_anchor_outnum INTEGER,"
	 "  commitment_fee BIGINT,"
	 "  commitment_weight INTEGER)"), NULL},
    {SQL("CREATE INDEX local_anchors_idx ON local_anchors (channel_id)"), NULL},
    {SQL("ALTER TABLE payments ADD updated_index BIGINT DEFAULT 0"), NULL},
    {SQL("CREATE INDEX payments_update_idx ON payments (updated_index)"), NULL},
    {NULL, migrate_initialize_payment_wait_indexes},
    {NULL, migrate_forwards_add_rowid},
    {SQL("ALTER TABLE forwards ADD updated_index BIGINT DEFAULT 0"), NULL},
    {SQL("CREATE INDEX forwards_updated_idx ON forwards (updated_index)"), NULL},
    {NULL, migrate_initialize_forwards_wait_indexes},
    {SQL("ALTER TABLE channel_funding_inflights ADD force_sign_first INTEGER DEFAULT 0"), NULL},
    {SQL("ALTER TABLE channels ADD remote_feerate_base INTEGER DEFAULT NULL;"), NULL},
    {SQL("ALTER TABLE channels ADD remote_feerate_ppm INTEGER DEFAULT NULL;"), NULL},
    {SQL("ALTER TABLE channels ADD remote_cltv_expiry_delta INTEGER DEFAULT NULL;"), NULL},
    {SQL("ALTER TABLE channels ADD remote_htlc_maximum_msat BIGINT DEFAULT NULL;"), NULL},
    {SQL("ALTER TABLE channels ADD remote_htlc_minimum_msat BIGINT DEFAULT NULL;"), NULL},
    {SQL("ALTER TABLE channels ADD last_stable_connection BIGINT DEFAULT 0;"), NULL},
    {NULL, NULL}, /* old migrate_initialize_alias_local */
    {SQL("CREATE TABLE addresses ("
	 "  keyidx BIGINT,"
	 "  addrtype INTEGER)"), NULL},
    {NULL, insert_addrtype_to_addresses},
    {SQL("ALTER TABLE channel_funding_inflights ADD remote_funding BLOB DEFAULT NULL;"), NULL},
    {SQL("ALTER TABLE peers ADD last_known_address BLOB DEFAULT NULL;"), NULL},
    {SQL("ALTER TABLE channels ADD close_attempt_height INTEGER DEFAULT 0;"), NULL},
    {NULL, migrate_convert_old_channel_keyidx},
    {SQL("INSERT INTO vars(name, intval)"
	 "  VALUES('needs_p2wpkh_close_rescan', 1)"), NULL},
    {SQL("ALTER TABLE channel_htlcs ADD updated_index BIGINT DEFAULT 0"), NULL},
    {SQL("CREATE INDEX channel_htlcs_updated_idx ON channel_htlcs (updated_index)"), NULL},
    {NULL, NULL}, /* Old, incorrect channel_htlcs_wait_indexes migration */
    {SQL("ALTER TABLE channel_funding_inflights ADD locked_scid BIGINT DEFAULT 0;"), NULL},
    {NULL, migrate_initialize_channel_htlcs_wait_indexes_and_fixup_forwards},
    {SQL("ALTER TABLE channel_funding_inflights ADD i_sent_sigs INTEGER DEFAULT 0"), NULL},
    {SQL("ALTER TABLE channels ADD old_scids BLOB DEFAULT NULL;"), NULL},
    {NULL, migrate_initialize_alias_local},
    /* Avoids duplication in chain_moves and coin_moves tables */
    {SQL("CREATE TABLE move_accounts ("
	 "  id BIGSERIAL,"
	 "  name TEXT,"
	 "  PRIMARY KEY (id),"
	 "  UNIQUE (name)"
	 ")"), NULL},
    {SQL("CREATE TABLE chain_moves ("
	 "  id BIGSERIAL,"
	 /* One of these is null */
	 "  account_channel_id BIGINT references channels(id),"
	 "  account_nonchannel_id BIGINT references move_accounts(id),"
	 "  tag_bitmap BIGINT NOT NULL,"
	 "  credit_or_debit BIGINT NOT NULL,"
	 "  timestamp BIGINT NOT NULL,"
	 "  utxo BLOB NOT NULL,"
	 "  spending_txid BLOB,"
	 /* This does NOT reference peers(node_id), since we can have
	  * MVT_CHANNEL_PROPOSED events on zeroconf channels where we end up
	  * forgetting the channel, thus the peer */
	 "  peer_id BLOB,"
	 "  payment_hash BLOB,"
	 "  block_height INTEGER NOT NULL,"
	 "  output_sat BIGINT NOT NULL,"
	 /* One of these is null */
	 "  originating_channel_id BIGINT references channels(id),"
	 "  originating_nonchannel_id BIGINT references move_accounts(id),"
	 "  output_count INTEGER,"
	 "  PRIMARY KEY (id)"
	 ")"), NULL},
    {SQL("CREATE TABLE channel_moves ("
	 "  id BIGSERIAL,"
	 /* One of these is null */
	 "  account_channel_id BIGINT references channels(id),"
	 "  account_nonchannel_id BIGINT references move_accounts(id),"
	 "  tag_bitmap BIGINT NOT NULL,"
	 "  credit_or_debit BIGINT NOT NULL,"
	 "  timestamp BIGINT NOT NULL,"
	 "  payment_hash BLOB,"
	 "  payment_part_id BIGINT,"
	 "  payment_group_id BIGINT,"
	 "  fees BIGINT NOT NULL,"
	 "  PRIMARY KEY (id)"
	 ")"), NULL},
    /* We do a lookup before each append, to avoid duplicates */
    {SQL("CREATE INDEX chain_moves_utxo_idx ON chain_moves (utxo)"), NULL},
    {NULL, migrate_from_account_db, NULL, revert_too_early},
    /* ^v25.09 */

    /* We accidentally allowed duplicate entries */
    {NULL, migrate_remove_chain_moves_duplicates,
     /* Removing duplicates is idempotent, so no revert needed */
     NULL, NULL},
    {SQL("CREATE TABLE network_events ("
	 "  id BIGSERIAL,"
	 "  peer_id BLOB NOT NULL,"
	 "  type INTEGER NOT NULL,"
	 "  timestamp BIGINT,"
	 "  reason TEXT,"
	 "  duration_nsec BIGINT,"
	 "  connect_attempted INTEGER NOT NULL,"
	 " PRIMARY KEY (id)"
	 ")"), NULL,
	 /* Simply drop table. */
	 SQL("DROP TABLE network_events")},
    {NULL, migrate_fail_pending_payments_without_htlcs,
     /* Failing pending payments is idempotent, so no revert needed */
     NULL, NULL},
    {SQL("ALTER TABLE channels ADD withheld INTEGER DEFAULT 0;"), NULL,
     /* Need to make sure that withheld isn't used. */
     NULL, revert_withheld_column},
    /* ^v25.12 */

};

const struct db_migration *get_db_migrations(size_t *num)
{
	*num = ARRAY_SIZE(dbmigrations);
	return dbmigrations;
}
