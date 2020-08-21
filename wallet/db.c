#include "db.h"

#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/derive_basepoints.h>
#include <common/key_derive.h>
#include <common/node_id.h>
#include <common/onionreply.h>
#include <common/version.h>
#include <hsmd/gen_hsm_wire.h>
#include <inttypes.h>
#include <lightningd/channel.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/plugin_hook.h>
#include <wallet/db_common.h>
#include <wallet/wallet.h>
#include <wally_bip32.h>
#include <wire/wire_sync.h>

#define NSEC_IN_SEC 1000000000

struct migration {
	const char *sql;
	void (*func)(struct lightningd *ld, struct db *db,
		     const struct ext_key *bip32_base);
};

static void migrate_pr2342_feerate_per_channel(struct lightningd *ld, struct db *db,
					       const struct ext_key *bip32_base);

static void migrate_our_funding(struct lightningd *ld, struct db *db,
				const struct ext_key *bip32_base);

static void migrate_last_tx_to_psbt(struct lightningd *ld, struct db *db,
				    const struct ext_key *bip32_base);

static void fillin_missing_scriptpubkeys(struct lightningd *ld, struct db *db,
					 const struct ext_key *bip32_base);

/* Do not reorder or remove elements from this array, it is used to
 * migrate existing databases from a previous state, based on the
 * string indices */
static struct migration dbmigrations[] = {
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
};

/* Leak tracking. */
#if DEVELOPER
static void db_assert_no_outstanding_statements(struct db *db)
{
	struct db_stmt *stmt;

	stmt = list_top(&db->pending_statements, struct db_stmt, list);
	if (stmt)
		db_fatal("Unfinalized statement %s", stmt->location);
}
#else
static void db_assert_no_outstanding_statements(struct db *db)
{
}
#endif

static void db_stmt_free(struct db_stmt *stmt)
{
	if (!stmt->executed)
		fatal("Freeing an un-executed statement from %s: %s",
		      stmt->location, stmt->query->query);
	if (stmt->inner_stmt)
		stmt->db->config->stmt_free_fn(stmt);
	assert(stmt->inner_stmt == NULL);
}

struct db_stmt *db_prepare_v2_(const char *location, struct db *db,
				     const char *query_id)
{
	struct db_stmt *stmt = tal(db, struct db_stmt);
	size_t num_slots;
	stmt->query = NULL;

	/* Normalize query_id paths, because unit tests are compiled with this
	 * prefix. */
	if (strncmp(query_id, "./", 2) == 0)
		query_id += 2;

	if (!db->in_transaction)
		db_fatal("Attempting to prepare a db_stmt outside of a "
			 "transaction: %s", location);

	/* Look up the query by its ID */
	for (size_t i = 0; i < db->config->num_queries; i++) {
		if (streq(query_id, db->config->queries[i].name)) {
			stmt->query = &db->config->queries[i];
			break;
		}
	}
	if (stmt->query == NULL)
		fatal("Could not resolve query %s", query_id);

	num_slots = stmt->query->placeholders;
	/* Allocate the slots for placeholders/bindings, zeroed next since
	 * that sets the type to DB_BINDING_UNINITIALIZED for later checks. */
	stmt->bindings = tal_arr(stmt, struct db_binding, num_slots);
	for (size_t i=0; i<num_slots; i++)
		stmt->bindings[i].type = DB_BINDING_UNINITIALIZED;

	stmt->location = location;
	stmt->error = NULL;
	stmt->db = db;
	stmt->executed = false;
	stmt->inner_stmt = NULL;

	tal_add_destructor(stmt, db_stmt_free);

	list_add(&db->pending_statements, &stmt->list);

	return stmt;
}

#define db_prepare_v2(db,query) \
	db_prepare_v2_(__FILE__ ":" stringify(__LINE__), db, query)

bool db_step(struct db_stmt *stmt)
{
	assert(stmt->executed);
	return stmt->db->config->step_fn(stmt);
}

u64 db_column_u64(struct db_stmt *stmt, int col)
{
	if (db_column_is_null(stmt, col)) {
		log_broken(stmt->db->log, "Accessing a null column %d in query %s", col, stmt->query->query);
		return 0;
	}
	return stmt->db->config->column_u64_fn(stmt, col);
}

int db_column_int_or_default(struct db_stmt *stmt, int col, int def)
{
	if (db_column_is_null(stmt, col))
		return def;
	else
		return db_column_int(stmt, col);
}

int db_column_int(struct db_stmt *stmt, int col)
{
	if (db_column_is_null(stmt, col)) {
		log_broken(stmt->db->log, "Accessing a null column %d in query %s", col, stmt->query->query);
		return 0;
	}
	return stmt->db->config->column_int_fn(stmt, col);
}

size_t db_column_bytes(struct db_stmt *stmt, int col)
{
	if (db_column_is_null(stmt, col)) {
		log_broken(stmt->db->log, "Accessing a null column %d in query %s", col, stmt->query->query);
		return 0;
	}
	return stmt->db->config->column_bytes_fn(stmt, col);
}

int db_column_is_null(struct db_stmt *stmt, int col)
{
	return stmt->db->config->column_is_null_fn(stmt, col);
}

const void *db_column_blob(struct db_stmt *stmt, int col)
{
	if (db_column_is_null(stmt, col)) {
		log_broken(stmt->db->log, "Accessing a null column %d in query %s", col, stmt->query->query);
		return NULL;
	}
	return stmt->db->config->column_blob_fn(stmt, col);
}

const unsigned char *db_column_text(struct db_stmt *stmt, int col)
{
	if (db_column_is_null(stmt, col)) {
		log_broken(stmt->db->log, "Accessing a null column %d in query %s", col, stmt->query->query);
		return NULL;
	}
	return stmt->db->config->column_text_fn(stmt, col);
}

size_t db_count_changes(struct db_stmt *stmt)
{
	assert(stmt->executed);
	return stmt->db->config->count_changes_fn(stmt);
}

u64 db_last_insert_id_v2(struct db_stmt *stmt TAKES)
{
	u64 id;
	assert(stmt->executed);
	id = stmt->db->config->last_insert_id_fn(stmt);

	if (taken(stmt))
		tal_free(stmt);

	return id;
}

static void destroy_db(struct db *db)
{
	db_assert_no_outstanding_statements(db);

	if (db->config->teardown_fn)
		db->config->teardown_fn(db);
}

/* We expect min changes (ie. BEGIN TRANSACTION): report if more.
 * Optionally add "final" at the end (ie. COMMIT). */
static void db_report_changes(struct db *db, const char *final, size_t min)
{
	assert(db->changes);
	assert(tal_count(db->changes) >= min);

	/* Having changes implies that we have a dirty TX. The opposite is
	 * currently not true, e.g., the postgres driver doesn't record
	 * changes yet. */
	assert(!tal_count(db->changes) || db->dirty);

	if (tal_count(db->changes) > min)
		plugin_hook_db_sync(db);
	db->changes = tal_free(db->changes);
}

static void db_prepare_for_changes(struct db *db)
{
	assert(!db->changes);
	db->changes = tal_arr(db, const char *, 0);
}

bool db_in_transaction(struct db *db)
{
	return db->in_transaction;
}

void db_begin_transaction_(struct db *db, const char *location)
{
	bool ok;
	if (db->in_transaction)
		db_fatal("Already in transaction from %s", db->in_transaction);

	/* No writes yet. */
	db->dirty = false;

	db_prepare_for_changes(db);
	ok = db->config->begin_tx_fn(db);
	if (!ok)
		db_fatal("Failed to start DB transaction: %s", db->error);

	db->in_transaction = location;
}

/* By making the update conditional on the current value we expect we
 * are implementing an optimistic lock: if the update results in
 * changes on the DB we know that the data_version did not change
 * under our feet and no other transaction ran in the meantime.
 *
 * Notice that this update effectively locks the row, so that other
 * operations attempting to change this outside the transaction will
 * wait for this transaction to complete. The external change will
 * ultimately fail the changes test below, it'll just delay its abort
 * until our transaction is committed.
 */
static void db_data_version_incr(struct db *db)
{
       struct db_stmt *stmt = db_prepare_v2(
	       db, SQL("UPDATE vars "
		       "SET intval = intval + 1 "
		       "WHERE name = 'data_version'"
		       " AND intval = ?"));
       db_bind_int(stmt, 0, db->data_version);
       db_exec_prepared_v2(stmt);
       if (db_count_changes(stmt) != 1)
	       fatal("Optimistic lock on the database failed. There may be a "
                     "concurrent access to the database. Aborting since "
                     "concurrent access is unsafe.");
       tal_free(stmt);
       db->data_version++;
}

void db_commit_transaction(struct db *db)
{
	bool ok;
	assert(db->in_transaction);
	db_assert_no_outstanding_statements(db);

	/* Increment before reporting changes to an eventual plugin. */
	if (db->dirty)
		db_data_version_incr(db);

	db_report_changes(db, NULL, 0);
	ok = db->config->commit_tx_fn(db);

	if (!ok)
		db_fatal("Failed to commit DB transaction: %s", db->error);

	db->in_transaction = NULL;
	db->dirty = false;
}

static struct db_config *db_config_find(const char *dsn)
{
	size_t num_configs;
	struct db_config **configs = autodata_get(db_backends, &num_configs);
	const char *sep, *driver_name;
	sep = strstr(dsn, "://");

	if (!sep)
		db_fatal("%s doesn't look like a valid data-source name (missing \"://\" separator.", dsn);

	driver_name = tal_strndup(tmpctx, dsn, sep - dsn);

	for (size_t i=0; i<num_configs; i++) {
		if (streq(driver_name, configs[i]->name)) {
			tal_free(driver_name);
			return configs[i];
		}
	}

	tal_free(driver_name);
	return NULL;
}

/**
 * db_open - Open or create a sqlite3 database
 */
static struct db *db_open(const tal_t *ctx, char *filename)
{
	struct db *db;

	db = tal(ctx, struct db);
	db->filename = tal_strdup(db, filename);
	list_head_init(&db->pending_statements);
	if (!strstr(db->filename, "://"))
		db_fatal("Could not extract driver name from \"%s\"", db->filename);

	db->config = db_config_find(db->filename);
	if (!db->config)
		db_fatal("Unable to find DB driver for %s", db->filename);

	tal_add_destructor(db, destroy_db);
	db->in_transaction = NULL;
	db->changes = NULL;

	/* This must be outside a transaction, so catch it */
	assert(!db->in_transaction);

	db_prepare_for_changes(db);
	if (db->config->setup_fn && !db->config->setup_fn(db))
		fatal("Error calling DB setup: %s", db->error);
	db_report_changes(db, NULL, 0);

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
	int res = -1;
	struct db_stmt *stmt = db_prepare_v2(db, SQL("SELECT version FROM version LIMIT 1"));

	/*
	 * Tentatively execute a query, but allow failures. Some databases
	 * like postgres will terminate the DB transaction if there is an
	 * error during the execution of a query, e.g., trying to access a
	 * table that doesn't exist yet, so we need to terminate and restart
	 * the DB transaction.
	 */
	if (!db_query_prepared(stmt)) {
		db_commit_transaction(stmt->db);
		db_begin_transaction(stmt->db);
		tal_free(stmt);
		return res;
	}

	if (db_step(stmt))
		res = db_column_int(stmt, 0);

	tal_free(stmt);
	return res;
}

/**
 * db_migrate - Apply all remaining migrations from the current version
 */
static void db_migrate(struct lightningd *ld, struct db *db,
		       const struct ext_key *bip32_base)
{
	/* Attempt to read the version from the database */
	int current, orig, available;
	struct db_stmt *stmt;

	orig = current = db_get_version(db);
	available = ARRAY_SIZE(dbmigrations) - 1;

	if (current == -1)
		log_info(db->log, "Creating database");
	else if (available < current)
		db_fatal("Refusing to migrate down from version %u to %u",
			 current, available);
	else if (current != available)
		log_info(db->log, "Updating database from version %u to %u",
			 current, available);

	while (current < available) {
		current++;
		if (dbmigrations[current].sql) {
			struct db_stmt *stmt =
			    db_prepare_v2(db, dbmigrations[current].sql);
			db_exec_prepared_v2(stmt);
			tal_free(stmt);
		}
		if (dbmigrations[current].func)
			dbmigrations[current].func(ld, db, bip32_base);
	}

	/* Finally update the version number in the version table */
	stmt = db_prepare_v2(db, SQL("UPDATE version SET version=?;"));
	db_bind_int(stmt, 0, available);
	db_exec_prepared_v2(stmt);
	tal_free(stmt);

	/* Annotate that we did upgrade, if any. */
	if (current != orig) {
		stmt = db_prepare_v2(
		    db, SQL("INSERT INTO db_upgrades VALUES (?, ?);"));
		db_bind_int(stmt, 0, orig);
		db_bind_text(stmt, 1, version());
		db_exec_prepared_v2(stmt);
		tal_free(stmt);
	}
}

u32 db_data_version_get(struct db *db)
{
	struct db_stmt *stmt;
	u32 version;
	stmt = db_prepare_v2(db, SQL("SELECT intval FROM vars WHERE name = 'data_version'"));
	db_query_prepared(stmt);
	db_step(stmt);
	version = db_column_int(stmt, 0);
	tal_free(stmt);
	return version;
}

struct db *db_setup(const tal_t *ctx, struct lightningd *ld,
		    const struct ext_key *bip32_base)
{
	struct db *db = db_open(ctx, ld->wallet_dsn);
	db->log = new_log(db, ld->log_book, NULL, "database");

	db_begin_transaction(db);

	db_migrate(ld, db, bip32_base);

	db->data_version = db_data_version_get(db);
	db_commit_transaction(db);
	return db;
}

s64 db_get_intvar(struct db *db, char *varname, s64 defval)
{
	s64 res = defval;
	struct db_stmt *stmt = db_prepare_v2(
	    db, SQL("SELECT intval FROM vars WHERE name= ? LIMIT 1"));
	db_bind_text(stmt, 0, varname);
	if (!db_query_prepared(stmt))
		goto done;

	if (db_step(stmt))
		res = db_column_int(stmt, 0);

done:
	tal_free(stmt);
	return res;
}

void db_set_intvar(struct db *db, char *varname, s64 val)
{
	size_t changes;
	struct db_stmt *stmt = db_prepare_v2(db, SQL("UPDATE vars SET intval=? WHERE name=?;"));
	db_bind_int(stmt, 0, val);
	db_bind_text(stmt, 1, varname);
	if (!db_exec_prepared_v2(stmt))
		db_fatal("Error executing update: %s", stmt->error);
	changes = db_count_changes(stmt);
	tal_free(stmt);

	if (changes == 0) {
		stmt = db_prepare_v2(db, SQL("INSERT INTO vars (name, intval) VALUES (?, ?);"));
		db_bind_text(stmt, 0, varname);
		db_bind_int(stmt, 1, val);
		if (!db_exec_prepared_v2(stmt))
			db_fatal("Error executing insert: %s", stmt->error);
		tal_free(stmt);
	}
}

/* Will apply the current config fee settings to all channels */
static void migrate_pr2342_feerate_per_channel(struct lightningd *ld, struct db *db,
					       const struct ext_key *bip32_base)
{
	struct db_stmt *stmt = db_prepare_v2(
	    db, SQL("UPDATE channels SET feerate_base = ?, feerate_ppm = ?;"));

	db_bind_int(stmt, 0, ld->config.fee_base);
	db_bind_int(stmt, 1, ld->config.fee_per_satoshi);

	db_exec_prepared_v2(stmt);
	tal_free(stmt);
}

/* We've added a column `our_funding_satoshis`, since channels can now
 * have funding for either channel participant. We need to 'backfill' this
 * data, however. We can do this using the fact that our_funding_satoshi
 * is the same as the funding_satoshi for every channel where we are
 * the `funder`
 */
static void migrate_our_funding(struct lightningd *ld, struct db *db,
				const struct ext_key *bip32_base)
{
	struct db_stmt *stmt;

	/* Statement to update record */
	stmt = db_prepare_v2(db, SQL("UPDATE channels"
				     " SET our_funding_satoshi = funding_satoshi"
				     " WHERE funder = 0;")); /* 0 == LOCAL */
	db_exec_prepared_v2(stmt);
	if (stmt->error)
		db_fatal("Error migrating funding satoshis to our_funding (%s)",
			 stmt->error);

	tal_free(stmt);
}

void fillin_missing_scriptpubkeys(struct lightningd *ld, struct db *db,
				  const struct ext_key *bip32_base)
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

		type = db_column_int(stmt, 0);
		keyindex = db_column_int(stmt, 1);
		db_column_txid(stmt, 2, &txid);
		outnum = db_column_int(stmt, 3);

		/* This indiciates whether or not we have 'close_info' */
		if (!db_column_is_null(stmt, 4)) {
			struct pubkey *commitment_point;
			struct node_id peer_id;
			u64 channel_id;
			u8 *msg;

			channel_id = db_column_u64(stmt, 4);
			db_column_node_id(stmt, 5, &peer_id);
			if (!db_column_is_null(stmt, 6)) {
				commitment_point = tal(stmt, struct pubkey);
				db_column_pubkey(stmt, 6, commitment_point);
			} else
				commitment_point = NULL;

			/* Have to go ask the HSM to derive the pubkey for us */
			msg = towire_hsm_get_output_scriptpubkey(NULL,
								 channel_id,
								 &peer_id,
								 commitment_point);
			if (!wire_sync_write(ld->hsm_fd, take(msg)))
				fatal("Could not write to HSM: %s", strerror(errno));
			msg = wire_sync_read(stmt, ld->hsm_fd);
			if (!fromwire_hsm_get_output_scriptpubkey_reply(stmt, msg,
									&scriptPubkey))
				fatal("HSM gave bad hsm_get_output_scriptpubkey_reply %s",
				      tal_hex(msg, msg));
		} else {
			/* Build from bip32_base */
			bip32_pubkey(bip32_base, &key, keyindex);
			if (type == p2sh_wpkh) {
				u8 *redeemscript = bitcoin_redeem_p2sh_p2wpkh(stmt, &key);
				scriptPubkey = scriptpubkey_p2sh(tmpctx, redeemscript);
			} else
				scriptPubkey = scriptpubkey_p2wpkh(stmt, &key);
		}

		update_stmt = db_prepare_v2(db, SQL("UPDATE outputs"
						    " SET scriptpubkey = ?"
						    " WHERE prev_out_tx = ? "
						    "   AND prev_out_index = ?"));
		db_bind_blob(update_stmt, 0, scriptPubkey, tal_bytelen(scriptPubkey));
		db_bind_txid(update_stmt, 1, &txid);
		db_bind_int(update_stmt, 2, outnum);
		db_exec_prepared_v2(update_stmt);
		tal_free(update_stmt);
	}

	tal_free(stmt);
}

/* We're moving everything over to PSBTs from tx's, particularly our last_tx's
 * which are commitment transactions for channels.
 * This migration loads all of the last_tx's and 're-formats' them into psbts,
 * adds the required input witness utxo information, and then saves it back to disk
 * */
void migrate_last_tx_to_psbt(struct lightningd *ld, struct db *db,
			     const struct ext_key *bip32_base)
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

		cdb_id = db_column_u64(stmt, 0);
		last_tx = db_column_tx(stmt, stmt, 2);
		assert(last_tx != NULL);

		/* If we've forgotten about the peer_id
		 * because we closed / forgot the channel,
		 * we can skip this. */
		if (db_column_is_null(stmt, 1))
			continue;
		db_column_node_id(stmt, 1, &peer_id);
		db_column_amount_sat(stmt, 3, &funding_sat);
		db_column_pubkey(stmt, 4, &remote_funding_pubkey);

		get_channel_basepoints(ld, &peer_id, cdb_id,
				       &local_basepoints, &local_funding_pubkey);

		funding_wscript = bitcoin_redeem_2of2(stmt, &local_funding_pubkey,
						      &remote_funding_pubkey);

		if (is_elements(chainparams)) {
			/*FIXME: persist asset tags */
			struct amount_asset asset;
			asset = amount_sat_to_asset(&funding_sat,
						    chainparams->fee_asset_tag);
			psbt_elements_input_init_witness(last_tx->psbt,
							 0, funding_wscript,
							 &asset, NULL);
		} else
			psbt_input_set_prev_utxo_wscript(last_tx->psbt,
							 0, funding_wscript,
							 funding_sat);

		if (!db_column_signature(stmt, 5, &last_sig.s))
			abort();

		last_sig.sighash_type = SIGHASH_ALL;
		if (!psbt_input_set_signature(last_tx->psbt, 0,
					      &remote_funding_pubkey, &last_sig))
			abort();
		psbt_input_add_pubkey(last_tx->psbt, 0,
		    &local_funding_pubkey);
		psbt_input_add_pubkey(last_tx->psbt, 0,
		    &remote_funding_pubkey);

		update_stmt = db_prepare_v2(db, SQL("UPDATE channels"
						    " SET last_tx = ?"
						    " WHERE id = ?;"));
		db_bind_psbt(update_stmt, 0, last_tx->psbt);
		db_bind_int(update_stmt, 1, cdb_id);
		db_exec_prepared_v2(update_stmt);
		tal_free(update_stmt);
	}

	tal_free(stmt);
}

void db_bind_null(struct db_stmt *stmt, int pos)
{
	assert(pos < tal_count(stmt->bindings));
	stmt->bindings[pos].type = DB_BINDING_NULL;
}

void db_bind_int(struct db_stmt *stmt, int pos, int val)
{
	assert(pos < tal_count(stmt->bindings));
	memcheck(&val, sizeof(val));
	stmt->bindings[pos].type = DB_BINDING_INT;
	stmt->bindings[pos].v.i = val;
}

void db_bind_u64(struct db_stmt *stmt, int pos, u64 val)
{
	memcheck(&val, sizeof(val));
	assert(pos < tal_count(stmt->bindings));
	stmt->bindings[pos].type = DB_BINDING_UINT64;
	stmt->bindings[pos].v.u64 = val;
}

void db_bind_blob(struct db_stmt *stmt, int pos, const u8 *val, size_t len)
{
	assert(pos < tal_count(stmt->bindings));
	stmt->bindings[pos].type = DB_BINDING_BLOB;
	stmt->bindings[pos].v.blob = memcheck(val, len);
	stmt->bindings[pos].len = len;
}

void db_bind_text(struct db_stmt *stmt, int pos, const char *val)
{
	assert(pos < tal_count(stmt->bindings));
	stmt->bindings[pos].type = DB_BINDING_TEXT;
	stmt->bindings[pos].v.text = val;
	stmt->bindings[pos].len = strlen(val);
}

void db_bind_preimage(struct db_stmt *stmt, int pos, const struct preimage *p)
{
	db_bind_blob(stmt, pos, p->r, sizeof(struct preimage));
}

void db_bind_sha256(struct db_stmt *stmt, int pos, const struct sha256 *s)
{
	db_bind_blob(stmt, pos, s->u.u8, sizeof(struct sha256));
}

void db_bind_sha256d(struct db_stmt *stmt, int pos, const struct sha256_double *s)
{
	db_bind_sha256(stmt, pos, &s->sha);
}

void db_bind_secret(struct db_stmt *stmt, int pos, const struct secret *s)
{
	assert(sizeof(s->data) == 32);
	db_bind_blob(stmt, pos, s->data, sizeof(s->data));
}

void db_bind_secret_arr(struct db_stmt *stmt, int col, const struct secret *s)
{
	size_t num = tal_count(s), elsize = sizeof(s->data);
	u8 *ser = tal_arr(stmt, u8, num * elsize);

	for (size_t i = 0; i < num; ++i)
		memcpy(ser + i * elsize, &s[i], elsize);

	db_bind_blob(stmt, col, ser, tal_count(ser));
}

void db_bind_txid(struct db_stmt *stmt, int pos, const struct bitcoin_txid *t)
{
	db_bind_sha256d(stmt, pos, &t->shad);
}

void db_bind_node_id(struct db_stmt *stmt, int pos, const struct node_id *id)
{
	db_bind_blob(stmt, pos, id->k, sizeof(id->k));
}

void db_bind_node_id_arr(struct db_stmt *stmt, int col,
			 const struct node_id *ids)
{
	/* Copy into contiguous array: ARM will add padding to struct node_id! */
	size_t n = tal_count(ids);
	u8 *arr = tal_arr(stmt, u8, n * sizeof(ids[0].k));

	for (size_t i = 0; i < n; ++i) {
		assert(node_id_valid(&ids[i]));
		memcpy(arr + sizeof(ids[i].k) * i,
		       ids[i].k,
		       sizeof(ids[i].k));
	}
	db_bind_blob(stmt, col, arr, tal_count(arr));
}

void db_bind_pubkey(struct db_stmt *stmt, int pos, const struct pubkey *pk)
{
	u8 *der = tal_arr(stmt, u8, PUBKEY_CMPR_LEN);
	pubkey_to_der(der, pk);
	db_bind_blob(stmt, pos, der, PUBKEY_CMPR_LEN);
}

void db_bind_short_channel_id(struct db_stmt *stmt, int col,
			      const struct short_channel_id *id)
{
	char *ser = short_channel_id_to_str(stmt, id);
	db_bind_text(stmt, col, ser);
}

void db_bind_short_channel_id_arr(struct db_stmt *stmt, int col,
				  const struct short_channel_id *id)
{
	u8 *ser = tal_arr(stmt, u8, 0);
	size_t num = tal_count(id);

	for (size_t i = 0; i < num; ++i)
		towire_short_channel_id(&ser, &id[i]);

	db_bind_blob(stmt, col, ser, tal_count(ser));
}

void db_bind_signature(struct db_stmt *stmt, int col,
		       const secp256k1_ecdsa_signature *sig)
{
	u8 *buf = tal_arr(stmt, u8, 64);
	int ret = secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx,
							      buf, sig);
	assert(ret == 1);
	db_bind_blob(stmt, col, buf, 64);
}

void db_bind_timeabs(struct db_stmt *stmt, int col, struct timeabs t)
{
	u64 timestamp =  t.ts.tv_nsec + (((u64) t.ts.tv_sec) * ((u64) NSEC_IN_SEC));
	db_bind_u64(stmt, col, timestamp);
}

void db_bind_tx(struct db_stmt *stmt, int col, const struct wally_tx *tx)
{
	u8 *ser = linearize_wtx(stmt, tx);
	assert(ser);
	db_bind_blob(stmt, col, ser, tal_count(ser));
}

void db_bind_psbt(struct db_stmt *stmt, int col, const struct wally_psbt *psbt)
{
	size_t bytes_written;
	const u8 *ser = psbt_get_bytes(stmt, psbt, &bytes_written);
	assert(ser);
	db_bind_blob(stmt, col, ser, bytes_written);
}

void db_bind_amount_msat(struct db_stmt *stmt, int pos,
			 const struct amount_msat *msat)
{
	db_bind_u64(stmt, pos, msat->millisatoshis); /* Raw: low level function */
}

void db_bind_amount_sat(struct db_stmt *stmt, int pos,
			 const struct amount_sat *sat)
{
	db_bind_u64(stmt, pos, sat->satoshis); /* Raw: low level function */
}

void db_bind_json_escape(struct db_stmt *stmt, int pos,
			 const struct json_escape *esc)
{
	db_bind_text(stmt, pos, esc->s);
}

void db_bind_onionreply(struct db_stmt *stmt, int pos, const struct onionreply *r)
{
	db_bind_blob(stmt, pos, r->contents, tal_bytelen(r->contents));
}

void db_column_preimage(struct db_stmt *stmt, int col,
			struct preimage *preimage)
{
	const u8 *raw;
	size_t size = sizeof(struct preimage);
	assert(db_column_bytes(stmt, col) == size);
	raw = db_column_blob(stmt, col);
	memcpy(preimage, raw, size);
}

void db_column_node_id(struct db_stmt *stmt, int col, struct node_id *dest)
{
	assert(db_column_bytes(stmt, col) == sizeof(dest->k));
	memcpy(dest->k, db_column_blob(stmt, col), sizeof(dest->k));
}

struct node_id *db_column_node_id_arr(const tal_t *ctx, struct db_stmt *stmt,
				      int col)
{
	struct node_id *ret;
	size_t n = db_column_bytes(stmt, col) / sizeof(ret->k);
	const u8 *arr = db_column_blob(stmt, col);
	assert(n * sizeof(ret->k) == (size_t)db_column_bytes(stmt, col));
	ret = tal_arr(ctx, struct node_id, n);

	for (size_t i = 0; i < n; i++)
		memcpy(ret[i].k, arr + i * sizeof(ret[i].k), sizeof(ret[i].k));

	return ret;
}

void db_column_pubkey(struct db_stmt *stmt, int pos, struct pubkey *dest)
{
	bool ok;
	assert(db_column_bytes(stmt, pos) == PUBKEY_CMPR_LEN);
	ok = pubkey_from_der(db_column_blob(stmt, pos), PUBKEY_CMPR_LEN, dest);
	assert(ok);
}

bool db_column_short_channel_id(struct db_stmt *stmt, int col,
				struct short_channel_id *dest)
{
	const char *source = db_column_blob(stmt, col);
	size_t sourcelen = db_column_bytes(stmt, col);
	return short_channel_id_from_str(source, sourcelen, dest);
}

struct short_channel_id *
db_column_short_channel_id_arr(const tal_t *ctx, struct db_stmt *stmt, int col)
{
	const u8 *ser;
	size_t len;
	struct short_channel_id *ret;

	ser = db_column_blob(stmt, col);
	len = db_column_bytes(stmt, col);
	ret = tal_arr(ctx, struct short_channel_id, 0);

	while (len != 0) {
		struct short_channel_id scid;
		fromwire_short_channel_id(&ser, &len, &scid);
		tal_arr_expand(&ret, scid);
	}

	return ret;
}

bool db_column_signature(struct db_stmt *stmt, int col,
			 secp256k1_ecdsa_signature *sig)
{
	assert(db_column_bytes(stmt, col) == 64);
	return secp256k1_ecdsa_signature_parse_compact(
		   secp256k1_ctx, sig, db_column_blob(stmt, col)) == 1;
}

struct timeabs db_column_timeabs(struct db_stmt *stmt, int col)
{
	struct timeabs t;
	u64 timestamp = db_column_u64(stmt, col);
	t.ts.tv_sec = timestamp / NSEC_IN_SEC;
	t.ts.tv_nsec = timestamp % NSEC_IN_SEC;
	return t;

}

struct bitcoin_tx *db_column_tx(const tal_t *ctx, struct db_stmt *stmt, int col)
{
	const u8 *src = db_column_blob(stmt, col);
	size_t len = db_column_bytes(stmt, col);
	return pull_bitcoin_tx(ctx, &src, &len);
}

struct bitcoin_tx *db_column_psbt_to_tx(const tal_t *ctx, struct db_stmt *stmt, int col)
{
	struct wally_psbt *psbt;
	const u8 *src = db_column_blob(stmt, col);
	size_t len = db_column_bytes(stmt, col);
	psbt = psbt_from_bytes(ctx, src, len);
	if (!psbt)
		return NULL;
	return bitcoin_tx_with_psbt(ctx, psbt);
}

void *db_column_arr_(const tal_t *ctx, struct db_stmt *stmt, int col,
			  size_t bytes, const char *label, const char *caller)
{
	size_t sourcelen;
	void *p;

	if (db_column_is_null(stmt, col))
		return NULL;

	sourcelen = db_column_bytes(stmt, col);

	if (sourcelen % bytes != 0)
		db_fatal("%s: column size %zu not a multiple of %s (%zu)",
			 caller, sourcelen, label, bytes);

	p = tal_arr_label(ctx, char, sourcelen, label);
	memcpy(p, db_column_blob(stmt, col), sourcelen);
	return p;
}

void db_column_amount_msat_or_default(struct db_stmt *stmt, int col,
				      struct amount_msat *msat,
				      struct amount_msat def)
{
	if (db_column_is_null(stmt, col))
		*msat = def;
	else
		msat->millisatoshis = db_column_u64(stmt, col); /* Raw: low level function */
}

void db_column_amount_msat(struct db_stmt *stmt, int col,
			   struct amount_msat *msat)
{
	msat->millisatoshis = db_column_u64(stmt, col); /* Raw: low level function */
}

void db_column_amount_sat(struct db_stmt *stmt, int col, struct amount_sat *sat)
{
	sat->satoshis = db_column_u64(stmt, col); /* Raw: low level function */
}

struct json_escape *db_column_json_escape(const tal_t *ctx,
					  struct db_stmt *stmt, int col)
{
	return json_escape_string_(ctx, db_column_blob(stmt, col),
				   db_column_bytes(stmt, col));
}

void db_column_sha256(struct db_stmt *stmt, int col, struct sha256 *sha)
{
	const u8 *raw;
	size_t size = sizeof(struct sha256);
	assert(db_column_bytes(stmt, col) == size);
	raw = db_column_blob(stmt, col);
	memcpy(sha, raw, size);
}

void db_column_sha256d(struct db_stmt *stmt, int col,
		       struct sha256_double *shad)
{
	const u8 *raw;
	size_t size = sizeof(struct sha256_double);
	assert(db_column_bytes(stmt, col) == size);
	raw = db_column_blob(stmt, col);
	memcpy(shad, raw, size);
}

void db_column_secret(struct db_stmt *stmt, int col, struct secret *s)
{
	const u8 *raw;
	assert(db_column_bytes(stmt, col) == sizeof(struct secret));
	raw = db_column_blob(stmt, col);
	memcpy(s, raw, sizeof(struct secret));
}

struct secret *db_column_secret_arr(const tal_t *ctx, struct db_stmt *stmt,
				    int col)
{
	return db_column_arr(ctx, stmt, col, struct secret);
}

void db_column_txid(struct db_stmt *stmt, int pos, struct bitcoin_txid *t)
{
	db_column_sha256d(stmt, pos, &t->shad);
}

struct onionreply *db_column_onionreply(const tal_t *ctx,
					struct db_stmt *stmt, int col)
{
	struct onionreply *r = tal(ctx, struct onionreply);
	r->contents = tal_dup_arr(r, u8,
				  db_column_blob(stmt, col),
				  db_column_bytes(stmt, col), 0);
	return r;
}

bool db_exec_prepared_v2(struct db_stmt *stmt TAKES)
{
	bool ret = stmt->db->config->exec_fn(stmt);

	/* If this was a write we need to bump the data_version upon commit. */
	stmt->db->dirty = stmt->db->dirty || !stmt->query->readonly;

	stmt->executed = true;
	list_del_from(&stmt->db->pending_statements, &stmt->list);

	/* The driver itself doesn't call `fatal` since we want to override it
	 * for testing. Instead we check here that the error message is set if
	 * we report an error. */
	if (!ret) {
		assert(stmt->error);
		db_fatal("Error executing statement: %s", stmt->error);
	}

	if (taken(stmt))
	    tal_free(stmt);

	return ret;
}

bool db_query_prepared(struct db_stmt *stmt)
{
	/* Make sure we don't accidentally execute a modifying query using a
	 * read-only path. */
	bool ret;
	assert(stmt->query->readonly);
	ret = stmt->db->config->query_fn(stmt);
	stmt->executed = true;
	list_del_from(&stmt->db->pending_statements, &stmt->list);
	return ret;
}

void db_changes_add(struct db_stmt *stmt, const char * expanded)
{
	struct db *db = stmt->db;

	if (stmt->query->readonly) {
		return;
	}
	/* We get a "COMMIT;" after we've sent our changes. */
	if (!db->changes) {
		assert(streq(expanded, "COMMIT;"));
		return;
	}

	tal_arr_expand(&db->changes, tal_strdup(db->changes, expanded));
}

const char **db_changes(struct db *db)
{
	return db->changes;
}
