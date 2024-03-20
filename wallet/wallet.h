#ifndef LIGHTNING_WALLET_WALLET_H
#define LIGHTNING_WALLET_WALLET_H

#include "config.h"
#include "db.h"
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/rune/rune.h>
#include <common/htlc.h>
#include <common/htlc_state.h>
#include <common/onion_encode.h>
#include <common/penalty_base.h>
#include <common/utxo.h>
#include <common/wallet.h>
#include <lightningd/bitcoind.h>
#include <lightningd/channel_state.h>
#include <lightningd/forwards.h>
#include <lightningd/log.h>
#include <lightningd/wait.h>

struct amount_msat;
struct invoices;
struct channel;
struct channel_inflight;
struct htlc_in;
struct htlc_in_map;
struct htlc_out;
struct htlc_out_map;
struct json_escape;
struct lightningd;
struct node_id;
struct oneshot;
struct peer;
struct timers;
struct local_anchor_info;

struct wallet {
	struct lightningd *ld;
	struct db *db;
	struct logger *log;
	struct invoices *invoices;
	u64 max_channel_dbid;

	/* Filter matching all outpoints corresponding to our owned outputs,
	 * including all spent ones */
	struct outpointfilter *owned_outpoints;

	/* Filter matching all outpoints that might be a funding transaction on
	 * the blockchain. This is currently all P2WSH outputs */
	struct outpointfilter *utxoset_outpoints;

	/* How many keys should we look ahead at most? */
	u64 keyscan_gap;
};

static inline enum output_status output_status_in_db(enum output_status s)
{
	switch (s) {
	case OUTPUT_STATE_AVAILABLE:
		BUILD_ASSERT(OUTPUT_STATE_AVAILABLE == 0);
		return s;
	case OUTPUT_STATE_RESERVED:
		BUILD_ASSERT(OUTPUT_STATE_RESERVED == 1);
		return s;
	case OUTPUT_STATE_SPENT:
		BUILD_ASSERT(OUTPUT_STATE_SPENT == 2);
		return s;
	/* This one doesn't go into db */
	case OUTPUT_STATE_ANY:
		break;
	}
	fatal("%s: %u is invalid", __func__, s);
}

/* Enumeration of all known output types. These include all types that
 * could ever end up on-chain and we may need to react upon. Notice
 * that `to_local`, `htlc_offer`, and `htlc_recv` may need immediate
 * action since they are encumbered with a CSV. */
/* /!\ This is a DB ENUM, please do not change the numbering of any
 * already defined elements (adding is ok) /!\ */
enum wallet_output_type {
	p2sh_wpkh = 0,
	to_local = 1,
	htlc_offer = 3,
	htlc_recv = 4,
	our_change = 5,
	p2wpkh = 6
};

static inline enum wallet_output_type wallet_output_type_in_db(enum wallet_output_type w)
{
	switch (w) {
	case p2sh_wpkh:
		BUILD_ASSERT(p2sh_wpkh == 0);
		return w;
	case to_local:
		BUILD_ASSERT(to_local == 1);
		return w;
	case htlc_offer:
		BUILD_ASSERT(htlc_offer == 3);
		return w;
	case htlc_recv:
		BUILD_ASSERT(htlc_recv == 4);
		return w;
	case our_change:
		BUILD_ASSERT(our_change == 5);
		return w;
	case p2wpkh:
		BUILD_ASSERT(p2wpkh == 6);
		return w;
	}
	fatal("%s: %u is invalid", __func__, w);
}

static inline enum forward_status wallet_forward_status_in_db(enum forward_status s)
{
	switch (s) {
	case FORWARD_OFFERED:
		BUILD_ASSERT(FORWARD_OFFERED == 0);
		return s;
	case FORWARD_SETTLED:
		BUILD_ASSERT(FORWARD_SETTLED == 1);
		return s;
	case FORWARD_FAILED:
		BUILD_ASSERT(FORWARD_FAILED == 2);
		return s;
	case FORWARD_LOCAL_FAILED:
		BUILD_ASSERT(FORWARD_LOCAL_FAILED == 3);
		return s;
	case FORWARD_ANY:
		break;
	}
	fatal("%s: %u is invalid", __func__, s);
}

/* Wrapper to ensure types don't change, and we don't insert/extract
 * invalid ones from db */
static inline enum forward_style forward_style_in_db(enum forward_style o)
{
	switch (o) {
	case FORWARD_STYLE_LEGACY:
		BUILD_ASSERT(FORWARD_STYLE_LEGACY == 0);
		return o;
	case FORWARD_STYLE_TLV:
		BUILD_ASSERT(FORWARD_STYLE_TLV == 1);
		return o;
	case FORWARD_STYLE_UNKNOWN:
		/* Not recorded in DB! */
		break;
	}
	fatal("%s: %u is invalid", __func__, o);
}

/* DB wrapper to check htlc_state */
static inline enum htlc_state htlc_state_in_db(enum htlc_state s)
{
	switch (s) {
	case SENT_ADD_HTLC:
		BUILD_ASSERT(SENT_ADD_HTLC == 0);
		return s;
	case SENT_ADD_COMMIT:
		BUILD_ASSERT(SENT_ADD_COMMIT == 1);
		return s;
	case RCVD_ADD_REVOCATION:
		BUILD_ASSERT(RCVD_ADD_REVOCATION == 2);
		return s;
	case RCVD_ADD_ACK_COMMIT:
		BUILD_ASSERT(RCVD_ADD_ACK_COMMIT == 3);
		return s;
	case SENT_ADD_ACK_REVOCATION:
		BUILD_ASSERT(SENT_ADD_ACK_REVOCATION == 4);
		return s;
	case RCVD_REMOVE_HTLC:
		BUILD_ASSERT(RCVD_REMOVE_HTLC == 5);
		return s;
	case RCVD_REMOVE_COMMIT:
		BUILD_ASSERT(RCVD_REMOVE_COMMIT == 6);
		return s;
	case SENT_REMOVE_REVOCATION:
		BUILD_ASSERT(SENT_REMOVE_REVOCATION == 7);
		return s;
	case SENT_REMOVE_ACK_COMMIT:
		BUILD_ASSERT(SENT_REMOVE_ACK_COMMIT == 8);
		return s;
	case RCVD_REMOVE_ACK_REVOCATION:
		BUILD_ASSERT(RCVD_REMOVE_ACK_REVOCATION == 9);
		return s;
	case RCVD_ADD_HTLC:
		BUILD_ASSERT(RCVD_ADD_HTLC == 10);
		return s;
	case RCVD_ADD_COMMIT:
		BUILD_ASSERT(RCVD_ADD_COMMIT == 11);
		return s;
	case SENT_ADD_REVOCATION:
		BUILD_ASSERT(SENT_ADD_REVOCATION == 12);
		return s;
	case SENT_ADD_ACK_COMMIT:
		BUILD_ASSERT(SENT_ADD_ACK_COMMIT == 13);
		return s;
	case RCVD_ADD_ACK_REVOCATION:
		BUILD_ASSERT(RCVD_ADD_ACK_REVOCATION == 14);
		return s;
	case SENT_REMOVE_HTLC:
		BUILD_ASSERT(SENT_REMOVE_HTLC == 15);
		return s;
	case SENT_REMOVE_COMMIT:
		BUILD_ASSERT(SENT_REMOVE_COMMIT == 16);
		return s;
	case RCVD_REMOVE_REVOCATION:
		BUILD_ASSERT(RCVD_REMOVE_REVOCATION == 17);
		return s;
	case RCVD_REMOVE_ACK_COMMIT:
		BUILD_ASSERT(RCVD_REMOVE_ACK_COMMIT == 18);
		return s;
	case SENT_REMOVE_ACK_REVOCATION:
		BUILD_ASSERT(SENT_REMOVE_ACK_REVOCATION == 19);
		return s;
	case HTLC_STATE_INVALID:
		/* Not in db! */
		break;
	}
	fatal("%s: %u is invalid", __func__, s);
}

/* DB wrapper to check channel_state */
static inline enum channel_state channel_state_in_db(enum channel_state s)
{
	switch (s) {
	case CHANNELD_AWAITING_LOCKIN:
		BUILD_ASSERT(CHANNELD_AWAITING_LOCKIN == 2);
		return s;
	case CHANNELD_NORMAL:
		BUILD_ASSERT(CHANNELD_NORMAL == 3);
		return s;
	case CHANNELD_SHUTTING_DOWN:
		BUILD_ASSERT(CHANNELD_SHUTTING_DOWN == 4);
		return s;
	case CLOSINGD_SIGEXCHANGE:
		BUILD_ASSERT(CLOSINGD_SIGEXCHANGE == 5);
		return s;
	case CLOSINGD_COMPLETE:
		BUILD_ASSERT(CLOSINGD_COMPLETE == 6);
		return s;
	case AWAITING_UNILATERAL:
		BUILD_ASSERT(AWAITING_UNILATERAL == 7);
		return s;
	case FUNDING_SPEND_SEEN:
		BUILD_ASSERT(FUNDING_SPEND_SEEN == 8);
		return s;
	case ONCHAIN:
		BUILD_ASSERT(ONCHAIN == 9);
		return s;
	case CLOSED:
		BUILD_ASSERT(CLOSED == 10);
		return s;
	case DUALOPEND_OPEN_COMMITTED:
		BUILD_ASSERT(DUALOPEND_OPEN_COMMITTED == 11);
		return s;
	case DUALOPEND_OPEN_COMMIT_READY:
		BUILD_ASSERT(DUALOPEND_OPEN_COMMIT_READY == 14);
		return s;
	case DUALOPEND_AWAITING_LOCKIN:
		BUILD_ASSERT(DUALOPEND_AWAITING_LOCKIN == 12);
		return s;
	case CHANNELD_AWAITING_SPLICE:
		BUILD_ASSERT(CHANNELD_AWAITING_SPLICE == 13);
		return s;
	case DUALOPEND_OPEN_INIT:
		/* Never appears in db! */
		break;
	}
	fatal("%s: %u is invalid", __func__, s);
}

/* A database backed shachain struct. The datastructure is
 * writethrough, reads are performed from an in-memory version, all
 * writes are passed through to the DB. */
struct wallet_shachain {
	u64 id;
	struct shachain chain;
};

/* Possible states for a payment. Payments start in
 * `PENDING`. Outgoing payments are set to `PAYMENT_COMPLETE` once we
 * get the preimage matching the rhash, or to
 * `PAYMENT_FAILED`. */
/* /!\ This is a DB ENUM, please do not change the numbering of any
 * already defined elements (adding is ok but you should append the
 * test case test_payment_status_enum() ) /!\ */
enum payment_status {
	PAYMENT_PENDING = 0,
	PAYMENT_COMPLETE = 1,
	PAYMENT_FAILED = 2
};

struct tx_annotation {
	enum wallet_tx_type type;
	struct short_channel_id channel;
};

static inline enum payment_status payment_status_in_db(enum payment_status w)
{
	switch (w) {
	case PAYMENT_PENDING:
		BUILD_ASSERT(PAYMENT_PENDING == 0);
		return w;
	case PAYMENT_COMPLETE:
		BUILD_ASSERT(PAYMENT_COMPLETE == 1);
		return w;
	case PAYMENT_FAILED:
		BUILD_ASSERT(PAYMENT_FAILED == 2);
		return w;
	}
	fatal("%s: %u is invalid", __func__, w);
}

/* Outgoing payments. A simple persisted representation
 * of a payment we initiated. This can be used by
 * a UI (alongside invoices) to display the balance history.
 */
struct wallet_payment {
	u64 id;
	u32 timestamp;
	u32 *completed_at;

	/* The combination of these three fields is unique: */
	struct sha256 payment_hash;
	u64 partid;
	u64 groupid;

	enum payment_status status;

	u64 updated_index;
	/* The destination may not be known if we used `sendonion` */
	struct node_id *destination;
	struct amount_msat msatoshi;
	struct amount_msat msatoshi_sent;
	struct amount_msat total_msat;
	/* If and only if PAYMENT_COMPLETE */
	struct preimage *payment_preimage;
	/* Needed for recovering from routing failures. */
	struct secret *path_secrets;
	struct node_id *route_nodes;
	struct short_channel_id *route_channels;
	/* bolt11/bolt12 string; NULL for old payments. */
	const char *invstring;

	/* The label of the payment. Must support `tal_len` */
	const char *label;

	/* The description of the payment (used if invstring has hash). */
	const char *description;

	/* If we could not decode the fail onion, just add it here. */
	const u8 *failonion;

	/* If we are associated with an internal invoice_request */
	struct sha256 *local_invreq_id;
};

struct outpoint {
	struct bitcoin_outpoint outpoint;
	u32 blockheight;
	u32 txindex;
	struct amount_sat sat;
	u8 *scriptpubkey;
	u32 spendheight;
};

/* Statistics for a channel */
struct channel_stats {
	u64  in_payments_offered,  in_payments_fulfilled;
	struct amount_msat  in_msatoshi_offered,  in_msatoshi_fulfilled;
	u64 out_payments_offered, out_payments_fulfilled;
	struct amount_msat out_msatoshi_offered, out_msatoshi_fulfilled;
};

struct channeltx {
	u32 channel_id;
	int type;
	u32 blockheight;
	struct bitcoin_txid txid;
	struct bitcoin_tx *tx;
	u32 input_num;
	u32 depth;
};

struct wallet_transaction {
	struct bitcoin_txid id;
	u32 blockheight;
	u32 txindex;
	u8 *rawtx;

	/* Fully parsed transaction */
	const struct bitcoin_tx *tx;
};

/**
 * wallet_new - Constructor for a new DB based wallet
 *
 * This is guaranteed to either return a valid wallet, or abort with
 * `fatal` if it cannot be initialized.
 */
struct wallet *wallet_new(struct lightningd *ld, struct timers *timers);

/**
 * wallet_confirm_tx - Confirm a tx which contains a UTXO.
 */
void wallet_confirm_tx(struct wallet *w,
		       const struct bitcoin_txid *txid,
		       const u32 confirmation_height);

/**
 * wallet_update_output_status - Perform an output state transition
 *
 * Change the current status of an output we are tracking in the
 * database. Returns true if the output exists with the @oldstatus and
 * was successfully updated to @newstatus. May fail if either the
 * output does not exist, or it does not have the expected
 * @oldstatus. In case we don't care about the previous state use
 * `output_state_any` as @oldstatus.
 */
bool wallet_update_output_status(struct wallet *w,
				 const struct bitcoin_outpoint *outpoint,
				 enum output_status oldstatus,
				 enum output_status newstatus);

/**
 * wallet_get_all_utxos - Return all utxos, including spent ones.
 *
 * Returns a `tal_arr` of `utxo` structs. Double indirection in order
 * to be able to steal individual elements onto something else.
 */
struct utxo **wallet_get_all_utxos(const tal_t *ctx, struct wallet *w);

/**
 * wallet_get_unspent_utxos - Return reserved and unreserved UTXOs.
 *
 * Returns a `tal_arr` of `utxo` structs. Double indirection in order
 * to be able to steal individual elements onto something else.
 *
 * Use utxo_is_reserved() to test if it's reserved.
 */
struct utxo **wallet_get_unspent_utxos(const tal_t *ctx, struct wallet *w);


/**
 * wallet_get_unconfirmed_closeinfo_utxos - Retrieve any unconfirmed utxos w/ closeinfo
 *
 * Returns a `tal_arr` of `utxo` structs. Double indirection in order
 * to be able to steal individual elements onto something else.
 */
struct utxo **wallet_get_unconfirmed_closeinfo_utxos(const tal_t *ctx,
						     struct wallet *w);

/**
 * wallet_find_utxo - Select an available UTXO (does not reserve it!).
 * @ctx: tal context
 * @w: wallet
 * @current_blockheight: current chain length.
 * @amount_we_are_short: optional amount.
 * @feerate_per_kw: feerate we are using.
 * @maxheight: zero (if caller doesn't care) or maximum blockheight to accept.
 * @nonwrapped: filter out p2sh-wrapped inputs
 * @excludes: UTXOs not to consider.
 *
 * If @amount_we_are_short is not NULL, we try to get something very close
 * (i.e. when we add this input, we will add => @amount_we_are_short, but
 * less than @amount_we_are_short + dustlimit).
 *
 * Otherwise we give a random UTXO.
 */
struct utxo *wallet_find_utxo(const tal_t *ctx, struct wallet *w,
			      unsigned current_blockheight,
			      struct amount_sat *amount_we_are_short,
			      unsigned feerate_per_kw,
			      u32 maxheight,
			      bool nonwrapped,
			      const struct utxo **excludes);

/**
 * wallet_has_funds: do we have sufficient other UTXOs for this amount?
 * @w: the wallet
 * @excludes: the utxos not to count (tal_arr or NULL)
 * @current_blockheight: current chain length.
 * @needed: the target, reduced if we find some funds
 *
 * This is a gross estimate, since it doesn't take into account the fees we
 * would need to actually spend these utxos!
 */
bool wallet_has_funds(struct wallet *wallet,
		      const struct utxo **excludes,
		      u32 current_blockheight,
		      struct amount_sat *needed);

/**
 * wallet_add_onchaind_utxo - Add a UTXO with spending info from onchaind.
 *
 * Usually we add UTXOs by looking at transactions, but onchaind tells
 * us about other UTXOs we can spend with some extra metadata.
 *
 * Returns false if we already have it in db (that's fine).
 */
bool wallet_add_onchaind_utxo(struct wallet *w,
			      const struct bitcoin_outpoint *outpoint,
			      const u8 *scriptpubkey,
			      u32 blockheight,
			      struct amount_sat amount,
			      const struct channel *chan,
			      /* NULL if option_static_remotekey */
			      const struct pubkey *commitment_point,
			      /* option_will_fund makes the csv_lock variable */
			      u32 csv_lock);

/**
 * wallet_reserve_utxo - set a reservation on a UTXO.
 *
 * If the reservation is already reserved:
 *   refreshes the reservation by @reserve, return true.
 * Otherwise if it's available:
 *   reserves until @current_height + @reserve, returns true.
 * Otherwise:
 *   returns false.
 */
bool wallet_reserve_utxo(struct wallet *w,
			 struct utxo *utxo,
			 u32 current_height,
			 u32 reserve);

/* wallet_unreserve_utxo - make a reserved UTXO available again.
 *
 * Must be reserved.
 */
void wallet_unreserve_utxo(struct wallet *w, struct utxo *utxo,
			   u32 current_height, u32 unreserve);

/** wallet_utxo_get - Retrive a utxo.
 *
 * Returns a utxo, or NULL if not found.
 */
struct utxo *wallet_utxo_get(const tal_t *ctx, struct wallet *w,
			     const struct bitcoin_outpoint *outpoint);

/**
 * wallet_utxo_boost - get (unreserved) utxos to meet a given feerate.
 * @ctx: context to tal return array from
 * @w: the wallet
 * @blockheight: current height (to determine reserved status)
 * @fee_amount: amount already paying in fees
 * @feerate_target: feerate we want, in perkw.
 * @weight: (in)existing weight before any utxos added, (out)final weight with utxos added.
 *
 * May not meet the feerate, but will spend all available utxos to try.
 * You may also need to create change, as it may exceed.
 */
struct utxo **wallet_utxo_boost(const tal_t *ctx,
				struct wallet *w,
				u32 blockheight,
				struct amount_sat fee_amount,
				u32 feerate_target,
				size_t *weight);

/**
 * wallet_can_spend - Do we have the private key matching this scriptpubkey?
 *
 * FIXME: This is very slow with lots of inputs!
 *
 * @w: (in) wallet holding the pubkeys to check against (privkeys are on HSM)
 * @script: (in) the script to check
 * @index: (out) the bip32 derivation index that matched the script
 */
bool wallet_can_spend(struct wallet *w,
		      const u8 *script,
		      u32 *index);

/**
 * wallet_get_newindex - get a new index from the wallet.
 * @ld: (in) lightning daemon
 *
 * Returns -1 on error (key exhaustion).
 */
s64 wallet_get_newindex(struct lightningd *ld);

/**
 * wallet_shachain_add_hash -- wallet wrapper around shachain_add_hash
 */
bool wallet_shachain_add_hash(struct wallet *wallet,
			      struct wallet_shachain *chain,
			      uint64_t index,
			      const struct secret *hash);

/**
 * wallet_get_uncommitted_channel_dbid -- get a unique channel dbid
 *
 * @wallet: the wallet
 */
u64 wallet_get_channel_dbid(struct wallet *wallet);

void wallet_htlcsigs_confirm_inflight(struct wallet *w, struct channel *chan,
				      const struct bitcoin_outpoint *confirmed_outpoint);

/**
 * wallet_channel_save -- Upsert the channel into the database
 *
 * @wallet: the wallet to save into
 * @chan: the instance to store (not const so we can update the unique_id upon
 *   insert)
 */
void wallet_channel_save(struct wallet *w, struct channel *chan);

/**
 * wallet_channel_insert -- Insert the initial channel into the database
 *
 * @wallet: the wallet to save into
 * @chan: the instance to store
 */
void wallet_channel_insert(struct wallet *w, struct channel *chan);

/**
 * Save an inflight transaction for a channel
 */
void wallet_inflight_add(struct wallet *w, struct channel_inflight *inflight);

/**
 * Delete an inflight transaction for a channel
 */
void wallet_inflight_del(struct wallet *w, const struct channel *chan,
			 const struct channel_inflight *inflight);

/**
 * Update an existing inflight channel transaction
 */
void wallet_inflight_save(struct wallet *w,
			  struct channel_inflight *inflight);

/**
 * Remove any channel inflights that are incomplete.
 */
void wallet_channel_inflight_cleanup_incomplete(struct wallet *w,
						u64 wallet_id);

/**
 * Remove all the inflights from a channel. Also cleans up
 * the channel's inflight list
 */
void wallet_channel_clear_inflights(struct wallet *w,
				    struct channel *chan);
/**
 * After fully resolving a channel, only keep a lightweight stub
 */
void wallet_channel_close(struct wallet *w, u64 wallet_id);

/**
 * Adds a channel state change history entry into the database
 */
void wallet_state_change_add(struct wallet *w,
			     const u64 channel_id,
			     struct timeabs timestamp,
			     enum channel_state old_state,
			     enum channel_state new_state,
			     enum state_change cause,
			     const char *message);

/**
 * Gets all state change history entries for a channel from the database
 */
struct state_change_entry *wallet_state_change_get(const tal_t *ctx,
						   struct wallet *w,
						   u64 channel_id);

/**
 * wallet_delete_peer_if_unused -- After no more channels in peer, forget about it
 */
void wallet_delete_peer_if_unused(struct wallet *w, u64 peer_dbid);

/**
 * wallet_init_channels -- Loads active channels into peers
 *    and inits the dbid counter for next channel.
 *
 *    @w: wallet to load from
 *
 * Be sure to call this only once on startup since it'll append peers
 * loaded from the database to the list without checking.
 */
bool wallet_init_channels(struct wallet *w);

/**
 * wallet_load_closed_channels -- Loads dead channels.
 * @ctx: context to allocate returned array from
 * @w: wallet to load from
 *
 * These will be all state CLOSED.
 */
struct closed_channel **wallet_load_closed_channels(const tal_t *ctx,
						    struct wallet *w);

/**
 * wallet_channel_stats_incr_* - Increase channel statistics.
 *
 * @w: wallet containing the channel
 * @cdbid: channel database id
 * @msatoshi: amount in msatoshi being transferred
 */
void wallet_channel_stats_incr_in_offered(struct wallet *w, u64 cdbid, struct amount_msat msatoshi);
void wallet_channel_stats_incr_in_fulfilled(struct wallet *w, u64 cdbid, struct amount_msat msatoshi);
void wallet_channel_stats_incr_out_offered(struct wallet *w, u64 cdbid, struct amount_msat msatoshi);
void wallet_channel_stats_incr_out_fulfilled(struct wallet *w, u64 cdbid, struct amount_msat msatoshi);

/**
 * wallet_channel_stats_load - Load channel statistics
 *
 * @w: wallet containing the channel
 * @cdbid: channel database id
 * @stats: location to load statistics to
 */
void wallet_channel_stats_load(struct wallet *w, u64 cdbid, struct channel_stats *stats);

/**
 * Retrieve the blockheight of the last block processed by lightningd.
 *
 * Will set min/max either the minimal/maximal blockheight or the default value
 * if the wallet was never used before.
 *
 * @w: wallet to load from.
 * @def: the default value to return if we've never used the wallet before
 * @min(out): height of the first block we track
 * @max(out): height of the last block we added
 */
void wallet_blocks_heights(struct wallet *w, u32 def, u32 *min, u32 *max);

/**
 * wallet_extract_owned_outputs - given a tx, extract all of our outputs
 */
int wallet_extract_owned_outputs(struct wallet *w, const struct wally_tx *tx,
				 bool is_coinbase,
				 const u32 *blockheight,
				 struct amount_sat *total);

/**
 * wallet_htlc_save_in - store an htlc_in in the database
 *
 * @wallet: wallet to store the htlc into
 * @chan: the channel this HTLC is associated with
 * @in: the htlc_in to store
 *
 * This will store the contents of the `struct htlc_in` in the
 * database. Since `struct htlc_in` commonly only change state after
 * being created we do not support updating arbitrary fields and this
 * function will fail when attempting to call it multiple times for
 * the same `struct htlc_in`. Instead `wallet_htlc_update` may be used
 * for state transitions or to set the `payment_key` for completed
 * HTLCs.
 */
void wallet_htlc_save_in(struct wallet *wallet,
			 const struct channel *chan, struct htlc_in *in);

/**
 * wallet_htlc_save_out - store an htlc_out in the database
 *
 * See comment for wallet_htlc_save_in.
 */
void wallet_htlc_save_out(struct wallet *wallet,
			  const struct channel *chan,
			  struct htlc_out *out);

/**
 * wallet_htlc_update - perform state transition or add payment_key
 *
 * @wallet: the wallet containing the HTLC to update
 * @htlc_dbid: the database ID used to identify the HTLC
 * @new_state: the state we should transition to
 * @payment_key: the `payment_key` which hashes to the `payment_hash`,
 *   or NULL if unknown.
 * @max_commit_num: maximum of local and remote commitment numbers.
 * @badonion: the current BADONION failure code, or 0.
 * @failonion: the current failure onion message (from peer), or NULL.
 * @failmsg: the current local failure message, or NULL.
 * @we_filled: for htlc-ins, true if we originated the preimage.
 *
 * Used to update the state of an HTLC, either a `struct htlc_in` or a
 * `struct htlc_out` and optionally set the `payment_key` should the
 * HTLC have been settled, or `failcode`/`failonion` if failed.
 */
void wallet_htlc_update(struct wallet *wallet, const u64 htlc_dbid,
			const enum htlc_state new_state,
			const struct preimage *payment_key,
			u64 max_commit_num,
			enum onion_wire badonion,
			const struct onionreply *failonion,
			const u8 *failmsg,
			bool *we_filled);

/**
 * wallet_htlcs_load_in_for_channel - Load incoming HTLCs associated with chan from DB.
 *
 * @wallet: wallet to load from
 * @chan: load HTLCs associated with this channel
 * @htlcs_in: htlc_in_map to store loaded htlc_in in
 *
 * This function looks for incoming HTLCs that are associated with the given
 * channel and loads them into the provided map.
 */
bool wallet_htlcs_load_in_for_channel(struct wallet *wallet,
				      struct channel *chan,
				      struct htlc_in_map *htlcs_in);

/**
 * wallet_htlcs_load_out_for_channel - Load outgoing HTLCs associated with chan from DB.
 *
 * @wallet: wallet to load from
 * @chan: load HTLCs associated with this channel
 * @htlcs_out: htlc_out_map to store loaded htlc_out in.
 * @remaining_htlcs_in: htlc_in_map with unconnected htlcs (removed as we progress)
 *
 * We populate htlc_out->in by looking up in remaining_htlcs_in.  It's
 * possible that it's still NULL, since we can have outgoing HTLCs
 * outlive their corresponding incoming.
 */
bool wallet_htlcs_load_out_for_channel(struct wallet *wallet,
				       struct channel *chan,
				       struct htlc_out_map *htlcs_out,
				       struct htlc_in_map *remaining_htlcs_in);

/**
 * wallet_announcement_save - Save remote announcement information with channel.
 *
 * @wallet: wallet to load from
 * @id: channel database id
 * @remote_ann_node_sig: location to load remote_ann_node_sig to
 * @remote_ann_bitcoin_sig: location to load remote_ann_bitcoin_sig to
 *
 * This function is only used to save REMOTE announcement information into DB
 * when the channel has set the announce_channel bit and don't send the shutdown
 * message(BOLT#7).
 */
void wallet_announcement_save(struct wallet *wallet, u64 id,
			      secp256k1_ecdsa_signature *remote_ann_node_sig,
			      secp256k1_ecdsa_signature *remote_ann_bitcoin_sig);

/* /!\ This is a DB ENUM, please do not change the numbering of any
 * already defined elements (adding is ok) /!\ */
enum invoice_status {
	UNPAID,
	PAID,
	EXPIRED,
};

static inline enum invoice_status invoice_status_in_db(enum invoice_status s)
{
	switch (s) {
	case UNPAID:
		BUILD_ASSERT(UNPAID == 0);
		return s;
	case PAID:
		BUILD_ASSERT(PAID == 1);
		return s;
	case EXPIRED:
		BUILD_ASSERT(EXPIRED == 2);
		return s;
	}
	fatal("%s: %u is invalid", __func__, s);
}

/**
 * wallet_htlc_stubs - Retrieve HTLC stubs for the given channel
 *
 * Load minimal necessary information about HTLCs for the on-chain
 * settlement. This returns a `tal_arr` allocated off of @ctx with the
 * necessary size to hold all HTLCs.
 *
 * @ctx: Allocation context for the return value
 * @wallet: Wallet to load from
 * @chan: Channel to fetch stubs for
 * @commit_num: The commitment number of the commit tx.
 */
struct htlc_stub *wallet_htlc_stubs(const tal_t *ctx, struct wallet *wallet,
				    struct channel *chan, u64 commit_num);

/**
 * wallet_add_payment - Store this payment in the db
 * @ctx: context to allocate returned `struct wallet_payment` off.
 * @wallet: wallet we're going to store it in.
 * @...: the details
 */
struct wallet_payment *wallet_add_payment(const tal_t *ctx,
					  struct wallet *wallet,
					  u32 timestamp,
					  const u32 *completed_at,
					  const struct sha256 *payment_hash,
					  u64 partid,
					  u64 groupid,
					  enum payment_status status,
					  /* The destination may not be known if we used `sendonion` */
					  const struct node_id *destination TAKES,
					  struct amount_msat msatoshi,
					  struct amount_msat msatoshi_sent,
					  struct amount_msat total_msat,
					  /* If and only if PAYMENT_COMPLETE */
					  const struct preimage *payment_preimage TAKES,
					  const struct secret *path_secrets TAKES,
					  const struct node_id *route_nodes TAKES,
					  const struct short_channel_id *route_channels TAKES,
					  const char *invstring TAKES,
					  const char *label TAKES,
					  const char *description TAKES,
					  const u8 *failonion TAKES,
					  const struct sha256 *local_invreq_id);

/**
 * wallet_payment_delete - Remove a payment
 *
 * Removes the payment from the database by hash; groupid and partid
 * may both be NULL to delete all entries, otherwise deletes only that
 * group/partid.
 */
void wallet_payment_delete(struct wallet *wallet,
			   const struct sha256 *payment_hash,
			   const u64 *groupid, const u64 *partid,
			   const enum payment_status *status);

/**
 * wallet_local_htlc_out_delete - Remove a local outgoing failed HTLC
 *
 * This is not a generic HTLC cleanup!  This is specifically for the
 * narrow (and simple!) case of removing the HTLC associated with a
 * local outgoing payment.
 */
void wallet_local_htlc_out_delete(struct wallet *wallet,
				  struct channel *chan,
				  const struct sha256 *payment_hash,
				  u64 partid);

/**
 * wallet_payment_by_hash - Retrieve a specific payment
 *
 * Given the `payment_hash` retrieve the matching payment.
 */
struct wallet_payment *
wallet_payment_by_hash(const tal_t *ctx, struct wallet *wallet,
		       const struct sha256 *payment_hash,
		       u64 partid, u64 groupid);

/**
 * Retrieve maximum groupid for a given payment_hash.
 *
 * Useful to either wait on the latest payment that was iniated with
 * the hash or start a new one by incrementing the groupid.
 */
u64 wallet_payment_get_groupid(struct wallet *wallet,
			       const struct sha256 *payment_hash);

/**
 * wallet_payment_set_status - Update the status of the payment
 *
 * Search for the payment with the given `payment_hash` and update
 * its state.
 */
void wallet_payment_set_status(struct wallet *wallet,
			       const struct sha256 *payment_hash,
			       u64 partid, u64 groupid,
			       const enum payment_status newstatus,
			       const struct preimage *preimage);

/**
 * wallet_payment_get_failinfo - Get failure information for a given
 * `payment_hash`.
 *
 * Data is allocated as children of the given context. *faildirection
 * is only set if *failchannel is set non-NULL.
 */
void wallet_payment_get_failinfo(const tal_t *ctx,
				 struct wallet *wallet,
				 const struct sha256 *payment_hash,
				 u64 partid,
				 u64 groupid,
				 /* outputs */
				 struct onionreply **failonionreply,
				 bool *faildestperm,
				 int *failindex,
				 enum onion_wire *failcode,
				 struct node_id **failnode,
				 struct short_channel_id **failchannel,
				 u8 **failupdate,
				 char **faildetail,
				 int *faildirection);
/**
 * wallet_payment_set_failinfo - Set failure information for a given
 * `payment_hash`.
 */
void wallet_payment_set_failinfo(struct wallet *wallet,
				 const struct sha256 *payment_hash,
				 u64 partid,
				 const struct onionreply *failonionreply,
				 bool faildestperm,
				 int failindex,
				 enum onion_wire failcode,
				 const struct node_id *failnode,
				 const struct short_channel_id *failchannel,
				 const u8 *failupdate,
				 const char *faildetail,
				 int faildirection);

/**
 * payments_first: get first payment, optionally filtering by status
 * @w: the wallet
 * @listindex: what index order to use (if you care)
 * @liststart: first index to return (0 == all).
 * @listlimit: limit on number of entries to return (NULL == no limit).
 *
 * Returns NULL if none, otherwise you must call payments_next() or
 * tal_free(stmt).
 */
struct db_stmt *payments_first(struct wallet *w,
			       const enum wait_index *listindex,
			       u64 liststart,
			       const u32 *listlimit);

/**
 * payments_next: get next payment
 * @w: the wallet
 * @stmt: the previous stmt from payments_first or payments_next.
 *
 * Returns NULL if none, otherwise you must call payments_next() or
 * tal_free(stmt).
 */
struct db_stmt *payments_next(struct wallet *w,
			      struct db_stmt *stmt);


/**
 * payments_by_hash: get the payment, if any, by payment_hash.
 * @w: the wallet
 * @payment_hash: the payment_hash.
 *
 * Returns NULL if none, otherwise call payments_get_details(),
 * and then tal_free(stmt).
 */
struct db_stmt *payments_by_hash(struct wallet *w,
				 const struct sha256 *payment_hash);

/**
 * payments_by_status: get the payments, if any, by status.
 * @w: the wallet
 * @status: the status.
 * @listindex: what index order to use (if you care)
 * @liststart: first index to return (0 == all).
 * @listlimit: limit on number of entries to return (NULL == no limit).
 *
 * Returns NULL if none, otherwise call payments_get_details(),
 * and then tal_free(stmt).
 */
struct db_stmt *payments_by_status(struct wallet *w,
				   enum payment_status status,
				   const enum wait_index *listindex,
				   u64 liststart,
				   const u32 *listlimit);

/**
 * payments_by_label: get the payment, if any, by label.
 * @w: the wallet
 * @label: the label.
 *
 * Returns NULL if none, otherwise call payments_get_details(),
 * and then tal_free(stmt).
 */
struct db_stmt *payments_by_label(struct wallet *w,
				  const struct json_escape *label);

/**
 * payments_by_invoice_request: get payments, if any, for this local_invreq_id
 * @w: the wallet
 * @local_invreq_id: the local invreq_id.
 *
 * Returns NULL if none, otherwise you must call payments_next() or
 * tal_free(stmt).
 */
struct db_stmt *payments_by_invoice_request(struct wallet *wallet,
					    const struct sha256 *local_invreq_id);

/**
 * payments_get_details: get the details of a payment.
 */
struct wallet_payment *payment_get_details(const tal_t *ctx,
					   struct db_stmt *stmt);


/**
 * wallet_htlc_sigs_save - Delete all HTLC sigs (including inflights) for the
 * channel and store `htlc_sigs` as the new values.
 */
void wallet_htlc_sigs_save(struct wallet *w, u64 channel_id,
			   const struct bitcoin_signature *htlc_sigs);

/**
 * wallet_htlc_sigs_add - Appends `htlc_sigs` for the given inflight splice.
 * `inflight_id` is the funding txid for the given splice.
 */
void wallet_htlc_sigs_add(struct wallet *w, u64 channel_id,
			  struct bitcoin_outpoint inflight_outpoint,
			  const struct bitcoin_signature *htlc_sigs);

/**
 * wallet_sanity_check - Check that the wallet is setup for this node_id and chain
 *
 * Ensure that the genesis_hash from the chainparams matches the
 * genesis_hash with which the DB was initialized, and that the HSM
 * gave us the same node_id as the one is the db.
 *
 * Returns false if the checks failed.
 */
bool wallet_sanity_check(struct wallet *w);

/**
 * wallet_block_add - Add a block to the blockchain tracked by this wallet
 */
void wallet_block_add(struct wallet *w, struct block *b);

/**
 * wallet_block_remove - Remove a block (and all its descendants) from the tracked blockchain
 */
void wallet_block_remove(struct wallet *w, struct block *b);

/**
 * wallet_blocks_rollback - Roll the blockchain back to the given height
 */
void wallet_blocks_rollback(struct wallet *w, u32 height);

/**
 * Return whether we have a block for the given height.
 */
bool wallet_have_block(struct wallet *w, u32 blockheight);

/**
 * Mark an outpoint as spent, both in the owned as well as the UTXO set
 *
 * Given the outpoint (txid, outnum), and the blockheight, mark the
 * corresponding DB entries as spent at the blockheight.
 *
 * @return true if found in our wallet's output set, false otherwise
 */
bool wallet_outpoint_spend(const tal_t *ctx, struct wallet *w,
			   const u32 blockheight,
			   const struct bitcoin_outpoint *outpoint);

struct outpoint *wallet_outpoint_for_scid(const tal_t *ctx, struct wallet *w,
					  const struct short_channel_id *scid);

void wallet_utxoset_add(struct wallet *w,
			const struct bitcoin_outpoint *outpoint,
			const u32 blockheight, const u32 txindex,
			const u8 *scriptpubkey, size_t scriptpubkey_len,
			struct amount_sat sat);

/**
 * Retrieve all UTXO entries that were spent by the given blockheight.
 *
 * This allows us to retrieve any UTXO entries that were spent by a block,
 * after the block has been processed. It's main use is to be able to tell
 * `gossipd` about potential channel outpoints being spent, without having to
 * track all outpoints in memory.
 *
 * In order to return correct results `blockheight` should not be called with
 * a height below the UTXO set pruning height (see `UTXO_PRUNE_DEPTH` for the
 * current value).
 */
const struct short_channel_id *
wallet_utxoset_get_spent(const tal_t *ctx, struct wallet *w, u32 blockheight);

/**
 * Retrieve all UTXO entries that were created at a given blockheight.
 */
const struct short_channel_id *
wallet_utxoset_get_created(const tal_t *ctx, struct wallet *w, u32 blockheight);

void wallet_transaction_add(struct wallet *w, const struct wally_tx *tx,
			    const u32 blockheight, const u32 txindex);

void wallet_annotate_txout(struct wallet *w,
			   const struct bitcoin_outpoint *outpoint,
			   enum wallet_tx_type type, u64 channel);

void wallet_annotate_txin(struct wallet *w, const struct bitcoin_txid *txid,
			  int innum, enum wallet_tx_type type, u64 channel);

/**
 * Get the transaction from the database
 *
 * Looks up a transaction we have in the database and returns it, or NULL if
 * not found.
 */
struct bitcoin_tx *wallet_transaction_get(const tal_t *ctx, struct wallet *w,
					  const struct bitcoin_txid *txid);

/**
 * Get the confirmation height of a transaction we are watching by its
 * txid. Returns 0 if the transaction was not part of any block.
 */
u32 wallet_transaction_height(struct wallet *w, const struct bitcoin_txid *txid);

/**
 * Locate a transaction in the blockchain, returns NULL if the transaction is
 * not tracked or is not yet confirmed.
 */
struct txlocator *wallet_transaction_locate(const tal_t *ctx, struct wallet *w,
					    const struct bitcoin_txid *txid);

/**
 * Get transaction IDs for transactions that we are tracking.
 */
struct bitcoin_txid *wallet_transactions_by_height(const tal_t *ctx,
						   struct wallet *w,
						   const u32 blockheight);

/**
 * Store transactions of interest in the database to replay on restart
 */
void wallet_channeltxs_add(struct wallet *w, struct channel *chan,
			    const int type, const struct bitcoin_txid *txid,
			   const u32 input_num, const u32 blockheight);

/**
 * List channels for which we had an onchaind running
 */
u32 *wallet_onchaind_channels(const tal_t *ctx, struct wallet *w);

/**
 * Get transactions that we'd like to replay for a channel.
 */
struct channeltx *wallet_channeltxs_get(const tal_t *ctx, struct wallet *w,
					u32 channel_id);

/**
 * Add of update a forwarded_payment
 */
void wallet_forwarded_payment_add(struct wallet *w, const struct htlc_in *in,
				  enum forward_style forward_style,
				  const struct short_channel_id *scid_out,
				  const struct htlc_out *out,
				  enum forward_status state,
				  enum onion_wire failcode);

/**
 * Retrieve summary of successful forwarded payments' fees
 */
struct amount_msat wallet_total_forward_fees(struct wallet *w);

/**
 * Retrieve a list of all forwarded_payments
 */
const struct forwarding *wallet_forwarded_payments_get(const tal_t *ctx,
						       struct wallet *w,
						       enum forward_status state,
						       const struct short_channel_id *chan_in,
						       const struct short_channel_id *chan_out,
						       const enum wait_index *listindex,
						       u64 liststart,
						       const u32 *listlimit);

/**
 * Delete a particular forward entry
 * Returns false if not found
 */
bool wallet_forward_delete(struct wallet *w,
			   const struct short_channel_id *chan_in,
			   const u64 *htlc_id,
			   enum forward_status state);

/**
 * Load remote_ann_node_sig and remote_ann_bitcoin_sig
 *
 * @w: wallet containing the channel
 * @chan: channel (must be in db)
 * @remote_ann_node_sig: location to load remote_ann_node_sig to
 * @remote_ann_bitcoin_sig: location to load remote_ann_bitcoin_sig to
 *
 * Returns false if the signatures were null.
 */
bool wallet_remote_ann_sigs_load(struct wallet *w,
				 const struct channel *chan,
				 secp256k1_ecdsa_signature *remote_ann_node_sig,
				 secp256k1_ecdsa_signature *remote_ann_bitcoin_sig);

/**
 * Null out remote_ann_node_sig and remote_ann_bitcoin_sig
 *
 * @w: wallet containing the channel
 * @id: channel database id
 */
void wallet_remote_ann_sigs_clear(struct wallet *w, const struct channel *chan);

/**
 * Get a list of transactions that we track in the wallet.
 *
 * @param ctx: allocation context for the returned list
 * @param wallet: Wallet to load from.
 * @return A tal_arr of wallet annotated transactions
 */
struct wallet_transaction *wallet_transactions_get(const tal_t *ctx, struct wallet *w);

/**
 * Add a filteredblock to the blocks and utxoset tables.
 *
 * This can be used to backfill the blocks and still unspent UTXOs that were before our wallet birth height.
 */
void wallet_filteredblock_add(struct wallet *w, const struct filteredblock *fb);

/**
 * Store a penalty base in the database.
 *
 * Required to eventually create a penalty transaction when we get a
 * revocation.
 */
void wallet_penalty_base_add(struct wallet *w, u64 chan_id,
			     const struct penalty_base *pb);

/**
 * Retrieve all pending penalty bases for a given channel.
 *
 * This list should stay relatively small since we remove items from it as we
 * get revocations. We retrieve this list whenever we start a new `channeld`.
 */
struct penalty_base *wallet_penalty_base_load_for_channel(const tal_t *ctx,
							  struct wallet *w,
							  u64 chan_id);

/**
 * Delete a penalty_base, after we created and delivered it to the hook.
 */
void wallet_penalty_base_delete(struct wallet *w, u64 chan_id, u64 commitnum);

/* /!\ This is a DB ENUM, please do not change the numbering of any
 * already defined elements (adding is ok) /!\ */
#define OFFER_STATUS_ACTIVE_F  0x1
#define OFFER_STATUS_SINGLE_F  0x2
#define OFFER_STATUS_USED_F    0x4
enum offer_status {
	OFFER_MULTIPLE_USE_UNUSED = OFFER_STATUS_ACTIVE_F,
	OFFER_MULTIPLE_USE_USED = OFFER_STATUS_ACTIVE_F|OFFER_STATUS_USED_F,
	OFFER_SINGLE_USE_UNUSED = OFFER_STATUS_ACTIVE_F|OFFER_STATUS_SINGLE_F,
	OFFER_SINGLE_USE_USED = OFFER_STATUS_SINGLE_F|OFFER_STATUS_USED_F,
	OFFER_SINGLE_DISABLED = OFFER_STATUS_SINGLE_F,
	OFFER_MULTIPLE_USED_DISABLED = OFFER_STATUS_USED_F,
	OFFER_MULTIPLE_DISABLED = 0,
};

static inline enum offer_status offer_status_in_db(enum offer_status s)
{
	switch (s) {
	case OFFER_MULTIPLE_USE_UNUSED:
		BUILD_ASSERT(OFFER_MULTIPLE_USE_UNUSED == 1);
		return s;
	case OFFER_MULTIPLE_USE_USED:
		BUILD_ASSERT(OFFER_MULTIPLE_USE_USED == 5);
		return s;
	case OFFER_SINGLE_USE_UNUSED:
		BUILD_ASSERT(OFFER_SINGLE_USE_UNUSED == 3);
		return s;
	case OFFER_SINGLE_USE_USED:
		BUILD_ASSERT(OFFER_SINGLE_USE_USED == 6);
		return s;
	case OFFER_SINGLE_DISABLED:
		BUILD_ASSERT(OFFER_SINGLE_DISABLED == 2);
		return s;
	case OFFER_MULTIPLE_USED_DISABLED:
		BUILD_ASSERT(OFFER_MULTIPLE_USED_DISABLED == 4);
		return s;
	case OFFER_MULTIPLE_DISABLED:
		BUILD_ASSERT(OFFER_MULTIPLE_DISABLED == 0);
		return s;
	}
	fatal("%s: %u is invalid", __func__, s);
}

static inline bool offer_status_active(enum offer_status s)
{
	return s & OFFER_STATUS_ACTIVE_F;
}

static inline bool offer_status_single(enum offer_status s)
{
	return s & OFFER_STATUS_SINGLE_F;
}

static inline bool offer_status_used(enum offer_status s)
{
	return s & OFFER_STATUS_USED_F;
}

/**
 * Store an offer in the database.
 * @w: the wallet
 * @offer_id: the merkle root, as used for signing (must be unique)
 * @bolt12: offer as text.
 * @label: optional label for this offer.
 * @status: OFFER_SINGLE_USE or OFFER_MULTIPLE_USE
 */
bool wallet_offer_create(struct wallet *w,
			 const struct sha256 *offer_id,
			 const char *bolt12,
			 const struct json_escape *label,
			 enum offer_status status)
	NON_NULL_ARGS(1,2,3);

/**
 * Retrieve an offer from the database.
 * @ctx: the tal context to allocate return from.
 * @w: the wallet
 * @offer_id: the merkle root, as used for signing (must be unique)
 * @label: the label of the offer, set to NULL if none (or NULL)
 * @status: set if succeeds (or NULL)
 *
 * If @offer_id is found, returns the bolt12 text, sets @label and
 * @state.  Otherwise returns NULL.
 */
char *wallet_offer_find(const tal_t *ctx,
			struct wallet *w,
			const struct sha256 *offer_id,
			const struct json_escape **label,
			enum offer_status *status)
	NON_NULL_ARGS(1,2,3);

/**
 * Iterate through all the offers.
 * @w: the wallet
 * @offer_id: the first offer id (if returns non-NULL)
 *
 * Returns pointer to hand as @stmt to wallet_offer_id_next(), or NULL.
 * If you choose not to call wallet_offer_id_next() you must free it!
 */
struct db_stmt *wallet_offer_id_first(struct wallet *w,
				      struct sha256 *offer_id);

/**
 * Iterate through all the offers.
 * @w: the wallet
 * @stmt: return from wallet_offer_id_first() or previous wallet_offer_id_next()
 * @offer_id: the next offer id (if returns non-NULL)
 *
 * Returns NULL once we're out of offers.  If you choose not to call
 * wallet_offer_id_next() again you must free return.
 */
struct db_stmt *wallet_offer_id_next(struct wallet *w,
				     struct db_stmt *stmt,
				     struct sha256 *offer_id);

/**
 * Disable an offer in the database.
 * @w: the wallet
 * @offer_id: the merkle root, as used for signing (must be unique)
 * @s: the current status (must be active).
 *
 * Must exist.  Returns new status. */
enum offer_status wallet_offer_disable(struct wallet *w,
				       const struct sha256 *offer_id,
				       enum offer_status s)
	NO_NULL_ARGS;

/**
 * Mark an offer in the database used.
 * @w: the wallet
 * @offer_id: the merkle root, as used for signing (must be unique)
 *
 * Must exist and be active.
 */
void wallet_offer_mark_used(struct db *db, const struct sha256 *offer_id)
	NO_NULL_ARGS;

/**
 * Store an offer in the database.
 * @w: the wallet
 * @invreq_id: the hash of the invoice_request.
 * @bolt12: invoice_request as text.
 * @label: optional label for this invoice_request.
 * @status: OFFER_SINGLE_USE or OFFER_MULTIPLE_USE
 */
bool wallet_invoice_request_create(struct wallet *w,
				   const struct sha256 *invreq_id,
				   const char *bolt12,
				   const struct json_escape *label,
				   enum offer_status status)
	NON_NULL_ARGS(1,2,3);

/**
 * Retrieve an invoice_request from the database.
 * @ctx: the tal context to allocate return from.
 * @w: the wallet
 * @invreq_id: the merkle root, as used for signing (must be unique)
 * @label: the label of the invoice_request, set to NULL if none (or NULL)
 * @status: set if succeeds (or NULL)
 *
 * If @invreq_id is found, returns the bolt12 text, sets @label and
 * @state.  Otherwise returns NULL.
 */
char *wallet_invoice_request_find(const tal_t *ctx,
			struct wallet *w,
			const struct sha256 *invreq_id,
			const struct json_escape **label,
			enum offer_status *status)
	NON_NULL_ARGS(1,2,3);

/**
 * Iterate through all the invoice_requests.
 * @w: the wallet
 * @invreq_id: the first invoice_request id (if returns non-NULL)
 *
 * Returns pointer to hand as @stmt to wallet_invreq_id_next(), or NULL.
 * If you choose not to call wallet_invreq_id_next() you must free it!
 */
struct db_stmt *wallet_invreq_id_first(struct wallet *w,
				      struct sha256 *invreq_id);

/**
 * Iterate through all the invoice_requests.
 * @w: the wallet
 * @stmt: return from wallet_invreq_id_first() or previous wallet_invreq_id_next()
 * @invreq_id: the next invoice_request id (if returns non-NULL)
 *
 * Returns NULL once we're out of invoice_requests.  If you choose not to call
 * wallet_invreq_id_next() again you must free return.
 */
struct db_stmt *wallet_invreq_id_next(struct wallet *w,
				     struct db_stmt *stmt,
				     struct sha256 *invreq_id);

/**
 * Disable an invoice_request in the database.
 * @w: the wallet
 * @invreq_id: the merkle root, as used for signing (must be unique)
 * @s: the current status (must be active).
 *
 * Must exist.  Returns new status. */
enum offer_status wallet_invoice_request_disable(struct wallet *w,
						 const struct sha256 *invreq_id,
						 enum offer_status s)
	NO_NULL_ARGS;

/**
 * Mark an invoice_request in the database used.
 * @w: the wallet
 * @invreq_id: the merkle root, as used for signing (must be unique)
 *
 * Must exist and be active.
 */
void wallet_invoice_request_mark_used(struct db *db, const struct sha256 *invreq_id)
	NO_NULL_ARGS;

/**
 * Add an new key/value to the datastore (generation 0)
 * @w: the wallet
 * @key: the new key (if returns non-NULL)
 * @data: the new data (if returns non-NULL)
 */
void wallet_datastore_create(struct wallet *w, const char **key, const u8 *data);

/**
 * Update an existing key/value to the datastore.
 * @w: the wallet
 * @key: the first key (if returns non-NULL)
 * @data: the first data (if returns non-NULL)
 */
void wallet_datastore_update(struct wallet *w,
			     const char **key,
			     const u8 *data);

/**
 * Remove a key from the datastore
 * @w: the wallet
 * @key: the key
 */
void wallet_datastore_remove(struct wallet *w, const char **key);

/**
 * Get a single entry from the datastore
 * @ctx: the tal ctx to allocate off
 * @w: the wallet
 * @key: the key
 * @generation: the generation or NULL (set if returns non-NULL)
 */
u8 *wallet_datastore_get(const tal_t *ctx,
			 struct wallet *w,
			 const char **key,
			 u64 *generation);

/**
 * Iterate through the datastore.
 * @ctx: the tal ctx to allocate off
 * @w: the wallet
 * @startkey: NULL, or the subkey to iterate
 * @key: the first key (if returns non-NULL)
 * @data: the first data (if returns non-NULL)
 * @generation: the first generation (if returns non-NULL)
 *
 * Returns pointer to hand as @stmt to wallet_datastore_next(), or NULL.
 * If you choose not to call wallet_datastore_next() you must free it!
 */
struct db_stmt *wallet_datastore_first(const tal_t *ctx,
				       struct wallet *w,
				       const char **startkey,
				       const char ***key,
				       const u8 **data,
				       u64 *generation);

/**
 * Iterate through the datastore.
 * @ctx: the tal ctx to allocate off
 * @startkey: NULL, or the subkey to iterate
 * @stmt: the previous statement.
 * @key: the key (if returns non-NULL)
 * @data: the data (if returns non-NULL)
 * @generation: the generation (if returns non-NULL)
 *
 * Returns pointer to hand as @stmt to wallet_datastore_next(), or NULL.
 * If you choose not to call wallet_datastore_next() you must free it!
 */
struct db_stmt *wallet_datastore_next(const tal_t *ctx,
				      const char **startkey,
				      struct db_stmt *stmt,
				      const char ***key,
				      const u8 **data,
				      u64 *generation);

/* Does k1 match k2 as far as k2 goes? */
bool datastore_key_startswith(const char **k1, const char **k2);
/* Does k1 match k2? */
bool datastore_key_eq(const char **k1, const char **k2);

/**
 * Iterate through the htlcs table.
 * @w: the wallet
 * @chan: optional channel to filter by
 *
 * Returns pointer to hand as @iter to wallet_htlcs_next(), or NULL.
 * If you choose not to call wallet_htlcs_next() you must free it!
 */
struct wallet_htlc_iter *wallet_htlcs_first(const tal_t *ctx,
					    struct wallet *w,
					    const struct channel *chan,
					    struct short_channel_id *scid,
					    u64 *htlc_id,
					    int *cltv_expiry,
					    enum side *owner,
					    struct amount_msat *msat,
					    struct sha256 *payment_hash,
					    enum htlc_state *hstate);

/**
 * Iterate through the htlcs table.
 * @w: the wallet
 * @iter: the previous iter.
 *
 * Returns pointer to hand as @iter to wallet_htlcs_next(), or NULL.
 * If you choose not to call wallet_htlcs_next() you must free it!
 */
struct wallet_htlc_iter *wallet_htlcs_next(struct wallet *w,
					   struct wallet_htlc_iter *iter,
					   struct short_channel_id *scid,
					   u64 *htlc_id,
					   int *cltv_expiry,
					   enum side *owner,
					   struct amount_msat *msat,
					   struct sha256 *payment_hash,
					   enum htlc_state *hstate);

/* Make a PSBT from these utxos, or enhance @base if non-NULL. */
struct wally_psbt *psbt_using_utxos(const tal_t *ctx,
				    struct wallet *wallet,
				    struct utxo **utxos,
				    u32 nlocktime,
				    u32 nsequence,
				    struct wally_psbt *base);

/**
 * Get a particular runestring from the db
 * @ctx: tal ctx for return to be tallocated from
 * @wallet: the wallet
 * @unique_id: the id of the rune.
 * @last_used: absolute time rune was last used
 *
 * Returns NULL if it's not found.
 */
const char *wallet_get_rune(const tal_t *ctx, struct wallet *wallet, u64 unique_id, struct timeabs *last_used);

/**
 * Get every runestring from the db
 * @ctx: tal ctx for return to be tallocated from
 * @wallet: the wallet
 * @last_used: absolute time rune was last used
 */
const char **wallet_get_runes(const tal_t *ctx, struct wallet *wallet, struct timeabs **last_used);

/**
 * wallet_rune_insert -- Insert the newly created rune into the database
 *
 * @wallet: the wallet to save into
 * @rune: the instance to store
 */
void wallet_rune_insert(struct wallet *wallet, const struct rune *rune);

/**
 * wallet_rune_update_last_used -- Update the timestamp on an existing rune
 *
 * @wallet: the wallet to save into
 * @rune: the instance to store
 * @last_used: now
 */
void wallet_rune_update_last_used(struct wallet *wallet, const struct rune *rune, struct timeabs last_used);

/* Load the runes blacklist */
struct rune_blacklist {
	u64 start, end;
};

/**
 * Load the next unique id for rune from the db.
 * @ctx: tal ctx for return to be tallocated from
 * @wallet: the wallet
 */
u64 wallet_get_rune_next_unique_id(const tal_t *ctx, struct wallet *wallet);

/**
 * Load the blacklist from the db.
 * @ctx: tal ctx for return to be tallocated from
 * @wallet: the wallet
 */
struct rune_blacklist *wallet_get_runes_blacklist(const tal_t *ctx, struct wallet *wallet);

/**
 * wallet_insert_blacklist -- Insert rune into blacklist
 *
 * @wallet: the wallet to save into
 * @entry: the new entry to insert
 */
void wallet_insert_blacklist(struct wallet *wallet, const struct rune_blacklist *entry);

/**
 * wallet_delete_blacklist -- Delete row from blacklist
 *
 * @wallet: the wallet to delete from
 * @entry: the entry to delete
 */
void wallet_delete_blacklist(struct wallet *wallet, const struct rune_blacklist *entry);

/**
 * wallet_set_local_anchor -- Set local anchor point for a remote commitment tx
 * @w: wallet containing the channel
 * @channel_id: channel database id
 * @anchor: the local_anchor_info describing the remote commitment tx.
 * @remote_index: the (remote) commitment index
 */
void wallet_set_local_anchor(struct wallet *w,
			     u64 channel_id,
			     const struct local_anchor_info *anchor,
			     u64 remote_index);

/**
 * wallet_remove_local_anchors -- Remove old local anchor points
 * @w: wallet containing the channel
 * @channel_id: channel database id
 * @old_remote_index: the (remote) commitment index to remove
 *
 * Since we only have to keep the last two, we use this to remove the
 * old entries for the channel.
 */
void wallet_remove_local_anchors(struct wallet *w,
				 u64 channel_id,
				 u64 old_remote_index);

/**
 * wallet_get_local_anchors -- Get all local anchor points for remote commitment txs
 * @ctx: tal context for returned array
 * @w: wallet containing the channel
 * @channel_id: channel database id
 */
struct local_anchor_info *wallet_get_local_anchors(const tal_t *ctx,
						   struct wallet *w,
						   u64 channel_id);
#endif /* LIGHTNING_WALLET_WALLET_H */
