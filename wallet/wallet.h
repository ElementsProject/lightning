#ifndef LIGHTNING_WALLET_WALLET_H
#define LIGHTNING_WALLET_WALLET_H

#include "config.h"
#include "db.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/tx.h>
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/list/list.h>
#include <ccan/tal/tal.h>
#include <common/channel_config.h>
#include <common/utxo.h>
#include <lightningd/chaintopology.h>
#include <lightningd/htlc_end.h>
#include <lightningd/invoice.h>
#include <onchaind/onchain_wire.h>
#include <wally_bip32.h>

enum onion_type;
struct invoices;
struct channel;
struct lightningd;
struct oneshot;
struct peer;
struct pubkey;
struct timers;

struct wallet {
	struct lightningd *ld;
	struct db *db;
	struct log *log;
	struct ext_key *bip32_base;
	struct invoices *invoices;
	struct list_head unstored_payments;
	u64 max_channel_dbid;

	/* Filter matching all outpoints corresponding to our owned outputs,
	 * including all spent ones */
	struct outpointfilter *owned_outpoints;

	/* Filter matching all outpoints that might be a funding transaction on
	 * the blockchain. This is currently all P2WSH outputs */
	struct outpointfilter *utxoset_outpoints;
};

/* Possible states for tracked outputs in the database. Not sure yet
 * whether we really want to have reservations reflected in the
 * database, it would simplify queries at the cost of some IO ops */
enum output_status {
	output_state_available= 0,
	output_state_reserved = 1,
	output_state_spent = 2,
	/* Special status used to express that we don't care in
	 * queries */
	output_state_any = 255
};

/* Enumeration of all known output types. These include all types that
 * could ever end up on-chain and we may need to react upon. Notice
 * that `to_local`, `htlc_offer`, and `htlc_recv` may need immediate
 * action since they are encumbered with a CSV. */
enum wallet_output_type {
	p2sh_wpkh = 0,
	to_local = 1,
	htlc_offer = 3,
	htlc_recv = 4,
	our_change = 5,
	p2wpkh = 6
};

/* A database backed shachain struct. The datastructure is
 * writethrough, reads are performed from an in-memory version, all
 * writes are passed through to the DB. */
struct wallet_shachain {
	u64 id;
	struct shachain chain;
};

/* Possible states for a wallet_payment. Payments start in
 * `PENDING`. Outgoing payments are set to `PAYMENT_COMPLETE` once we
 * get the preimage matching the rhash, or to
 * `PAYMENT_FAILED`. */
/* /!\ This is a DB ENUM, please do not change the numbering of any
 * already defined elements (adding is ok) /!\ */
enum wallet_payment_status {
	PAYMENT_PENDING = 0,
	PAYMENT_COMPLETE = 1,
	PAYMENT_FAILED = 2
};

/* Outgoing payments. A simple persisted representation
 * of a payment we initiated. This can be used by
 * a UI (alongside invoices) to display the balance history.
 */
struct wallet_payment {
	/* If it's in unstored_payments */
	struct list_node list;
	u64 id;
	u32 timestamp;
	struct sha256 payment_hash;
	enum wallet_payment_status status;
	struct pubkey destination;
	u64 msatoshi;
	u64 msatoshi_sent;
	/* If and only if PAYMENT_COMPLETE */
	struct preimage *payment_preimage;
	/* Needed for recovering from routing failures. */
	struct secret *path_secrets;
	struct pubkey *route_nodes;
	struct short_channel_id *route_channels;

	/* The description of the payment. Must support `tal_len` */
	const char *description;
};

struct outpoint {
	struct bitcoin_txid txid;
	u32 blockheight;
	u32 txindex;
	u32 outnum;
	u64 satoshis;
	u8 *scriptpubkey;
	u32 spendheight;
};

/* Statistics for a channel */
struct channel_stats {
	u64  in_payments_offered,  in_payments_fulfilled;
	u64  in_msatoshi_offered,  in_msatoshi_fulfilled;
	u64 out_payments_offered, out_payments_fulfilled;
	u64 out_msatoshi_offered, out_msatoshi_fulfilled;
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

/**
 * wallet_new - Constructor for a new sqlite3 based wallet
 *
 * This is guaranteed to either return a valid wallet, or abort with
 * `fatal` if it cannot be initialized.
 */
struct wallet *wallet_new(struct lightningd *ld,
			  struct log *log, struct timers *timers);

/**
 * wallet_add_utxo - Register an UTXO which we (partially) own
 *
 * Add an UTXO to the set of outputs we care about.
 */
bool wallet_add_utxo(struct wallet *w, struct utxo *utxo,
		     enum wallet_output_type type);

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
				 const struct bitcoin_txid *txid,
				 const u32 outnum, enum output_status oldstatus,
				 enum output_status newstatus);

/**
 * wallet_get_utxos - Retrieve all utxos matching a given state
 *
 * Returns a `tal_arr` of `utxo` structs. Double indirection in order
 * to be able to steal individual elements onto something else.
 */
struct utxo **wallet_get_utxos(const tal_t *ctx, struct wallet *w,
			      const enum output_status state);

const struct utxo **wallet_select_coins(const tal_t *ctx, struct wallet *w,
					const u64 value,
					const u32 feerate_per_kw,
					size_t outscriptlen,
					u64 *fee_estimate,
					u64 *change_satoshi);

const struct utxo **wallet_select_all(const tal_t *ctx, struct wallet *w,
					const u32 feerate_per_kw,
					size_t outscriptlen,
					u64 *value,
					u64 *fee_estimate);

/**
 * wallet_confirm_utxos - Once we've spent a set of utxos, mark them confirmed.
 *
 * May be called once the transaction spending these UTXOs has been
 * broadcast. If something fails use `tal_free(utxos)` instead to undo
 * the reservation.
 */
void wallet_confirm_utxos(struct wallet *w, const struct utxo **utxos);

/**
 * wallet_can_spend - Do we have the private key matching this scriptpubkey?
 *
 * FIXME: This is very slow with lots of inputs!
 *
 * @w: (in) allet holding the pubkeys to check against (privkeys are on HSM)
 * @script: (in) the script to check
 * @index: (out) the bip32 derivation index that matched the script
 * @output_is_p2sh: (out) whether the script is a p2sh, or p2wpkh
 */
bool wallet_can_spend(struct wallet *w, const u8 *script,
		      u32 *index, bool *output_is_p2sh);

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
 * wallet_shachain_load -- Load an existing shachain from the wallet.
 *
 * @wallet: the wallet to load from
 * @id: the shachain id to load
 * @chain: where to load the shachain into
 */
bool wallet_shachain_load(struct wallet *wallet, u64 id,
			  struct wallet_shachain *chain);


/**
 * wallet_get_uncommitted_channel_dbid -- get a unique channel dbid
 *
 * @wallet: the wallet
 */
u64 wallet_get_channel_dbid(struct wallet *wallet);

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
 * wallet_channel_delete -- After resolving a channel, forget about it
 */
void wallet_channel_delete(struct wallet *w, u64 wallet_id);

/**
 * wallet_peer_delete -- After no more channels in peer, forget about it
 */
void wallet_peer_delete(struct wallet *w, u64 peer_dbid);

/**
 * wallet_channel_config_load -- Load channel_config from database into cc
 */
bool wallet_channel_config_load(struct wallet *w, const u64 id,
				struct channel_config *cc);

/**
 * wlalet_channels_load_active -- Load persisted active channels into the peers
 *
 * @ctx: context to allocate peers from
 * @w: wallet to load from
 *
 * Be sure to call this only once on startup since it'll append peers
 * loaded from the database to the list without checking.
 */
bool wallet_channels_load_active(const tal_t *ctx, struct wallet *w);

/**
 * wallet_channel_stats_incr_* - Increase channel statistics.
 *
 * @w: wallet containing the channel
 * @cdbid: channel database id
 * @msatoshi: amount in msatoshi being transferred
 */
void wallet_channel_stats_incr_in_offered(struct wallet *w, u64 cdbid, u64 msatoshi);
void wallet_channel_stats_incr_in_fulfilled(struct wallet *w, u64 cdbid, u64 msatoshi);
void wallet_channel_stats_incr_out_offered(struct wallet *w, u64 cdbid, u64 msatoshi);
void wallet_channel_stats_incr_out_fulfilled(struct wallet *w, u64 cdbid, u64 msatoshi);

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
int wallet_extract_owned_outputs(struct wallet *w, const struct bitcoin_tx *tx,
				 const u32 *blockheight, u64 *total_satoshi);

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
 *
 * Used to update the state of an HTLC, either a `struct htlc_in` or a
 * `struct htlc_out` and optionally set the `payment_key` should the
 * HTLC have been settled.
 */
void wallet_htlc_update(struct wallet *wallet, const u64 htlc_dbid,
			const enum htlc_state new_state,
			const struct preimage *payment_key);

/**
 * wallet_htlcs_load_for_channel - Load HTLCs associated with chan from DB.
 *
 * @wallet: wallet to load from
 * @chan: load HTLCs associated with this channel
 * @htlcs_in: htlc_in_map to store loaded htlc_in in
 * @htlcs_out: htlc_out_map to store loaded htlc_out in
 *
 * This function looks for HTLCs that are associated with the given
 * channel and loads them into the provided maps. One caveat is that
 * the `struct htlc_out` instances are not wired up with the
 * corresponding `struct htlc_in` in the forwarding case nor are they
 * associated with a `struct pay_command` in the case we originated
 * the payment. In the former case the corresponding `struct htlc_in`
 * may not have been loaded yet. In the latter case the pay_command
 * does not exist anymore since we restarted.
 *
 * Use `wallet_htlcs_reconnect` to wire htlc_out instances to the
 * corresponding htlc_in after loading all channels.
 */
bool wallet_htlcs_load_for_channel(struct wallet *wallet,
				   struct channel *chan,
				   struct htlc_in_map *htlcs_in,
				   struct htlc_out_map *htlcs_out);

/**
 * wallet_htlcs_reconnect -- Link outgoing HTLCs to their origins
 *
 * For each outgoing HTLC find the incoming HTLC that triggered it. If
 * we are the origin of the transfer then we cannot resolve the
 * incoming HTLC in which case we just leave it `NULL`.
 */
bool wallet_htlcs_reconnect(struct wallet *wallet,
			    struct htlc_in_map *htlcs_in,
			    struct htlc_out_map *htlcs_out);

/* /!\ This is a DB ENUM, please do not change the numbering of any
 * already defined elements (adding is ok) /!\ */
enum invoice_status {
	UNPAID,
	PAID,
	EXPIRED,
};

/* The information about an invoice */
struct invoice_details {
	/* Current invoice state */
	enum invoice_status state;
	/* Preimage for this invoice */
	struct preimage r;
	/* Hash of preimage r */
	struct sha256 rhash;
	/* Label assigned by user */
	const struct json_escaped *label;
	/* NULL if they specified "any" */
	u64 *msatoshi;
	/* Absolute UNIX epoch time this will expire */
	u64 expiry_time;
	/* Set if state == PAID; order to be returned by waitanyinvoice */
	u64 pay_index;
	/* Set if state == PAID; amount received */
	u64 msatoshi_received;
	/* Set if state == PAID; time paid */
	u64 paid_timestamp;
	/* BOLT11 encoding for this invoice */
	const char *bolt11;

	/* The description of the payment. */
	char *description;
};

/* An object that handles iteration over the set of invoices */
struct invoice_iterator {
	/* The contents of this object is subject to change
	 * and should not be depended upon */
	void *p;
};

struct invoice {
	/* Internal, rest of lightningd should not use */
	/* Database ID */
	u64 id;
};

#define INVOICE_MAX_LABEL_LEN 128

/**
 * wallet_invoice_load - Load the invoices from the database
 *
 * @wallet - the wallet whose invoices are to be loaded.
 *
 * All other wallet_invoice_* functions cannot be called
 * until this function is called.
 * As a database operation it must be called within
 * db_begin_transaction .. db_commit_transaction
 * (all other invoice functions also have this requirement).
 * Returns true if loaded successfully.
 */
bool wallet_invoice_load(struct wallet *wallet);

/**
 * wallet_invoice_create - Create a new invoice.
 *
 * @wallet - the wallet to create the invoice in.
 * @pinvoice - pointer to location to load new invoice in.
 * @msatoshi - the amount the invoice should have, or
 * NULL for any-amount invoices.
 * @label - the unique label for this invoice. Must be
 * non-NULL.
 * @expiry - the number of seconds before the invoice
 * expires
 *
 * Returns false if label already exists or expiry is 0.
 * Returns true if created invoice.
 * FIXME: Fallback addresses
 */
bool wallet_invoice_create(struct wallet *wallet,
			   struct invoice *pinvoice,
			   u64 *msatoshi TAKES,
			   const struct json_escaped *label TAKES,
			   u64 expiry,
			   const char *b11enc,
			   const char *description,
			   const struct preimage *r,
			   const struct sha256 *rhash);

/**
 * wallet_invoice_find_by_label - Search for an invoice by label
 *
 * @wallet - the wallet to search.
 * @pinvoice - pointer to location to load found invoice in.
 * @label - the label to search for.
 *
 * Returns false if no invoice with that label exists.
 * Returns true if found.
 */
bool wallet_invoice_find_by_label(struct wallet *wallet,
				  struct invoice *pinvoice,
				  const struct json_escaped *label);

/**
 * wallet_invoice_find_by_rhash - Search for an invoice by payment_hash
 *
 * @wallet - the wallet to search.
 * @pinvoice - pointer to location to load found invoice in.
 * @rhash - the payment_hash to search for.
 *
 * Returns false if no invoice with that rhash exists.
 * Returns true if found.
 */
bool wallet_invoice_find_by_rhash(struct wallet *wallet,
				  struct invoice *pinvoice,
				  const struct sha256 *rhash);

/**
 * wallet_invoice_find_unpaid - Search for an unpaid, unexpired invoice by
 * payment_hash
 *
 * @wallet - the wallet to search.
 * @pinvoice - pointer to location to load found invoice in.
 * @rhash - the payment_hash to search for.
 *
 * Returns false if no unpaid invoice with that rhash exists.
 * Returns true if found.
 */
bool wallet_invoice_find_unpaid(struct wallet *wallet,
				struct invoice *pinvoice,
				const struct sha256 *rhash);

/**
 * wallet_invoice_delete - Delete an invoice
 *
 * @wallet - the wallet to delete the invoice from.
 * @invoice - the invoice to delete.
 *
 * Return false on failure.
 */
bool wallet_invoice_delete(struct wallet *wallet,
			   struct invoice invoice);

/**
 * wallet_invoice_delete_expired - Delete all expired invoices
 * with expiration time less than or equal to the given.
 *
 * @wallet - the wallet to delete invoices from.
 * @max_expiry_time - the maximum expiry time to delete.
 */
void wallet_invoice_delete_expired(struct wallet *wallet,
				   u64 max_expiry_time);

/**
 * wallet_invoice_autoclean - Set up a repeating autoclean of
 * expired invoices.
 * Cleans (deletes) expired invoices every @cycle_seconds.
 * Clean only those invoices that have been expired for at
 * least @expired_by seconds or more.
 */
void wallet_invoice_autoclean(struct wallet * wallet,
			      u64 cycle_seconds,
			      u64 expired_by);

/**
 * wallet_invoice_iterate - Iterate over all existing invoices
 *
 * @wallet - the wallet whose invoices are to be iterated over.
 * @iterator - the iterator object to use.
 *
 * Return false at end-of-sequence, true if still iterating.
 * Usage:
 *
 *   struct invoice_iterator it;
 *   memset(&it, 0, sizeof(it))
 *   while (wallet_invoice_iterate(wallet, &it)) {
 *       ...
 *   }
 */
bool wallet_invoice_iterate(struct wallet *wallet,
			    struct invoice_iterator *it);

/**
 * wallet_invoice_iterator_deref - Read the details of the
 * invoice currently pointed to by the given iterator.
 *
 * @ctx - the owner of the label and msatoshi fields returned.
 * @wallet - the wallet whose invoices are to be iterated over.
 * @iterator - the iterator object to use.
 * @return pointer to the invoice details allocated off of `ctx`.
 */
const struct invoice_details *
wallet_invoice_iterator_deref(const tal_t *ctx, struct wallet *wallet,
			      const struct invoice_iterator *it);

/**
 * wallet_invoice_resolve - Mark an invoice as paid
 *
 * @wallet - the wallet containing the invoice.
 * @invoice - the invoice to mark as paid.
 * @msatoshi_received - the actual amount received.
 *
 * Precondition: the invoice must not yet be expired (wallet
 * does not check!).
 */
void wallet_invoice_resolve(struct wallet *wallet,
			    struct invoice invoice,
			    u64 msatoshi_received);

/**
 * wallet_invoice_waitany - Wait for any invoice to be paid.
 *
 * @ctx - the owner of the callback. If the owner is freed,
 * the callback is cancelled.
 * @wallet - the wallet to query.
 * @lastpay_index - wait for invoices after the specified
 * pay_index. Use 0 to wait for the first invoice.
 * @cb - the callback to invoke. If an invoice is already
 * paid with pay_index greater than lastpay_index, this
 * is called immediately, otherwise it is called during
 * an invoices_resolve call. Will never be given a NULL
 * pointer-to-invoice.
 * @cbarg - the callback data.
 */
void wallet_invoice_waitany(const tal_t *ctx,
			    struct wallet *wallet,
			    u64 lastpay_index,
			    void (*cb)(const struct invoice *, void*),
			    void *cbarg);

/**
 * wallet_invoice_waitone - Wait for a specific invoice to be paid,
 * deleted, or expired.
 *
 * @ctx - the owner of the callback. If the owner is freed,
 * the callback is cancelled.
 * @wallet - the wallet to query.
 * @invoice - the invoice to wait on.
 * @cb - the callback to invoice. If invoice is already paid
 * or expired, this is called immediately, otherwise it is
 * called during an invoices_resolve or invoices_delete call.
 * If the invoice was deleted, the callback is given a NULL
 * invoice.
 * @cbarg - the callback data.
 *
 */
void wallet_invoice_waitone(const tal_t *ctx,
			    struct wallet *wallet,
			    struct invoice invoice,
			    void (*cb)(const struct invoice *, void*),
			    void *cbarg);

/**
 * wallet_invoice_details - Get the invoice_details of an invoice.
 *
 * @ctx - the owner of the label and msatoshi fields returned.
 * @wallet - the wallet to query.
 * @invoice - the invoice to get details on.
 * @return pointer to the invoice details allocated off of `ctx`.
 */
const struct invoice_details *wallet_invoice_details(const tal_t *ctx,
						     struct wallet *wallet,
						     struct invoice invoice);

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
 */
struct htlc_stub *wallet_htlc_stubs(const tal_t *ctx, struct wallet *wallet,
				    struct channel *chan);

/**
 * wallet_payment_setup - Remember this payment for later committing.
 *
 * Either wallet_payment_store() gets called to put in db once hout
 * is ready to go (and frees @payment), or @payment is tal_free'd.
 *
 * @wallet: wallet we're going to store it in.
 * @payment: the payment for later committing.
 */
void wallet_payment_setup(struct wallet *wallet, struct wallet_payment *payment);

/**
 * wallet_payment_store - Record a new incoming/outgoing payment
 *
 * Stores the payment in the database.
 */
void wallet_payment_store(struct wallet *wallet,
			  const struct sha256 *payment_hash);

/**
 * wallet_payment_delete - Remove a payment
 *
 * Removes the payment from the database.
 */
void wallet_payment_delete(struct wallet *wallet,
			   const struct sha256 *payment_hash);

/**
 * wallet_local_htlc_out_delete - Remove a local outgoing failed HTLC
 *
 * This is not a generic HTLC cleanup!  This is specifically for the
 * narrow (and simple!) case of removing the HTLC associated with a
 * local outgoing payment.
 */
void wallet_local_htlc_out_delete(struct wallet *wallet,
				  struct channel *chan,
				  const struct sha256 *payment_hash);

/**
 * wallet_payment_by_hash - Retrieve a specific payment
 *
 * Given the `payment_hash` retrieve the matching payment.
 */
struct wallet_payment *
wallet_payment_by_hash(const tal_t *ctx, struct wallet *wallet,
				const struct sha256 *payment_hash);

/**
 * wallet_payment_set_status - Update the status of the payment
 *
 * Search for the payment with the given `payment_hash` and update
 * its state.
 */
void wallet_payment_set_status(struct wallet *wallet,
				const struct sha256 *payment_hash,
			        const enum wallet_payment_status newstatus,
			        const struct preimage *preimage);

/**
 * wallet_payment_get_failinfo - Get failure information for a given
 * `payment_hash`.
 *
 * Data is allocated as children of the given context.
 */
void wallet_payment_get_failinfo(const tal_t *ctx,
				 struct wallet *wallet,
				 const struct sha256 *payment_hash,
				 /* outputs */
				 u8 **failonionreply,
				 bool *faildestperm,
				 int *failindex,
				 enum onion_type *failcode,
				 struct pubkey **failnode,
				 struct short_channel_id **failchannel,
				 u8 **failupdate,
				 char **faildetail);
/**
 * wallet_payment_set_failinfo - Set failure information for a given
 * `payment_hash`.
 */
void wallet_payment_set_failinfo(struct wallet *wallet,
				 const struct sha256 *payment_hash,
				 const u8 *failonionreply,
				 bool faildestperm,
				 int failindex,
				 enum onion_type failcode,
				 const struct pubkey *failnode,
				 const struct short_channel_id *failchannel,
				 const u8 *failupdate,
				 const char *faildetail);

/**
 * wallet_payment_list - Retrieve a list of payments
 *
 * payment_hash: optional filter for only this payment hash.
 */
const struct wallet_payment **wallet_payment_list(const tal_t *ctx,
						  struct wallet *wallet,
						  const struct sha256 *payment_hash);

/**
 * wallet_htlc_sigs_save - Store the latest HTLC sigs for the channel
 */
void wallet_htlc_sigs_save(struct wallet *w, u64 channel_id,
			   secp256k1_ecdsa_signature *htlc_sigs);

/**
 * wallet_network_check - Check that the wallet is setup for this chain
 *
 * Ensure that the genesis_hash from the chainparams matches the
 * genesis_hash with which the DB was initialized. Returns false if
 * the check failed, i.e., if the genesis hashes do not match.
 */
bool wallet_network_check(struct wallet *w,
			  const struct chainparams *chainparams);

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
 * Mark an outpoint as spent, both in the owned as well as the UTXO set
 *
 * Given the outpoint (txid, outnum), and the blockheight, mark the
 * corresponding DB entries as spent at the blockheight.
 *
 * @return scid The short_channel_id corresponding to the spent outpoint, if
 *         any.
 */
const struct short_channel_id *
wallet_outpoint_spend(struct wallet *w, const tal_t *ctx, const u32 blockheight,
		      const struct bitcoin_txid *txid, const u32 outnum);

struct outpoint *wallet_outpoint_for_scid(struct wallet *w, tal_t *ctx,
					  const struct short_channel_id *scid);

void wallet_utxoset_add(struct wallet *w, const struct bitcoin_tx *tx,
			const u32 outnum, const u32 blockheight,
			const u32 txindex, const u8 *scriptpubkey,
			const u64 satoshis);

void wallet_transaction_add(struct wallet *w, const struct bitcoin_tx *tx,
			    const u32 blockheight, const u32 txindex);

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
u32 *wallet_onchaind_channels(struct wallet *w,
			      const tal_t *ctx);

/**
 * Get transactions that we'd like to replay for a channel.
 */
struct channeltx *wallet_channeltxs_get(struct wallet *w, const tal_t *ctx,
					u32 channel_id);

#endif /* LIGHTNING_WALLET_WALLET_H */
