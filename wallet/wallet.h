#ifndef WALLET_WALLET_H
#define WALLET_WALLET_H

#include "config.h"
#include "db.h"
#include <bitcoin/tx.h>
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/list/list.h>
#include <ccan/tal/tal.h>
#include <common/channel_config.h>
#include <common/utxo.h>
#include <lightningd/htlc_end.h>
#include <lightningd/invoice.h>
#include <onchaind/onchain_wire.h>
#include <wally_bip32.h>

struct invoices;
struct lightningd;
struct pubkey;

struct wallet {
	struct db *db;
	struct log *log;
	struct ext_key *bip32_base;
	struct invoices *invoices;
	struct list_head unstored_payments;
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

/* A database backed peer struct. Like wallet_shachain, it is writethrough. */
/* TODO(cdecker) Separate peer from channel */
struct wallet_channel {
	u64 id;
	struct peer *peer;
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
	/* if PAYMENT_COMPLETE */
	struct preimage *payment_preimage;
	struct secret *path_secrets;
};

/**
 * wallet_new - Constructor for a new sqlite3 based wallet
 *
 * This is guaranteed to either return a valid wallet, or abort with
 * `fatal` if it cannot be initialized.
 */
struct wallet *wallet_new(const tal_t *ctx, struct log *log);

/**
 * wallet_add_utxo - Register a UTXO which we (partially) own
 *
 * Add a UTXO to the set of outputs we care about.
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
 * wallet_shachain_init -- wallet wrapper around shachain_init
 */
void wallet_shachain_init(struct wallet *wallet, struct wallet_shachain *chain);

/**
 * wallet_shachain_add_hash -- wallet wrapper around shachain_add_hash
 */
bool wallet_shachain_add_hash(struct wallet *wallet,
			      struct wallet_shachain *chain,
			      uint64_t index,
			      const struct sha256 *hash);

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
 * wallet_channel_save -- Upsert the channel into the database
 *
 * @wallet: the wallet to save into
 * @chan: the instance to store (not const so we can update the unique_id upon
 *   insert)
 * @current_block_height: current height, minimum block this funding tx could
 *   be in (only used on initial insert).
 */
void wallet_channel_save(struct wallet *w, struct wallet_channel *chan,
			 u32 current_block_height);

/**
 * wallet_channel_delete -- After resolving a channel, forget about it
 */
void wallet_channel_delete(struct wallet *w, u64 wallet_id);

/**
 * wallet_channel_config_save -- Upsert a channel_config into the database
 */
void wallet_channel_config_save(struct wallet *w, struct channel_config *cc);

/**
 * wallet_channel_config_load -- Load channel_config from database into cc
 */
bool wallet_channel_config_load(struct wallet *w, const u64 id,
				struct channel_config *cc);

/**
 * wallet_peer_by_nodeid -- Given a node_id/pubkey, load the peer from DB
 *
 * @w: the wallet to load from
 * @nodeid: the node_id to search for
 * @peer(out): the destination where to store the peer
 *
 * Returns true on success, or false if we were unable to find a peer
 * with the given node_id.
 */
bool wallet_peer_by_nodeid(struct wallet *w, const struct pubkey *nodeid,
			   struct peer *peer);

/**
 * wlalet_channels_load_active -- Load persisted active channels into the peers
 *
 * @ctx: context to allocate peers from
 * @w: wallet to load from
 * @peers: list_head to load channels/peers into
 *
 * Be sure to call this only once on startup since it'll append peers
 * loaded from the database to the list without checking.
 */
bool wallet_channels_load_active(const tal_t *ctx,
				 struct wallet *w, struct list_head *peers);

/**
 * wallet_channels_first_blocknum - get first block we're interested in.
 *
 * @w: wallet to load from.
 *
 * Returns UINT32_MAX if nothing interesting.
 */
u32 wallet_channels_first_blocknum(struct wallet *w);

/**
 * wallet_extract_owned_outputs - given a tx, extract all of our outputs
 */
int wallet_extract_owned_outputs(struct wallet *w, const struct bitcoin_tx *tx,
				 u64 *total_satoshi);

/**
 * wallet_htlc_save_in - store a htlc_in in the database
 *
 * @wallet: wallet to store the htlc into
 * @chan: the `wallet_channel` this HTLC is associated with
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
			 const struct wallet_channel *chan, struct htlc_in *in);

/**
 * wallet_htlc_save_out - store a htlc_out in the database
 *
 * See comment for wallet_htlc_save_in.
 */
void wallet_htlc_save_out(struct wallet *wallet,
			  const struct wallet_channel *chan,
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
				   struct wallet_channel *chan,
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
};

struct invoice {
	/* List off ld->wallet->invoices */
	struct list_node list;
	/* Database ID */
	u64 id;
	enum invoice_status state;
	const char *label;
	/* NULL if they specified "any" */
	u64 *msatoshi;
	/* Set if state == PAID */
	u64 msatoshi_received;
	/* Set if state == PAID */
	u64 paid_timestamp;
	struct preimage r;
	u64 expiry_time;
	struct sha256 rhash;
	/* Non-zero if state == PAID */
	u64 pay_index;
	/* Any JSON waitinvoice calls waiting for this to be paid */
	struct list_head waitone_waiters;
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
 * @msatoshi - the amount the invoice should have, or
 * NULL for any-amount invoices.
 * @label - the unique label for this invoice. Must be
 * non-NULL. Must be null-terminated.
 * @expiry - the number of seconds before the invoice
 * expires
 *
 * Returns NULL if label already exists or expiry is 0.
 * FIXME: Fallback addresses
 */
const struct invoice *wallet_invoice_create(struct wallet *wallet,
					    u64 *msatoshi TAKES,
					    const char *label TAKES,
					    u64 expiry);

/**
 * wallet_invoice_find_by_label - Search for an invoice by label
 *
 * @wallet - the wallet to search.
 * @label - the label to search for. Must be null-terminated.
 *
 * Returns NULL if no invoice with that label exists.
 */
const struct invoice *wallet_invoice_find_by_label(struct wallet *wallet,
						   const char *label);

/**
 * wallet_invoice_find_unpaid - Search for an unpaid, unexpired invoice by
 * payment_hash
 *
 * @wallet - the wallet to search.
 * @rhash - the payment_hash to search for.
 *
 * Returns NULL if no invoice with that payment hash exists.
 */
const struct invoice *wallet_invoice_find_unpaid(struct wallet *wallet,
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
			   const struct invoice *invoice);

/**
 * wallet_invoice_iterate - Iterate over all existing invoices
 *
 * @wallet - the wallet whose invoices are to be iterated over.
 * @invoice - the previous invoice you iterated over.
 *
 * Return NULL at end-of-sequence. Usage:
 *
 *   const struct invoice *i;
 *   i = NULL;
 *   while ((i = wallet_invoice_iterate(wallet, i))) {
 *       ...
 *   }
 */
const struct invoice *wallet_invoice_iterate(struct wallet *wallet,
					     const struct invoice *invoice);

/**
 * wallet_invoice_resolve - Mark an invoice as paid
 *
 * @wallet - the wallet containing the invoice.
 * @invoice - the invoice to mark as paid.
 * @msatoshi_received - the actual amount received.
 *
 * Precondition: the invoice must not yet be expired (wallet
 * does not check).
 */
void wallet_invoice_resolve(struct wallet *wallet,
			    const struct invoice *invoice,
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
 * an invoices_resolve call.
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
 * FIXME: actually trigger on expired invoices.
 */
void wallet_invoice_waitone(const tal_t *ctx,
			    struct wallet *wallet,
			    struct invoice const *invoice,
			    void (*cb)(const struct invoice *, void*),
			    void *cbarg);


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
				    struct wallet_channel *chan);

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
 * wallet_payment_get_secrets - Get the secrets array for a given `payment_hash`
 *
 * Returns a tal_array: can return NULL for old dbs.
 */
struct secret *wallet_payment_get_secrets(const tal_t *ctx,
					  struct wallet *wallet,
					  const struct sha256 *payment_hash);

/**
 * wallet_payment_list - Retrieve a list of payments
 *
 * payment_hash: optional filter for only this payment hash.
 */
const struct wallet_payment **wallet_payment_list(const tal_t *ctx,
						  struct wallet *wallet,
						  const struct sha256 *payment_hash);

#endif /* WALLET_WALLET_H */
