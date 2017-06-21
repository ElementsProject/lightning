#ifndef WALLET_WALLET_H
#define WALLET_WALLET_H

#include "config.h"
#include "db.h"
#include <ccan/tal/tal.h>
#include <lightningd/utxo.h>
#include <wally_bip32.h>

struct wallet {
	struct db *db;
	struct log *log;
	struct ext_key *bip32_base;
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
	htlc_recv = 4
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
				 const struct sha256_double *txid,
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
					u64 *fee_estimate,
					u64 *change_satoshi);

/**
 * wallet_confirm_utxos - Once we've spent a set of utxos, mark them confirmed.
 *
 * May be called once the transaction spending these UTXOs has been
 * broadcast. If something fails use `tal_free(utxos)` instead to undo
 * the reservation.
 */
void wallet_confirm_utxos(struct wallet *w, const struct utxo **utxos);

#endif /* WALLET_WALLET_H */
