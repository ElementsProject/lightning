#ifndef LIGHTNING_LIGHTNINGD_PAYCODES_H
#define LIGHTNING_LIGHTNINGD_PAYCODES_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <ccan/typesafe_cb/typesafe_cb.h>

struct amount_msat;
struct htlc_in;
struct log;
struct paycodes;
struct preimage;
struct sha256;
struct timerel;
struct timers;
struct wallet;

/**
 * paycodes_new - Constructor for a new paycodes manager.
 *
 * @ctx: owner of the paycodes manager.
 * @wallet: wallet managing invoices (to ensure we do not
 * duplicate hashes).
 * @log: log to report to.
 * @timers: timers object used for expirations.
 */
struct paycodes *paycodes_new(const tal_t *ctx,
			      struct wallet *wallet,
			      struct log *log,
			      struct timers *timers);

/**
 * paycodes_result - Result of paycode add and wait operation.
 *
 * @paycodes_paid: paycode was paid.
 * @paycodes_timeout: paycode timed out.
 * @paycodes_duplicate: hash already exists as either a
 * paycode or invoice.
 *
 * Paycodes are not saved in DB so actual values don't matter.
 */
enum paycodes_result {
	paycodes_paid,
	paycodes_timeout,
	paycodes_duplicate
};

/**
 * paycodes_add_and_wait - Create a paycode, and wait for
 * it to resolve, invoking callback on resolution.
 * Returns immediately without calling callback.
 *
 * @pcs: paycodes manager.
 * @preimage: Preimage to add.
 * @msat_min: minimum amount to accept, inclusive.
 * @msat_max: maximum amount to accept, exclusive.
 * @expire: lifetime of paycode.
 * @cb: Callback to invoke.
 * @arg: Argument of callback.
 */
void paycodes_add_and_wait_(struct paycodes *pcs,
			    const struct preimage *preimage,
			    const struct amount_msat msat_min,
			    const struct amount_msat msat_max,
			    struct timerel expire,
			    void (*cb)(enum paycodes_result, void *),
			    void *arg);
#define paycodes_add_and_wait(pcs, preimage, \
			      msat_min, msat_max, expire, \
			      cb, arg) \
	paycodes_add_and_wait_((pcs), (preimage), \
			       (msat_min), (msat_max), (expire), \
			       typesafe_cb_preargs(void, \
						   void *, \
						   (cb), (arg), \
						   enum paycodes_result), \
			       (arg))

/**
 * paycode_try_pay - process payment for this payment_hash,
 * amount msat.
 * Return true if payment processed, false otherwise.
 *
 * @pcs: paycodes manager.
 * @hin: the input HTLC which is offering to pay.
 * @payment_hash: hash of preimage they want.
 * @msat: amount they offer to pay.
 *
 * If returned true, called either fulfill_htlc() or fail_htlc().
 * If returned false, did not call anything.
 */
bool paycode_try_pay(struct paycodes *pcs,
		     struct htlc_in *hin,
		     const struct sha256 *payment_hash,
		     const struct amount_msat msat);


#endif /* LIGHTNING_LIGHTNINGD_PAYCODES_H */
