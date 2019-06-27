#include "paycodes.h"

#include <bitcoin/preimage.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/list/list.h>
#include <ccan/structeq/structeq.h>
#include <ccan/time/time.h>
#include <ccan/timer/timer.h>
#include <common/amount.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <lightningd/log.h>
#include <lightningd/peer_htlcs.h>
#include <wallet/wallet.h>
#include <wire/gen_onion_wire.h>

struct paycode {
	struct list_node list;

	struct paycodes *pcs;
	struct preimage payment_preimage;
	struct sha256 payment_hash;
	struct amount_msat msat_min;
	struct amount_msat msat_max;
	void (*cb)(enum paycodes_result, void*);
	void *arg;

	struct oneshot *timer;
};

struct paycodes {
	struct wallet *wallet;
	struct log *log;
	struct timers *timers;

	/* We expect paycodes to be *very* transient and only
	 * rarely used, so a list should be OK.
	 * If this will change in the future, we should use
	 * a hashmap instead.
	 */
	struct list_head paycodes;
};

struct paycodes *paycodes_new(const tal_t *ctx,
			      struct wallet *wallet,
			      struct log *log,
			      struct timers *timers)
{
	struct paycodes *pcs;

	pcs = tal(ctx, struct paycodes);
	pcs->wallet = wallet;
	pcs->log = log;
	pcs->timers = timers;
	list_head_init(&pcs->paycodes);

	return pcs;
}

/* Handle paycode failure. */
struct paycodes_duplicate {
	void (*cb)(enum paycodes_result, void*);
	void *arg;
};
static
void paycodes_duplicate_resolve(struct paycodes_duplicate *pdup)
{
	tal_steal(tmpctx, pdup);
	pdup->cb(paycodes_duplicate, pdup->arg);
}
static
void paycodes_duplicate_error(struct paycodes *pcs,
			      void (*cb)(enum paycodes_result, void *),
			      void *arg)
{
	struct paycodes_duplicate *pdup;

	pdup = tal(pcs, struct paycodes_duplicate);
	pdup->cb = cb;
	pdup->arg = arg;

	/* We use a 0-duration timer, since we promise in our
	 * interface that we will not call the callback before
	 * returning from paycodes_add_and_wait.
	 */
	new_reltimer(pcs->timers, pcs, time_from_sec(0),
		     &paycodes_duplicate_resolve,
		     pdup);
}

/* Handle paycode timeout. */
static
void paycode_expire(struct paycode *paycode)
{
	struct paycodes *pcs = paycode->pcs;

	tal_steal(tmpctx, paycode);
	list_del(&paycode->list);

	log_info(pcs->log, "Timing out temporary paycode hash '%s'",
		 type_to_string(tmpctx,
				struct sha256, &paycode->payment_hash));

	paycode->cb(paycodes_timeout, paycode->arg);
}

/* Create a paycode and wait to be paid or cleaned up. */
void paycodes_add_and_wait_(struct paycodes *pcs,
			    const struct preimage *preimage,
			    const struct amount_msat msat_min,
			    const struct amount_msat msat_max,
			    struct timerel expire,
			    void (*cb)(enum paycodes_result, void *),
			    void *arg)
{
	struct sha256 payment_hash;
	struct invoice invoice;
	struct paycode *paycode;

	sha256(&payment_hash, preimage, sizeof(*preimage));

	/* Check for duplicates. */
	if (wallet_invoice_find_by_rhash(pcs->wallet, &invoice,
					 &payment_hash)) {
		paycodes_duplicate_error(pcs, cb, arg);
		return;
	}
	list_for_each (&pcs->paycodes, paycode, list) {
		if (sha256_eq(&payment_hash, &paycode->payment_hash)) {
			paycodes_duplicate_error(pcs, cb, arg);
			return;
		}
	}

	/* Construct new paycode. */
	paycode = tal(pcs, struct paycode);
	list_node_init(&paycode->list);
	paycode->pcs = pcs;
	paycode->payment_preimage = *preimage;
	paycode->payment_hash = payment_hash;
	paycode->msat_min = msat_min;
	paycode->msat_max = msat_max;
	paycode->cb = cb;
	paycode->arg = arg;

	/* Add to paycodes manager. */
	list_add(&pcs->paycodes, &paycode->list);

	/* Create a timeout. */
	paycode->timer = new_reltimer(pcs->timers, paycode, expire,
				      &paycode_expire, paycode);

	/* Done! */
	return;
}

/* Resolve a payment. */
static
void paycode_resolve(struct paycode *paycode,
		     struct htlc_in *hin)
{
	struct paycodes *pcs = paycode->pcs;

	tal_steal(tmpctx, paycode);
	paycode->timer = tal_free(paycode->timer);
	list_del(&paycode->list);

	log_info(pcs->log, "Resolving temporary paycode hash '%s'",
		 type_to_string(tmpctx,
				struct sha256, &paycode->payment_hash));

	paycode->cb(paycodes_paid, paycode->arg);
	fulfill_htlc(hin, &paycode->payment_preimage);
}

/* Validate value vs. paycode, resolve if acceptable.  */
static
void paycode_validate_and_resolve(struct paycode *paycode,
				  struct htlc_in *hin,
				  const struct amount_msat msat)
{
	struct paycodes *pcs = paycode->pcs;
	bool ok;

	/* Validate amount. */
	ok = true;
	if (ok && amount_msat_less(msat, paycode->msat_min))
		ok = false;
	if (ok && amount_msat_greater(msat, paycode->msat_max))
		ok = false;

	/* Amount ok? */
	if (!ok) {
		log_info(pcs->log,
			 "NOT resolving temporary paycode hash '%s': "
			 "amount %s outside range [%s, %s]",
			 type_to_string(tmpctx,
					struct sha256, &paycode->payment_hash),
			 type_to_string(tmpctx, struct amount_msat,
					&msat),
			 type_to_string(tmpctx, struct amount_msat,
					&paycode->msat_min),
			 type_to_string(tmpctx, struct amount_msat,
					&paycode->msat_max));

		fail_htlc(hin, WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS);
		return;
	}

	/* Validation is fine.  */
	paycode_resolve(paycode, hin);
}

/* Try to see if the paycodes manager has a paycode
 * matching an incoming payment.
 */
bool paycode_try_pay(struct paycodes *pcs,
		     struct htlc_in *hin,
		     const struct sha256 *payment_hash,
		     const struct amount_msat msat)
{
	struct paycode *paycode;
	list_for_each (&pcs->paycodes, paycode, list) {
		if (sha256_eq(payment_hash, &paycode->payment_hash)) {
			paycode_validate_and_resolve(paycode, hin, msat);
			return true;
		}
	}
	return false;
}
