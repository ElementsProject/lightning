#include "config.h"
#include <common/features.h>
#include <common/timeout.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/htlc_set.h>
#include <lightningd/invoice.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_htlcs.h>

static struct incoming_payment *new_inpay(const tal_t *ctx,
					  struct logger *log,
					  struct amount_msat msat,
					  void (*fail)(void *, const u8 *),
					  void (*succeeded)(void *,
							    const struct preimage *),
					  void *arg)
{
	struct incoming_payment *inpay = tal(ctx, struct incoming_payment);
	inpay->log = log;
	inpay->msat = msat;
	inpay->fail = fail;
	inpay->succeeded = succeeded;
	inpay->arg = arg;
	return inpay;
}

/* If an HTLC times out, we need to free entire set, since we could be
 * processing it in invoice.c right now. */
static void htlc_set_inpay_destroyed(struct incoming_payment *inpay,
				     struct htlc_set *set)
{
	for (size_t i = 0; i < tal_count(set->inpays); i++) {
		if (set->inpays[i] == inpay) {
			/* Don't try to re-fail this HTLC! */
			tal_arr_remove(&set->inpays, i);
			/* Kind of the correct failure code. */
			htlc_set_fail(set, take(towire_mpp_timeout(NULL)));
			return;
		}
	}
	abort();
}

static void destroy_htlc_set(struct htlc_set *set,
			     struct htlc_set_map *map)
{
	htlc_set_map_del(map, set);
}

/* BOLT #4:
 * - MUST fail all HTLCs in the HTLC set after some reasonable
 *   timeout.
 *...
 *   - SHOULD use `mpp_timeout` for the failure message.
 */
static void timeout_htlc_set(struct htlc_set *set)
{
	htlc_set_fail(set, take(towire_mpp_timeout(NULL)));
}

void htlc_set_fail_(struct htlc_set *set, const u8 *failmsg TAKES,
		    const char *file, int line)
{
	/* Don't let local_fail_in_htlc take! */
	if (taken(failmsg))
		tal_steal(set, failmsg);

	for (size_t i = 0; i < tal_count(set->inpays); i++) {
		const u8 *this_failmsg;

		/* Don't remove from set */
		tal_del_destructor2(set->inpays[i], htlc_set_inpay_destroyed, set);

		if (tal_bytelen(failmsg) == 0)
			this_failmsg = towire_incorrect_or_unknown_payment_details(tmpctx, set->inpays[i]->msat, get_block_height(set->ld->topology));
		else
			this_failmsg = failmsg;

		log_debug(set->inpays[i]->log,
			  "failing with %s: %s:%u",
			  onion_wire_name(fromwire_peektype(this_failmsg)),
			  file, line);
		/* Attach inpays[i] to set so it's freed below (not with arg) */
		tal_steal(set->inpays, set->inpays[i]);
		set->inpays[i]->fail(set->inpays[i]->arg, this_failmsg);
	}
	tal_free(set);
}

void htlc_set_fulfill(struct htlc_set *set, const struct preimage *preimage)
{
	for (size_t i = 0; i < tal_count(set->inpays); i++) {
		/* Don't remove from set */
		tal_del_destructor2(set->inpays[i],
				    htlc_set_inpay_destroyed, set);

		/* Reparent set->inpays[i] so it's freed with set */
		tal_steal(set->inpays, set->inpays[i]);
		set->inpays[i]->succeeded(set->inpays[i]->arg, preimage);
	}
	tal_free(set);
}

static struct htlc_set *new_htlc_set(struct lightningd *ld,
				     struct incoming_payment *inpay,
				     const struct sha256 *payment_hash,
				     struct amount_msat total_msat)
{
	struct htlc_set *set;

	set = tal(ld, struct htlc_set);
	set->ld = ld;
	set->total_msat = total_msat;
	set->payment_hash = *payment_hash;
	set->so_far = AMOUNT_MSAT(0);
	set->inpays = tal_arr(set, struct incoming_payment *, 1);
	set->inpays[0] = inpay;

	/* BOLT #4:
	 * - MUST fail all HTLCs in the HTLC set after some reasonable
	 *   timeout.
	 *   - SHOULD wait for at least 60 seconds after the initial
	 *     HTLC.
	 */
	set->timeout = new_reltimer(ld->timers, set, time_from_sec(70),
				    timeout_htlc_set, set);
	htlc_set_map_add(ld->htlc_sets, set);
	tal_add_destructor2(set, destroy_htlc_set, ld->htlc_sets);
	return set;
}

void htlc_set_add_(struct lightningd *ld,
		   struct logger *log,
		   struct amount_msat msat,
		   struct amount_msat total_msat,
		   const struct sha256 *payment_hash,
		   const struct secret *payment_secret,
		   void (*fail)(void *, const u8 *),
		   void (*succeeded)(void *, const struct preimage *),
		   void *arg)
{
	struct incoming_payment *inpay;
	struct htlc_set *set;
	const struct invoice_details *details;
	const char *err;

	/* BOLT #4:
	 * The final node:
	 *   - MUST fail the HTLC if dictated by Requirements under
	 *     [Failure Messages](#failure-messages)
	 *     - Note: "amount paid" specified there is the `total_msat` field.
	 */
	details = invoice_check_payment(tmpctx, ld, payment_hash,
					total_msat, payment_secret, &err);
	if (!details) {
		log_debug(log, "payment failed: %s", err);
		fail(arg, take(failmsg_incorrect_or_unknown(NULL, ld, msat)));
		return;
	}

	/* If we insist on a payment secret, it must always have it */
	if (feature_is_set(details->features, COMPULSORY_FEATURE(OPT_PAYMENT_SECRET))
	    && !payment_secret) {
		log_debug(log,
			  "Missing payment_secret, but required for %s",
			  fmt_sha256(tmpctx, payment_hash));
		fail(arg, take(failmsg_incorrect_or_unknown(NULL, ld, msat)));
		return;
	}

	/* BOLT #4:
	 *  - otherwise, if it supports `basic_mpp`:
	 *    - MUST add it to the HTLC set corresponding to that `payment_hash`.
	 */
	inpay = new_inpay(arg, log, msat, fail, succeeded, arg);
	set = htlc_set_map_get(ld->htlc_sets, payment_hash);
	if (!set)
		set = new_htlc_set(ld, inpay, payment_hash, total_msat);
	else {
		/* BOLT #4:
		 *
		 * otherwise, if it supports `basic_mpp`:
		 * ...
		 *  - otherwise, if the total `amt_to_forward` of this HTLC set is
		 *    less than `total_msat`:
		 * ...
		 *     - MUST require `payment_secret` for all HTLCs in the set.
		 */
		/* We check this now, since we want to fail with this as soon
		 * as possible, to avoid other probing attacks. */
		if (!payment_secret) {
			log_debug(log,
				  "Missing payment_secret, but required for MPP");
			fail(arg, take(failmsg_incorrect_or_unknown(NULL, ld, msat)));
			return;
		}
		tal_arr_expand(&set->inpays, inpay);
	}

	/* Remove from set should hin get destroyed somehow */
	tal_add_destructor2(inpay, htlc_set_inpay_destroyed, set);

	/* BOLT #4:
	 * - SHOULD fail the entire HTLC set if `total_msat` is not
	 *   the same for all HTLCs in the set.
	 */
	if (!amount_msat_eq(total_msat, set->total_msat)) {
		log_unusual(log, "Failing HTLC set %s:"
			    " total_msat %s new htlc total %s",
			    fmt_sha256(tmpctx, &set->payment_hash),
			    fmt_amount_msat(tmpctx, set->total_msat),
			    fmt_amount_msat(tmpctx, total_msat));
		htlc_set_fail(set,
			      take(towire_final_incorrect_htlc_amount(NULL,
								      msat)));
		return;
	}

	if (!amount_msat_accumulate(&set->so_far, msat)) {
		log_unusual(ld->log, "Failing HTLC set %s:"
			    " overflow adding %s+%s",
			    fmt_sha256(tmpctx, &set->payment_hash),
			    fmt_amount_msat(tmpctx, set->so_far),
			    fmt_amount_msat(tmpctx, msat));
		htlc_set_fail(set,
			      take(towire_final_incorrect_htlc_amount(NULL,
								      msat)));
		return;
	}

	log_debug(ld->log,
		  "HTLC set contains %zu HTLCs, for a total of %s out of %s (%spayment_secret)",
		  tal_count(set->inpays),
		  fmt_amount_msat(tmpctx, set->so_far),
		  fmt_amount_msat(tmpctx, total_msat),
		  payment_secret ? "" : "no "
		);

	/* BOLT #4:
	 * - if the total `amt_to_forward` of this HTLC set is equal to or greater than
	 *   `total_msat`:
	 *   - SHOULD fulfill all HTLCs in the HTLC set
	 */
	if (amount_msat_greater_eq(set->so_far, total_msat)) {
		/* Disable timer now, in case invoice_hook is slow! */
		tal_free(set->timeout);
		invoice_try_pay(ld, set, details, set->so_far, NULL);
		return;
	}

	/* BOLT #4:
	 * - otherwise, if the total `amt_to_forward` of this HTLC set is less than
	 *  `total_msat`:
	 *   - MUST NOT fulfill any HTLCs in the HTLC set
	 *...
	 *   - MUST require `payment_secret` for all HTLCs in the set. */
	/* This catches the case of the first payment in a set. */
	if (!payment_secret) {
		htlc_set_fail(set, NULL);
		return;
	}
}
