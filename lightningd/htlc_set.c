#include "config.h"
#include <common/features.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <lightningd/htlc_set.h>
#include <lightningd/invoice.h>
#include <lightningd/lightningd.h>

/* If an HTLC times out, we need to free entire set, since we could be processing
 * it in invoice.c right now. */
static void htlc_set_hin_destroyed(struct htlc_in *hin,
				   struct htlc_set *set)
{
	for (size_t i = 0; i < tal_count(set->htlcs); i++) {
		if (set->htlcs[i] == hin) {
			/* Don't try to re-fail this HTLC! */
			tal_arr_remove(&set->htlcs, i);
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

void htlc_set_fail(struct htlc_set *set, const u8 *failmsg TAKES)
{
	/* Don't let local_fail_in_htlc take! */
	if (taken(failmsg))
		tal_steal(set, failmsg);

	for (size_t i = 0; i < tal_count(set->htlcs); i++) {
		/* Don't remove from set */
		tal_del_destructor2(set->htlcs[i], htlc_set_hin_destroyed, set);
		local_fail_in_htlc(set->htlcs[i], failmsg);
	}
	tal_free(set);
}

void htlc_set_fulfill(struct htlc_set *set, const struct preimage *preimage)
{
	for (size_t i = 0; i < tal_count(set->htlcs); i++) {
		/* Don't remove from set */
		tal_del_destructor2(set->htlcs[i], htlc_set_hin_destroyed, set);

		/* mark that we filled -- needed for tagging coin mvt */
		set->htlcs[i]->we_filled = tal(set->htlcs[i], bool);
		*set->htlcs[i]->we_filled = true;
		fulfill_htlc(set->htlcs[i], preimage);
	}
	tal_free(set);
}

static struct htlc_set *new_htlc_set(struct lightningd *ld,
				     struct htlc_in *hin,
				     struct amount_msat total_msat)
{
	struct htlc_set *set;

	set = tal(ld, struct htlc_set);
	set->total_msat = total_msat;
	set->payment_hash = hin->payment_hash;
	set->so_far = AMOUNT_MSAT(0);
	set->htlcs = tal_arr(set, struct htlc_in *, 1);
	set->htlcs[0] = hin;

	/* BOLT #4:
	 * - MUST fail all HTLCs in the HTLC set after some reasonable
	 *   timeout.
	 *   - SHOULD wait for at least 60 seconds after the initial
	 *     HTLC.
	 */
	set->timeout = new_reltimer(ld->timers, set, time_from_sec(70),
				    timeout_htlc_set, set);
	htlc_set_map_add(&ld->htlc_sets, set);
	tal_add_destructor2(set, destroy_htlc_set, &ld->htlc_sets);
	return set;
}

void htlc_set_add(struct lightningd *ld,
		  struct htlc_in *hin,
		  struct amount_msat total_msat,
		  const struct secret *payment_secret)
{
	struct htlc_set *set;
	const struct invoice_details *details;

	/* BOLT #4:
	 * The final node:
	 *   - MUST fail the HTLC if dictated by Requirements under
	 *     [Failure Messages](#failure-messages)
	 *     - Note: "amount paid" specified there is the `total_msat` field.
	 */
	details = invoice_check_payment(tmpctx, ld, &hin->payment_hash,
					total_msat, payment_secret);
	if (!details) {
		local_fail_in_htlc(hin,
				   take(failmsg_incorrect_or_unknown(NULL, ld, hin)));
		return;
	}

	/* If we insist on a payment secret, it must always have it */
	if (feature_is_set(details->features, COMPULSORY_FEATURE(OPT_PAYMENT_SECRET))
	    && !payment_secret) {
		log_debug(ld->log, "Missing payment_secret, but required for %s",
			  type_to_string(tmpctx, struct sha256,
					 &hin->payment_hash));
		local_fail_in_htlc(hin,
				   take(failmsg_incorrect_or_unknown(NULL, ld, hin)));
		return;
	}

	/* BOLT #4:
	 *  - otherwise, if it supports `basic_mpp`:
	 *    - MUST add it to the HTLC set corresponding to that `payment_hash`.
	 */
	set = htlc_set_map_get(&ld->htlc_sets, &hin->payment_hash);
	if (!set)
		set = new_htlc_set(ld, hin, total_msat);
	else {
		/* BOLT #4:
		 *
		 * if it supports `basic_mpp`:
		 * ...
		 *  - otherwise, if the total `amount_msat` of this HTLC set is
		 *    less than `total_msat`:
		 * ...
		 *     - MUST require `payment_secret` for all HTLCs in the set.
		 */
		/* We check this now, since we want to fail with this as soon
		 * as possible, to avoid other probing attacks. */
		if (!payment_secret) {
			local_fail_in_htlc(hin, take(failmsg_incorrect_or_unknown(NULL, ld, hin)));
			return;
		}
		tal_arr_expand(&set->htlcs, hin);
	}

	/* Remove from set should hin get destroyed somehow */
	tal_add_destructor2(hin, htlc_set_hin_destroyed, set);

	/* BOLT #4:
	 * - SHOULD fail the entire HTLC set if `total_msat` is not
	 *   the same for all HTLCs in the set.
	 */
	if (!amount_msat_eq(total_msat, set->total_msat)) {
		log_unusual(ld->log, "Failing HTLC set %s:"
			    " total_msat %s new htlc total %s",
			    type_to_string(tmpctx, struct sha256,
					   &set->payment_hash),
			    type_to_string(tmpctx, struct amount_msat,
					   &set->total_msat),
			    type_to_string(tmpctx, struct amount_msat,
					   &total_msat));
		htlc_set_fail(set,
			      take(towire_final_incorrect_htlc_amount(NULL,
								      hin->msat)));
		return;
	}

	/* BOLT #4:
	 * - if the total `amount_msat` of this HTLC set equals `total_msat`:
	 *   - SHOULD fulfill all HTLCs in the HTLC set
	 */
	if (!amount_msat_add(&set->so_far, set->so_far, hin->msat)) {
		log_unusual(ld->log, "Failing HTLC set %s:"
			    " overflow adding %s+%s",
			    type_to_string(tmpctx, struct sha256,
					   &set->payment_hash),
			    type_to_string(tmpctx, struct amount_msat,
					   &set->so_far),
			    type_to_string(tmpctx, struct amount_msat,
					   &hin->msat));
		htlc_set_fail(set,
			      take(towire_final_incorrect_htlc_amount(NULL,
								      hin->msat)));
		return;
	}

	log_debug(ld->log,
		  "HTLC set contains %zu HTLCs, for a total of %s out of %s (%spayment_secret)",
		  tal_count(set->htlcs),
		  type_to_string(tmpctx, struct amount_msat, &set->so_far),
		  type_to_string(tmpctx, struct amount_msat, &total_msat),
		  payment_secret ? "" : "no "
		);

	if (amount_msat_eq(set->so_far, total_msat)) {
		/* Disable timer now, in case invoice_hook is slow! */
		tal_free(set->timeout);
		invoice_try_pay(ld, set, details);
		return;
	}

	/* BOLT #4:
	 * - otherwise, if the total `amount_msat` of this HTLC set is less than
	 *  `total_msat`:
	 *   - MUST NOT fulfill any HTLCs in the HTLC set
	 *...
	 *   - MUST require `payment_secret` for all HTLCs in the set. */
	/* This catches the case of the first payment in a set. */
	if (!payment_secret) {
		htlc_set_fail(set,
			      take(failmsg_incorrect_or_unknown(NULL, ld, hin)));
		return;
	}
}
