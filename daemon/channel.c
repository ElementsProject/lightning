#include "channel.h"
#include "htlc.h"
#include "remove_dust.h"
#include "type_to_string.h"
#include <assert.h>
#include <ccan/array_size/array_size.h>
#include <ccan/mem/mem.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <inttypes.h>
#include <string.h>

uint64_t fee_by_feerate(size_t txsize, uint64_t fee_rate)
{
	/* FIXME-OLD #2:
	 *
	 * The fee for a transaction MUST be calculated by multiplying this
	 * bytecount by the fee rate, dividing by 1000 and truncating
	 * (rounding down) the result to an even number of satoshis.
	 */
	return txsize * fee_rate / 2000 * 2;
}

/* FIXME-OLD #2:
 *
 * A node MUST use the formula 338 + 32 bytes for every non-dust HTLC
 * as the bytecount for calculating commitment transaction fees.  Note
 * that the fee requirement is unchanged, even if the elimination of
 * dust HTLC outputs has caused a non-zero fee already.
 */
static size_t tx_bytes(size_t num_nondust_htlcs)
{
	return 338 + 32 * num_nondust_htlcs;
}

static uint64_t calculate_fee_msat(size_t num_nondust_htlcs,
				   uint64_t fee_rate)
{
	/* milli-satoshis */
	return fee_by_feerate(tx_bytes(num_nondust_htlcs), fee_rate) * 1000;
}

/* Pay this much fee, if possible.  Return amount unpaid. */
static uint64_t pay_fee(struct channel_oneside *side, uint64_t fee_msat)
{
	if (side->pay_msat >= fee_msat) {
		side->pay_msat -= fee_msat;
		side->fee_msat += fee_msat;
		return 0;
	} else {
		uint64_t remainder = fee_msat - side->pay_msat;
		side->fee_msat += side->pay_msat;
		side->pay_msat = 0;
		return remainder;
	}
}

/* Charge the fee as per FIXME-OLD #2 */
static void recalculate_fees(struct channel_oneside *a,
			     struct channel_oneside *b,
			     uint64_t fee_msat)
{
	uint64_t remainder;

	/* Fold in fees, to recalcuate again below. */
	a->pay_msat += a->fee_msat;
	b->pay_msat += b->fee_msat;
	a->fee_msat = b->fee_msat = 0;

	/* FIXME-OLD #2:
	 *
	 * 1. If each nodes can afford half the fee from their
	 *    to-`final_key` output, reduce the two to-`final_key`
	 *    outputs accordingly.
	 *
	 * 2. Otherwise, reduce the to-`final_key` output of one node
	 *    which cannot afford the fee to zero (resulting in that
	 *    entire output paying fees).  If the remaining
	 *    to-`final_key` output is greater than the fee remaining,
	 *    reduce it accordingly, otherwise reduce it to zero to
	 *    pay as much fee as possible.
	 */
	remainder = pay_fee(a, fee_msat / 2) + pay_fee(b, fee_msat / 2);

	/* If there's anything left, the other side tries to pay for it. */
	remainder = pay_fee(a, remainder);
	pay_fee(b, remainder);
}

/* a transfers htlc_msat to a HTLC (gains it, if -ve) */
static bool change_funding(uint64_t anchor_satoshis,
			   uint64_t fee_rate,
			   int64_t htlc_msat,
			   struct channel_oneside *a,
			   struct channel_oneside *b,
			   size_t num_nondust_htlcs,
			   bool must_afford_fee)
{
	uint64_t fee_msat;
	uint64_t htlcs_total;

	htlcs_total = anchor_satoshis * 1000
		- (a->pay_msat + a->fee_msat + b->pay_msat + b->fee_msat);

	fee_msat = calculate_fee_msat(num_nondust_htlcs, fee_rate);

	/* If A is paying, can it afford it? */
	if (htlc_msat >= 0) {
		uint64_t cost = htlc_msat;
		if (must_afford_fee)
			cost += fee_msat / 2;
		if (cost > a->pay_msat + a->fee_msat)
			return false;
	}

	/* OK, now adjust funds for A, then recalculate fees. */
	a->pay_msat -= htlc_msat;
	recalculate_fees(a, b, fee_msat);

	htlcs_total += htlc_msat;
	assert(htlcs_total == anchor_satoshis * 1000
	       - (a->pay_msat + a->fee_msat + b->pay_msat + b->fee_msat));
	return true;
}

bool anchor_too_large(uint64_t anchor_satoshis)
{
	/* Anchor must fit in 32 bit. */
	return anchor_satoshis >= (1ULL << 32) / 1000;
}

struct channel_state *initial_cstate(const tal_t *ctx,
				      uint64_t anchor_satoshis,
				      uint64_t fee_rate,
				      enum side funding)
{
	uint64_t fee_msat;
	struct channel_state *cstate = talz(ctx, struct channel_state);
	struct channel_oneside *funder, *fundee;

	cstate->fee_rate = fee_rate;
	cstate->anchor = anchor_satoshis;
	cstate->num_nondust = 0;

	/* Anchor must fit in 32 bit. */
	assert(!anchor_too_large(anchor_satoshis));

	fee_msat = calculate_fee_msat(0, fee_rate);
	if (fee_msat > anchor_satoshis * 1000)
		return tal_free(cstate);

	funder = &cstate->side[funding];
	fundee = &cstate->side[!funding];

	/* Neither side has HTLCs. */
	funder->num_htlcs = fundee->num_htlcs = 0;

	/* Initially, all goes back to funder. */
	funder->pay_msat = anchor_satoshis * 1000 - fee_msat;
	funder->fee_msat = fee_msat;

	/* Make sure it checks out. */
	assert(change_funding(anchor_satoshis, fee_rate, 0, funder, fundee, 0, false));
	assert(funder->fee_msat == fee_msat);
	assert(fundee->fee_msat == 0);

	return cstate;
}

/* FIXME: Write exact variant! */
uint64_t approx_max_feerate(const struct channel_state *cstate,
			    enum side side)
{
	uint64_t max_funds;

	max_funds = cstate->side[side].pay_msat + cstate->side[side].fee_msat;

	return max_funds / tx_bytes(cstate->num_nondust);
}

bool can_afford_feerate(const struct channel_state *cstate, uint64_t fee_rate,
			enum side side)
{
	u64 fee_msat = calculate_fee_msat(cstate->num_nondust, fee_rate);

	return cstate->side[side].pay_msat + cstate->side[side].fee_msat
		>= fee_msat;
}

void adjust_fee(struct channel_state *cstate, uint64_t fee_rate)
{
	uint64_t fee_msat;

	fee_msat = calculate_fee_msat(cstate->num_nondust, fee_rate);

	recalculate_fees(&cstate->side[LOCAL], &cstate->side[REMOTE], fee_msat);
}

bool force_fee(struct channel_state *cstate, uint64_t fee)
{
	/* Beware overflow! */
	if (fee > 0xFFFFFFFFFFFFFFFFULL / 1000)
		return false;
	recalculate_fees(&cstate->side[LOCAL], &cstate->side[REMOTE], fee * 1000);
	return cstate->side[LOCAL].fee_msat + cstate->side[REMOTE].fee_msat == fee * 1000;
}

/* Add a HTLC to @creator if it can afford it. */
bool cstate_add_htlc(struct channel_state *cstate, const struct htlc *htlc,
		     bool must_afford_fee)
{
	size_t nondust;
	struct channel_oneside *creator, *recipient;

	creator = &cstate->side[htlc_owner(htlc)];
	recipient = &cstate->side[!htlc_owner(htlc)];

	/* Remember to count the new one in total txsize if not dust! */
	nondust = cstate->num_nondust;
	if (!is_dust(htlc->msatoshi / 1000))
		nondust++;

	if (!change_funding(cstate->anchor, cstate->fee_rate,
			    htlc->msatoshi, creator, recipient, nondust,
			    must_afford_fee))
		return false;

	cstate->num_nondust = nondust;
	creator->num_htlcs++;
	return true;
}

/* Remove htlc from creator, credit it to beneficiary. */
static void remove_htlc(struct channel_state *cstate,
			enum side creator,
			enum side beneficiary,
			const struct htlc *htlc)
{
	size_t nondust;

	/* Remember to remove this one in total txsize if not dust! */
	nondust = cstate->num_nondust;
	if (!is_dust(htlc->msatoshi / 1000)) {
		assert(nondust > 0);
		nondust--;
	}

	/* Can't fail since msatoshi is positive. */
	if (!change_funding(cstate->anchor, cstate->fee_rate,
			    -(int64_t)htlc->msatoshi,
			    &cstate->side[beneficiary],
			    &cstate->side[!beneficiary], nondust, false))
		abort();

	/* Actually remove the HTLC. */
	assert(cstate->side[creator].num_htlcs > 0);
	cstate->side[creator].num_htlcs--;
	cstate->num_nondust = nondust;
}

void cstate_fail_htlc(struct channel_state *cstate, const struct htlc *htlc)
{
	remove_htlc(cstate, htlc_owner(htlc), htlc_owner(htlc), htlc);
}

void cstate_fulfill_htlc(struct channel_state *cstate, const struct htlc *htlc)
{
	remove_htlc(cstate, htlc_owner(htlc), !htlc_owner(htlc), htlc);
}

struct channel_state *copy_cstate(const tal_t *ctx,
				  const struct channel_state *cstate)
{
	return tal_dup(ctx, struct channel_state, cstate);
}

void force_add_htlc(struct channel_state *cstate, const struct htlc *htlc)
{
	struct channel_oneside *creator;

	creator = &cstate->side[htlc_owner(htlc)];
	creator->num_htlcs++;
	creator->pay_msat -= htlc->msatoshi;

	/* Remember to count the new one in total txsize if not dust! */
	if (!is_dust(htlc->msatoshi / 1000))
		cstate->num_nondust++;
}

static void force_remove_htlc(struct channel_state *cstate,
			      enum side beneficiary,
			      const struct htlc *htlc)
{
	cstate->side[beneficiary].pay_msat += htlc->msatoshi;
	cstate->side[htlc_owner(htlc)].num_htlcs--;
	if (!is_dust(htlc->msatoshi / 1000))
		cstate->num_nondust--;
}

void force_fail_htlc(struct channel_state *cstate, const struct htlc *htlc)
{
	force_remove_htlc(cstate, htlc_owner(htlc), htlc);
}

void force_fulfill_htlc(struct channel_state *cstate, const struct htlc *htlc)
{
	force_remove_htlc(cstate, !htlc_owner(htlc), htlc);
}

bool balance_after_force(struct channel_state *cstate)
{
	/* We should not spend more than anchor */
	if (cstate->side[LOCAL].pay_msat + cstate->side[REMOTE].pay_msat
	    > cstate->anchor * 1000)
		return false;

	/* Check for wrap. */
	if (cstate->side[LOCAL].pay_msat > cstate->anchor * 1000)
		return false;
	if (cstate->side[REMOTE].pay_msat > cstate->anchor * 1000)
		return false;

	if (cstate->num_nondust
	    > cstate->side[LOCAL].num_htlcs + cstate->side[REMOTE].num_htlcs)
		return false;

	/* Recalc fees. */
	adjust_fee(cstate, cstate->fee_rate);
	return true;
}

static char *fmt_channel_oneside(const tal_t *ctx,
				 const struct channel_oneside *co)
{
	return tal_fmt(ctx, "{ pay_msat=%u"
		       " fee_msat=%u"
		       " num_htlcs=%u }",
		       co->pay_msat,
		       co->fee_msat,
		       co->num_htlcs);
}

static char *fmt_channel_state(const tal_t *ctx,
			       const struct channel_state *cs)
{
	return tal_fmt(ctx, "{ anchor=%"PRIu64
		       " fee_rate=%"PRIu64
		       " num_nondust=%u"
		       " ours=%s"
		       " theirs=%s }",
		       cs->anchor,
		       cs->fee_rate,
		       cs->num_nondust,
		       fmt_channel_oneside(ctx, &cs->side[LOCAL]),
		       fmt_channel_oneside(ctx, &cs->side[REMOTE]));
}

REGISTER_TYPE_TO_STRING(channel_oneside, fmt_channel_oneside);
REGISTER_TYPE_TO_STRING(channel_state, fmt_channel_state);
