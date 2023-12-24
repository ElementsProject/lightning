#ifndef LIGHTNING_PLUGINS_RENEPAY_FLOW_H
#define LIGHTNING_PLUGINS_RENEPAY_FLOW_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/htable/htable_type.h>
#include <common/amount.h>
#include <common/gossmap.h>


// TODO(eduardo): a hard coded constant to indicate a limit on any channel
// capacity. Channels for which the capacity is unknown (because they are not
// announced) use this value. It makes sense, because if we don't even know the
// channel capacity the liquidity could be anything but it will never be greater
// than the global number of msats.
// It remains to be checked if this value does not lead to overflow somewhere in
// the code.
#define MAX_CAP (AMOUNT_MSAT(21000000*MSAT_PER_BTC))

/* Any implementation needs to keep some data on channels which are
 * in-use (or about which we have extra information).  We use a hash
 * table here, since most channels are not in use. */
// TODO(eduardo): if we know the liquidity of channel (X,dir) is [A,B]
// then we also know that the liquidity of channel (X,!dir) is [Cap-B,Cap-A].
// This means that it is redundant to store known_min and known_max for both
// halves of the channel and it also means that once we update the knowledge of
// (X,dir) the knowledge of (X,!dir) is updated as well.
struct chan_extra {
	struct short_channel_id scid;
	struct amount_msat capacity;

	struct chan_extra_half {
		/* How many htlcs we've directed through it */
		size_t num_htlcs;

		/* The total size of those HTLCs */
		struct amount_msat htlc_total;

		/* The known minimum / maximum capacity (if nothing known, 0/capacity */
		struct amount_msat known_min, known_max;
	} half[2];
};

bool chan_extra_is_busy(const struct chan_extra *const ce);

static inline const struct short_channel_id
chan_extra_scid(const struct chan_extra *cd)
{
	return cd->scid;
}

static inline size_t hash_scid(const struct short_channel_id scid)
{
	/* scids cost money to generate, so simple hash works here */
	return (scid.u64 >> 32)
		^ (scid.u64 >> 16)
		^ scid.u64;
}

static inline bool chan_extra_eq_scid(const struct chan_extra *cd,
				      const struct short_channel_id scid)
{
	return short_channel_id_eq(&scid, &cd->scid);
}

HTABLE_DEFINE_TYPE(struct chan_extra,
		   chan_extra_scid, hash_scid, chan_extra_eq_scid,
		   chan_extra_map);

/* Helpers for chan_extra_map */
/* Channel knowledge invariants:
 *
 * 	0<=a<=b<=capacity
 *
 * 	a_inv = capacity-b
 * 	b_inv = capacity-a
 *
 * where a,b are the known minimum and maximum liquidities, and a_inv and b_inv
 * are the known minimum and maximum liquidities for the channel in the opposite
 * direction.
 *
 * Knowledge update operations can be:
 *
 * 1. set liquidity (x)
 * 	(a,b) -> (x,x)
 *
 * 	The entropy is minimum here (=0).
 *
 * 2. can send (x):
 * 	xb = min(x,capacity)
 * 	(a,b) -> (max(a,xb),max(b,xb))
 *
 * 	If x<=a then there is no new knowledge and the entropy remains
 * 	the same.
 * 	If x>a the entropy decreases.
 *
 *
 * 3. can't send (x):
 * 	xb = max(0,x-1)
 * 	(a,b) -> (min(a,xb),min(b,xb))
 *
 * 	If x>b there is no new knowledge and the entropy remains.
 * 	If x<=b then the entropy decreases.
 *
 * 4. sent success (x):
 * 	(a,b) -> (max(0,a-x),max(0,b-x))
 *
 * 	If x<=a there is no new knowledge and the entropy remains.
 * 	If a<x then the entropy decreases.
 *
 * 5. relax (x,y):
 *
 * 	(a,b) -> (max(0,a-x),min(capacity,b+y))
 *
 * 	Entropy increases unless it is already maximum.
 * */

const char *fmt_chan_extra_map(
		const tal_t *ctx,
		struct chan_extra_map* chan_extra_map);

/* Returns "" if nothing useful known about channel, otherwise
 * "(details)" */
const char *fmt_chan_extra_details(const tal_t *ctx,
				   const struct chan_extra_map* chan_extra_map,
				   const struct short_channel_id_dir *scidd);

/* Creates a new chan_extra and adds it to the chan_extra_map. */
struct chan_extra *new_chan_extra(
		struct chan_extra_map *chan_extra_map,
		const struct short_channel_id scid,
		struct amount_msat capacity);


/* Helper to find the min of two amounts */
static inline struct amount_msat amount_msat_min(
		struct amount_msat a,
		struct amount_msat b)
{
	return amount_msat_less(a,b) ? a : b;
}
/* Helper to find the max of two amounts */
static inline struct amount_msat amount_msat_max(
		struct amount_msat a,
		struct amount_msat b)
{
	return amount_msat_greater(a,b) ? a : b;
}

/* Update the knowledge that this (channel,direction) can send x msat.*/
bool chan_extra_can_send(const tal_t *ctx,
			 struct chan_extra_map *chan_extra_map,
			 const struct short_channel_id_dir *scidd,
			 struct amount_msat x, char **fail);

/* Update the knowledge that this (channel,direction) cannot send x msat.*/
bool chan_extra_cannot_send(const tal_t *ctx,
			    struct chan_extra_map *chan_extra_map,
			    const struct short_channel_id_dir *scidd,
			    struct amount_msat sent, char **fail);

/* Update the knowledge that this (channel,direction) has liquidity x.*/
bool chan_extra_set_liquidity(const tal_t *ctx,
			      struct chan_extra_map *chan_extra_map,
			      const struct short_channel_id_dir *scidd,
			      struct amount_msat x, char **fail);

/* Update the knowledge that this (channel,direction) has sent x msat.*/
bool chan_extra_sent_success(const tal_t *ctx,
			     struct chan_extra_map *chan_extra_map,
			     const struct short_channel_id_dir *scidd,
			     struct amount_msat x, char **fail);

/* Forget the channel information by a fraction of the capacity. */
bool chan_extra_relax_fraction(const tal_t *ctx, struct chan_extra *ce,
			       double fraction, char **fail);

/* Returns either NULL, or an entry from the hash */
struct chan_extra_half *get_chan_extra_half_by_scid(struct chan_extra_map *chan_extra_map,
						    const struct short_channel_id_dir *scidd);
/* If the channel is not registered, then a new entry is created. scid must be
 * present in the gossmap. */
struct chan_extra_half *
get_chan_extra_half_by_chan_verify(
		const struct gossmap *gossmap,
		struct chan_extra_map *chan_extra_map,
		const struct gossmap_chan *chan,
		int dir);

/* Helper if we have a gossmap_chan */
struct chan_extra_half *get_chan_extra_half_by_chan(const struct gossmap *gossmap,
						    struct chan_extra_map *chan_extra_map,
						    const struct gossmap_chan *chan,
						    int dir);

/* An actual partial flow. */
struct flow {
	const struct gossmap_chan **path;
	/* The directions to traverse. */
	int *dirs;
	/* Amounts for this flow (fees mean this shrinks across path). */
	struct amount_msat *amounts;
	/* Probability of success (0-1) */
	double success_prob;
};

/* Helper to access the half chan at flow index idx */
const struct half_chan *flow_edge(const struct flow *flow, size_t idx);

/* A big number, meaning "don't bother" (not infinite, since you may add) */
#define FLOW_INF_COST 100000000.0

/* Cost function to send @f msat through @c in direction @dir,
 * given we already have a flow of prev_flow. */
double flow_edge_cost(const struct gossmap *gossmap,
		      const struct gossmap_chan *c, int dir,
		      const struct amount_msat known_min,
		      const struct amount_msat known_max,
		      struct amount_msat prev_flow,
		      struct amount_msat f,
		      double mu,
		      double basefee_penalty,
		      double delay_riskfactor);

/* Function to fill in amounts and success_prob for flow. */
bool flow_complete(const tal_t *ctx, struct flow *flow,
		   const struct gossmap *gossmap,
		   struct chan_extra_map *chan_extra_map,
		   struct amount_msat delivered, char **fail);

/* Compute the prob. of success of a set of concurrent set of flows. */
double flowset_probability(const tal_t *ctx, struct flow **flows,
			   const struct gossmap *const gossmap,
			   struct chan_extra_map *chan_extra_map, char **fail);

// TODO(eduardo): we probably don't need this. Instead we should have payflow
// input.
/* Once flow is completed, this can remove it from the extra_map */
bool remove_completed_flow(const tal_t *ctx, const struct gossmap *gossmap,
			   struct chan_extra_map *chan_extra_map,
			   struct flow *flow, char **fail);

// TODO(eduardo): we probably don't need this. Instead we should have payflow
// input.
bool remove_completed_flowset(const tal_t *ctx, const struct gossmap *gossmap,
			      struct chan_extra_map *chan_extra_map,
			      struct flow **flows, char **fail);

bool flowset_fee(struct amount_msat *fee, struct flow **flows);

/*
 * mu (μ) is used as follows in the cost function:
 *
 *     -log((c_e + 1 - f_e) / (c_e + 1)) + μ fee
 *
 * This raises the question of how to set mu?  The left term is a
 * logrithmic failure probability, the right term is the fee in
 * millisats.
 *
 * We want a more "usable" measure of frugality (fr), where fr = 1
 * means that the two terms are roughly equal, and fr < 1 means the
 * probability is more important, and fr > 1 means the fee is more
 * important.
 *
 * For this we take the current payment amount and the median channel
 * capacity and feerates:
 *
 * -log((median_cap + 1 - f_e) / (median_cap + 1)) = μ (1/fr) median_fee
 *
 * => μ = -log((median_cap + 1 - f_e) / (median_cap + 1)) * fr / median_fee
 *
 * But this is slightly too naive!  If we're trying to make a payment larger
 * than the median, this is undefined; and grows hugely when we're near the median.
 * In fact, it should be "the median of all channels larger than the amount",
 * which is what we calculate here.
 *
 * Turns out that in the real network:
 * - median_cap = 1250800000
 * - median_feerate = 51
 *
 * And the log term at the 10th percentile capacity is about 0.125 of the median,
 * and at the 90th percentile capacity the log term is about 12.5 the value at the median.
 *
 * In other words, we expose a simple frugality knob with reasonable
 * range 0.1 (don't care about fees) to 10 (fees before probability),
 * and generate our μ from there.
 */
double derive_mu(const struct gossmap *gossmap,
		 struct amount_msat amount,
		 double frugality);

s64 linear_fee_cost(
		const struct gossmap_chan *c,
		const int dir,
		double base_fee_penalty,
		double delay_feefactor);

// TODO(eduardo): we probably don't need this. Instead we should have payflow
// input.
/* Take the flows and commit them to the chan_extra's . */
bool commit_flow(const tal_t *ctx, const struct gossmap *gossmap,
		 struct chan_extra_map *chan_extra_map, struct flow *flow,
		 char **fail);

// TODO(eduardo): we probably don't need this. Instead we should have payflow
// input.
/* Take the flows and commit them to the chan_extra's .
 * Returns the number of flows successfully commited. */
size_t commit_flowset(const tal_t *ctx, const struct gossmap *gossmap,
		    struct chan_extra_map *chan_extra_map, struct flow **flows,
		    char **fail);

#endif /* LIGHTNING_PLUGINS_RENEPAY_FLOW_H */
