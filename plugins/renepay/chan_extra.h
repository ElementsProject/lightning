#ifndef LIGHTNING_PLUGINS_RENEPAY_CHAN_EXTRA_H
#define LIGHTNING_PLUGINS_RENEPAY_CHAN_EXTRA_H

#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/htable/htable_type.h>
#include <common/amount.h>
#include <common/gossmap.h>
#include <plugins/renepay/errorcodes.h>

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

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

		/* The known minimum / maximum capacity (if nothing known,
		 * 0/capacity */
		struct amount_msat known_min, known_max;
	} half[2];
};

bool chan_extra_is_busy(const struct chan_extra *const ce);

static inline const struct short_channel_id
chan_extra_scid(const struct chan_extra *cd)
{
	return cd->scid;
}

static inline bool chan_extra_eq_scid(const struct chan_extra *cd,
				      const struct short_channel_id scid)
{
	return short_channel_id_eq(scid, cd->scid);
}

HTABLE_DEFINE_TYPE(struct chan_extra, chan_extra_scid, short_channel_id_hash,
		   chan_extra_eq_scid, chan_extra_map);

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

const char *fmt_chan_extra_map(const tal_t *ctx,
			       struct chan_extra_map *chan_extra_map);

/* Returns "" if nothing useful known about channel, otherwise
 * "(details)" */
const char *fmt_chan_extra_details(const tal_t *ctx,
				   const struct chan_extra_map *chan_extra_map,
				   const struct short_channel_id_dir *scidd);

/* Creates a new chan_extra and adds it to the chan_extra_map. */
struct chan_extra *new_chan_extra(struct chan_extra_map *chan_extra_map,
				  const struct short_channel_id scid,
				  struct amount_msat capacity);

/* Update the knowledge that this (channel,direction) can send x msat.*/
enum renepay_errorcode
chan_extra_can_send(struct chan_extra_map *chan_extra_map,
		    const struct short_channel_id_dir *scidd);

/* Update the knowledge that this (channel,direction) cannot send x msat.*/
enum renepay_errorcode
chan_extra_cannot_send(struct chan_extra_map *chan_extra_map,
		       const struct short_channel_id_dir *scidd);

enum renepay_errorcode
chan_extra_remove_htlc(struct chan_extra_map *chan_extra_map,
		       const struct short_channel_id_dir *scidd,
		       struct amount_msat amount);

enum renepay_errorcode
chan_extra_commit_htlc(struct chan_extra_map *chan_extra_map,
		       const struct short_channel_id_dir *scidd,
		       struct amount_msat amount);


/* Update the knowledge that this (channel,direction) has liquidity x.*/
enum renepay_errorcode
chan_extra_set_liquidity(struct chan_extra_map *chan_extra_map,
			 const struct short_channel_id_dir *scidd,
			 struct amount_msat min,
			 struct amount_msat max);

/* Update the knowledge that this (channel,direction) has sent x msat.*/
enum renepay_errorcode
chan_extra_sent_success(struct chan_extra_map *chan_extra_map,
			const struct short_channel_id_dir *scidd,
			struct amount_msat x);

/* Forget the channel information by a fraction of the capacity. */
enum renepay_errorcode chan_extra_relax_fraction(struct chan_extra *ce,
						 double fraction);

/* Returns either NULL, or an entry from the hash */
struct chan_extra_half *
get_chan_extra_half_by_scid(struct chan_extra_map *chan_extra_map,
			    const struct short_channel_id_dir *scidd);
/* If the channel is not registered, then a new entry is created. scid must be
 * present in the gossmap. */
struct chan_extra_half *
get_chan_extra_half_by_chan_verify(const struct gossmap *gossmap,
				   struct chan_extra_map *chan_extra_map,
				   const struct gossmap_chan *chan, int dir);

/* Helper if we have a gossmap_chan */
struct chan_extra_half *
get_chan_extra_half_by_chan(const struct gossmap *gossmap,
			    struct chan_extra_map *chan_extra_map,
			    const struct gossmap_chan *chan, int dir);

/* Based on the knowledge that we have and HTLCs, returns the greatest
 * amount that we can send through this channel. */
enum renepay_errorcode channel_liquidity(struct amount_msat *liquidity,
					 const struct gossmap *gossmap,
					 struct chan_extra_map *chan_extra_map,
					 const struct gossmap_chan *chan,
					 const int dir);

/* inputs
 * @chan: a channel
 * @recv: how much can we send to this channels
 *
 * output
 * @max_forward: how much can we ask this channel to forward to the next hop
 * */
enum renepay_errorcode channel_maximum_forward(struct amount_msat *max_forward,
					       const struct gossmap_chan *chan,
					       const int dir,
					       struct amount_msat recv);

/* Assume a uniform distribution:
 * @min, @max: the bounds of liquidity
 * @in_flight: htlcs
 *
 * @f: the amount we want to forward
 *
 * returns the probability that this forward request gets through.
 * */
double edge_probability(struct amount_msat min, struct amount_msat max,
			struct amount_msat in_flight, struct amount_msat f);

/* Checks BOLT 7 HTLC fee condition:
 *	recv >= base_fee + (send*proportional_fee)/1000000 */
bool check_fee_inequality(struct amount_msat recv, struct amount_msat send,
			  u64 base_fee, u64 proportional_fee);

#endif /* LIGHTNING_PLUGINS_RENEPAY_CHAN_EXTRA_H */
