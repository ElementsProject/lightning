#ifndef LIGHTNING_COMMON_GOSSMAP_H
#define LIGHTNING_COMMON_GOSSMAP_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/take/take.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <common/amount.h>
#include <common/fp16.h>

struct node_id;
struct sciddir_or_pubkey;

struct gossmap_node {
	/* Offset in memory map for node_announce, or 0. */
	u64 nann_off;
	u32 num_chans;
	u32 *chan_idxs;
};

struct gossmap_chan {
	u64 cann_off;
	/* FIXME: Technically redundant */
	u64 plus_scid_off;
	/* Offsets of cupdates (0 if missing).  Logically inside half_chan,
	 * but that would add padding. */
	u64 cupdate_off[2];
	/* two nodes we connect (lesser idx first) */
	struct half_chan {
		/* Top bit indicates it's enabled */
		u32 enabled: 1;
		u32 nodeidx : 31;
		fp16_t htlc_min, htlc_max;

		/* millisatoshi. */
		u64 base_fee : 24;
		/* millionths */
		u64 proportional_fee : 20;
		/* Delay for HTLC in blocks. */
		u64 delay : 20;
	} half[2];
};

/* If num_channel_updates_rejected is not NULL, indicates how many channels we
 * marked inactive because their values were too high to be represented. */
struct gossmap *gossmap_load(const tal_t *ctx, const char *filename,
			     size_t *num_channel_updates_rejected);

/* Version which uses existing fd */
#define gossmap_load_fd(ctx, fd, cupdate_fail, unknown_record, cbarg)	\
	gossmap_load_fd_((ctx), (fd),					\
			 typesafe_cb_preargs(void, void *, (cupdate_fail), (cbarg), \
					     struct gossmap *,		\
					     const struct short_channel_id_dir *, \
					     u16 cltv_expiry_delta,	\
					     u32 fee_base_msat,		\
					     u32 fee_proportional_millionths), \
			 typesafe_cb_preargs(bool, void *, (unknown_record), (cbarg), \
					     struct gossmap *,		\
					     int type,			\
					     u64 off,			\
					     size_t msglen),		\
			 (cbarg))

struct gossmap *gossmap_load_fd_(const tal_t *ctx, int fd,
				 void (*cupdate_fail)(struct gossmap *map,
						      const struct short_channel_id_dir *scidd,
						      u16 cltv_expiry_delta,
						      u32 fee_base_msat,
						      u32 fee_proportional_millionths,
						      void *cb_arg),
				 bool (*unknown_record)(struct gossmap *map,
							int type,
							u64 off,
							size_t msglen,
							void *cb_arg),
				 void *cb_arg);


/* Call this before using to ensure it's up-to-date.  Returns true if something
 * was updated. Note: this can scramble node and chan indexes! */
bool gossmap_refresh(struct gossmap *map, size_t *num_channel_updates_rejected);

/* Call this if you have set unknown_cb, and thus this can fail! */
bool gossmap_refresh_mayfail(struct gossmap *map, bool *updated);

/* Local modifications. */
struct gossmap_localmods *gossmap_localmods_new(const tal_t *ctx);

/* Create a local-only channel; if this conflicts with a real channel when added,
 * that will be used instead.
 * Returns false (and does nothing) if scid was already in localmods.
 */
bool gossmap_local_addchan(struct gossmap_localmods *localmods,
			   const struct node_id *n1,
			   const struct node_id *n2,
			   struct short_channel_id scid,
			   struct amount_msat capacity,
			   const u8 *features)
	NON_NULL_ARGS(1,2,3);

/* Create a local-only channel_update: can apply to lcoal-only or
 * normal channels.  Returns false if amounts don't fit in our
 * internal representation (implies channel unusable anyway).  Any
 * NULL arguments mean "leave as is". */
bool gossmap_local_updatechan(struct gossmap_localmods *localmods,
			      const struct short_channel_id_dir *scidd,
			      const bool *enabled,
			      const struct amount_msat *htlc_min,
			      const struct amount_msat *htlc_max,
			      const struct amount_msat *base_fee,
			      const u32 *proportional_fee,
			      const u16 *delay);

/* Convenience version which sets everything (older API) */
bool gossmap_local_setchan(struct gossmap_localmods *localmods,
			   struct short_channel_id scid,
			   struct amount_msat htlc_min,
			   struct amount_msat htlc_max,
			   struct amount_msat base_fee,
			   u32 proportional_fee,
			   u16 delay,
			   bool enabled,
			   int dir);

/* Apply localmods to this map */
void gossmap_apply_localmods(struct gossmap *map,
			     struct gossmap_localmods *localmods);

/* Remove localmods from this map */
void gossmap_remove_localmods(struct gossmap *map,
			      const struct gossmap_localmods *localmods);

/* Is this channel a localmod? */
bool gossmap_chan_is_localmod(const struct gossmap *map,
			      const struct gossmap_chan *c);

/* Is this channel dying? */
bool gossmap_chan_is_dying(const struct gossmap *map,
			   const struct gossmap_chan *c);

/* Each channel has a unique (low) index. */
u32 gossmap_node_idx(const struct gossmap *map, const struct gossmap_node *node);
u32 gossmap_chan_idx(const struct gossmap *map, const struct gossmap_chan *chan);

struct gossmap_node *gossmap_node_byidx(const struct gossmap *map, u32 idx);
struct gossmap_chan *gossmap_chan_byidx(const struct gossmap *map, u32 idx);

/* Every node_idx/chan_idx will be < these.
 * These values can change across calls to gossmap_check. */
u32 gossmap_max_node_idx(const struct gossmap *map);
u32 gossmap_max_chan_idx(const struct gossmap *map);

/* Find node with this node_id */
struct gossmap_node *gossmap_find_node(const struct gossmap *map,
				       const struct node_id *id);
/* Find chan with this short_channel_id */
struct gossmap_chan *gossmap_find_chan(const struct gossmap *map,
				       const struct short_channel_id *scid);

/* Get the short_channel_id of this chan */
struct short_channel_id gossmap_chan_scid(const struct gossmap *map,
					  const struct gossmap_chan *c);

/* Given a struct node, get the node_id */
void gossmap_node_get_id(const struct gossmap *map,
			 const struct gossmap_node *node,
			 struct node_id *id);

/* Do we have any values for this halfchannel ? */
static inline bool gossmap_chan_set(const struct gossmap_chan *chan, int dir)
{
	return chan->cupdate_off[dir] != 0;
}

/* Return capacity (in msat). */
struct amount_msat gossmap_chan_get_capacity(const struct gossmap *map,
					     const struct gossmap_chan *c);

/* Get the announcement msg which created this chan (NULL for localmods) */
u8 *gossmap_chan_get_announce(const tal_t *ctx,
			      const struct gossmap *map,
			      const struct gossmap_chan *c);

/* Do we have a node_announcement for this onde ? */
static inline bool gossmap_node_announced(const struct gossmap_node *node)
{
	return node->nann_off != 0;
}

/* Get the announcement msg (if any) for this node. */
u8 *gossmap_node_get_announce(const tal_t *ctx,
			      const struct gossmap *map,
			      const struct gossmap_node *n);

/* Return the channel feature bit (odd or even), or -1 if neither. */
int gossmap_chan_get_feature(const struct gossmap *map,
			     const struct gossmap_chan *c,
			     int fbit);

/* Return the channel feature bitmap */
u8 *gossmap_chan_get_features(const tal_t *ctx,
			      const struct gossmap *map,
			      const struct gossmap_chan *c);

/* Return the node feature bit (odd or even), or -1 if neither (or no announcement) */
int gossmap_node_get_feature(const struct gossmap *map,
			     const struct gossmap_node *n,
			     int fbit);

/* Return the node feature bitmap: NULL if no announcement. */
u8 *gossmap_node_get_features(const tal_t *ctx,
			      const struct gossmap *map,
			      const struct gossmap_node *n);

/* Return the channel_update (or NULL if !gossmap_chan_set) */
u8 *gossmap_chan_get_update(const tal_t *ctx,
			    const struct gossmap *map,
			    const struct gossmap_chan *chan,
			    int dir);

/* Return true if we can map this sciddir_or_pubkey to a pubkey. */
bool gossmap_scidd_pubkey(struct gossmap *gossmap,
			  struct sciddir_or_pubkey *sciddpk);

/* Returns details from channel_update (must be gossmap_chan_set)! */
void gossmap_chan_get_update_details(const struct gossmap *map,
				     const struct gossmap_chan *chan,
				     int dir,
				     u32 *timestamp,
				     u8 *message_flags,
				     u8 *channel_flags,
				     u16 *cltv_expiry_delta,
				     u32 *fee_base_msat,
				     u32 *fee_proportional_millionths,
				     struct amount_msat *htlc_minimum_msat,
				     struct amount_msat *htlc_maximum_msat);

/* Given a struct node, get the nth channel, and tell us if we're half[0/1].
 * n must be less than node->num_chans */
struct gossmap_chan *gossmap_nth_chan(const struct gossmap *map,
				      const struct gossmap_node *node,
				      u32 n,
				      int *which_half);

/* Given a struct chan, get the nth node, where n is 0 or 1. */
struct gossmap_node *gossmap_nth_node(const struct gossmap *map,
				      const struct gossmap_chan *chan,
				      int n);

/* Can this channel send this amount? */
bool gossmap_chan_has_capacity(const struct gossmap_chan *chan,
			       int direction,
			       struct amount_msat amount);

/* Convenience routines to get htlc min/max as amount_msat */
static inline struct amount_msat
gossmap_chan_htlc_max(const struct gossmap_chan *chan, const int dir)
{
	return amount_msat(fp16_to_u64(chan->half[dir].htlc_max));
}

static inline struct amount_msat
gossmap_chan_htlc_min(const struct gossmap_chan *chan, const int dir)
{
	return amount_msat(fp16_to_u64(chan->half[dir].htlc_min));
}

/* Remove a channel from the map (warning! realloc can move gossmap_chan
 * and gossmap_node ptrs!) */
void gossmap_remove_chan(struct gossmap *map, struct gossmap_chan *chan);

/* Remove node (by removing all its channels) */
void gossmap_remove_node(struct gossmap *map, struct gossmap_node *node);

/* Unsorted iterate through (do not add/remove channels or nodes!) */
size_t gossmap_num_nodes(const struct gossmap *map);

struct gossmap_node *gossmap_first_node(const struct gossmap *map);
struct gossmap_node *gossmap_next_node(const struct gossmap *map,
				       const struct gossmap_node *prev);

/* Unsorted iterate through (do not add/remove channels or nodes!) */
size_t gossmap_num_chans(const struct gossmap *map);

struct gossmap_chan *gossmap_first_chan(const struct gossmap *map);
struct gossmap_chan *gossmap_next_chan(const struct gossmap *map,
				       struct gossmap_chan *prev);

/* For iterating the gossmap: returns iterator at start. */
struct gossmap_iter *gossmap_iter_new(const tal_t *ctx,
				      const struct gossmap *map);
/* Copy an existing iterator (same offset) */
struct gossmap_iter *gossmap_iter_dup(const tal_t *ctx,
				      const struct gossmap_iter *iter);

/* Get next message, and optional timestamp */
const void *gossmap_stream_next(const tal_t *ctx,
				const struct gossmap *map,
				struct gossmap_iter *iter,
				u32 *timestamp);
/* For fast-forwarding to the given timestamp */
void gossmap_iter_fast_forward(const struct gossmap *map,
			       struct gossmap_iter *iter,
			       u64 timestamp);
/* Moves iterator to the end. */
void gossmap_iter_end(const struct gossmap *map, struct gossmap_iter *iter);

/* For debugging: returns length read, and total known length of file */
u64 gossmap_lengths(const struct gossmap *map, u64 *total);

/* Debugging: connectd wants to enumerate fds */
int gossmap_fd(const struct gossmap *map);
#endif /* LIGHTNING_COMMON_GOSSMAP_H */
