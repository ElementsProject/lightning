#ifndef LIGHTNING_PLUGINS_ASKRENE_CHILD_CHILD_H
#define LIGHTNING_PLUGINS_ASKRENE_CHILD_CHILD_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/compiler/compiler.h>
#include <ccan/short_types/short_types.h>
#include <ccan/time/time.h>
#include <common/amount.h>
#include <common/fp16.h>
#include <common/node_id.h>
#include <stdbool.h>

struct additional_cost_htable;
struct gossmap;
struct gossmap_node;
struct json_filter;
struct layer;
struct reserve_htable;

/* For circular (self-rebalance) requests the parent splits the source
 * node in two before forking (see inject_circular_fake in askrene.c):
 * each still-enabled (peer -> source) channel direction is disabled
 * and mirrored, under a fake scid, into a synthetic destination node.
 * This table maps the synthetic side back to reality when serializing
 * routes: a hop over a mirror's fake scid is rewritten to the real
 * (peer -> source) channel, and its node_id_out becomes the real
 * source id.  NULL for normal (non-circular) requests. */
struct circular_unsplit_entry {
	struct short_channel_id fake_scid;
	struct short_channel_id_dir real;
};

struct circular_unsplit {
	/* The real source (== destination) node id. */
	struct node_id source;
	/* tal array: one entry per mirrored channel direction. */
	struct circular_unsplit_entry *entries;
};

/* This is the child.  Do the thing. */
void run_child(const struct gossmap *gossmap,
	       const struct layer **layers,
	       const s8 *biases,
	       const struct additional_cost_htable *additional_costs,
	       struct reserve_htable *reserved,
	       fp16_t *capacities TAKES,
	       bool single_path,
	       struct timemono deadline,
	       const struct gossmap_node *srcnode,
	       const struct gossmap_node *dstnode,
	       struct amount_msat amount, struct amount_msat maxfee,
	       u32 finalcltv, u32 maxdelay, size_t maxparts,
	       bool include_fees,
	       const char *cmd_id,
	       struct json_filter *cmd_filter,
	       bool include_next_node_id,
	       bool include_amount_msat,
	       bool include_delay,
	       const struct circular_unsplit *unsplit,
	       int reply_fd) NORETURN;

#endif /* LIGHTNING_PLUGINS_ASKRENE_CHILD_CHILD_H */

