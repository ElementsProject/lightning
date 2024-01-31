#ifndef LIGHTNING_GOSSIPD_GOSSIP_GENERATION_H
#define LIGHTNING_GOSSIPD_GOSSIP_GENERATION_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>
#include <stddef.h>

struct chan;
struct daemon;
struct half_chan;
struct local_chan;
struct gossip_store;
struct peer;
struct node;

/* Helper to get non-signature, non-timestamp parts of (valid!) channel_update */
void get_cupdate_parts(const u8 *channel_update,
		       const u8 *parts[2],
		       size_t sizes[2]);


/* Is this channel_update different from prev (not sigs and timestamps)?
 * is_halfchan_defined(hc) must be true! */
bool cupdate_different(struct gossip_store *gs,
		       const struct half_chan *hc,
		       const u8 *cupdate);

/* Is this node_announcement different from prev (not sigs and timestamps)?
 * node->bcast.index must be non-zero! */
bool nannounce_different(struct gossip_store *gs,
			 const struct node *node,
			 const u8 *nannounce,
			 bool *only_missing_tlv);

/* Should we announce our own node?  Called at strategic places. */
void maybe_send_own_node_announce(struct daemon *daemon, bool startup);

#endif /* LIGHTNING_GOSSIPD_GOSSIP_GENERATION_H */
