#ifndef LIGHTNING_LIGHTNINGD_GOSSIP_CONTROL_H
#define LIGHTNING_LIGHTNINGD_GOSSIP_CONTROL_H
#include "config.h"
#include <bitcoin/short_channel_id.h>

struct bitcoin_tx;
struct channel;
struct lightningd;

void gossip_init(struct lightningd *ld, int connectd_fd);

void gossipd_notify_spends(struct lightningd *ld,
			   u32 blockheight,
			   const struct short_channel_id *scids);

void gossip_notify_new_block(struct lightningd *ld);

/* bwatch handler for "gossip/<scid>" (WATCH_SCID).  Replies to gossipd's
 * pending get_txout request, then arms the funding-spent watch.  tx==NULL
 * means the SCID's expected position in the block was empty. */
void gossip_scid_watch_found(struct lightningd *ld,
			     const char *suffix,
			     const struct bitcoin_tx *tx,
			     size_t index,
			     u32 blockheight,
			     u32 txindex);

void gossip_scid_watch_revert(struct lightningd *ld,
			      const char *suffix,
			      u32 blockheight);

/* bwatch handler for "gossip/funding_spent/<scid>" (WATCH_OUTPOINT).  Tells
 * gossipd that the channel is closed. */
void gossip_funding_spent_watch_found(struct lightningd *ld,
				      const char *suffix,
				      const struct bitcoin_tx *tx,
				      size_t index,
				      u32 blockheight,
				      u32 txindex);

void gossip_funding_spent_watch_revert(struct lightningd *ld,
				       const char *suffix,
				       u32 blockheight);

#endif /* LIGHTNING_LIGHTNINGD_GOSSIP_CONTROL_H */
