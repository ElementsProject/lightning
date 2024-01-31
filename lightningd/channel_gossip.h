#ifndef LIGHTNING_LIGHTNINGD_CHANNEL_GOSSIP_H
#define LIGHTNING_LIGHTNINGD_CHANNEL_GOSSIP_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <bitcoin/signature.h>

struct channel;
struct lightningd;
struct peer;
struct peer_update;

/* Initialize channel->channel_gossip state */
void channel_gossip_init(struct channel *channel,
			 const struct peer_update *remote_update TAKES);

/* Something about channel/blockchain changed: update if required */
void channel_gossip_update(struct channel *channel);

/* Short channel id changed (splice, or reorg). */
void channel_gossip_scid_changed(struct channel *channel);

/* Block height changed */
void channel_gossip_notify_new_block(struct lightningd *ld,
				     u32 block_height);

/* Got announcement_signatures from peer */
void channel_gossip_got_announcement_sigs(struct channel *channel,
					  struct short_channel_id scid,
					  const secp256k1_ecdsa_signature *node_sig,
					  const secp256k1_ecdsa_signature *bitcoin_sig);

/* Gossipd told us about a channel update on one of our channels (on loading) */
void channel_gossip_update_from_gossipd(struct channel *channel,
					const u8 *channel_update TAKES);

/* Gossipd init is done: if you expected a channel_update, be
 * disappointed.  */
void channel_gossip_init_done(struct lightningd *ld);

/* Peer has connected. */
void channel_gossip_peer_connected(struct peer *peer);

/* Gossipd sent us this channel_update about the peer's side of the channle */
void channel_gossip_set_remote_update(struct lightningd *ld,
				      const struct peer_update *update TAKES,
				      const struct node_id *source);

/* Get channel_update to send in an error onion reply (can give NULL!) */
const u8 *channel_gossip_update_for_error(const tal_t *ctx,
					  struct channel *channel);

/* Get the peer's last-sent channel_update info, if any. */
const struct peer_update *channel_gossip_get_remote_update(const struct channel *channel);

#endif /* LIGHTNING_LIGHTNINGD_CHANNEL_GOSSIP_H */
