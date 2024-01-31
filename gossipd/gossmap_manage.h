#ifndef LIGHTNING_GOSSIPD_GOSSMAP_MANAGE_H
#define LIGHTNING_GOSSIPD_GOSSMAP_MANAGE_H
#include "config.h"

struct daemon;
struct gossmap_manage;

struct gossmap_manage *gossmap_manage_new(const tal_t *ctx,
					  struct daemon *daemon);

/* Minimal gossmap-only transition constructor */
struct gossmap_manage *gossmap_manage_new_gossmap_only(const tal_t *ctx,
						       struct daemon *daemon);

/**
 * gossmap_manage_channel_announcement: process an incoming channel_announcement
 * @ctx: tal context for return string
 * @gm: the gossmap_manage context
 * @announce: the channel_announcement message
 * @source_peer: peer who sent this (NULL if it's from lightningd)
 * @known_amount: if non-NULL, do not ask lightningd to look up UTXO.
 *
 * Returns an error string if it wasn't redundant or included.  Lightningd
 * suppresses lookups if it generated the announcement, partially because it's
 * redundant, but also because in our tests the UTXO is often spent by the time
 * it processes the lookup!
 */
const char *gossmap_manage_channel_announcement(const tal_t *ctx,
						struct gossmap_manage *gm,
						const u8 *announce TAKES,
						const struct node_id *source_peer TAKES,
						const struct amount_sat *known_amount);


/**
 * gossmap_manage_handle_get_txout_reply: process a txout reply from lightningd
 * @gm: the gossmap_manage context
 * @msg: the message
 *
 * Since handle_channel_announcement asks lightning for utxos,
 * it gets called back here.
 */
void gossmap_manage_handle_get_txout_reply(struct gossmap_manage *gm, const u8 *msg);

/**
 * gossmap_manage_channel_update: process an incoming channel_update
 * @ctx: tal context for return string
 * @gm: the gossmap_manage context
 * @update: the channel_update message
 * @source_peer: optional peer who sent this
 *
 * Returns an error string if it wasn't redundant or included.
 */
const char *gossmap_manage_channel_update(const tal_t *ctx,
					  struct gossmap_manage *gm,
					  const u8 *update TAKES,
					  const struct node_id *source_peer TAKES);

/**
 * gossmap_manage_node_announcement: process an incoming node_announcement
 * @ctx: tal context for return string allocation
 * @gm: the gossmap_manage context
 * @node_announcement: the node_announcement message
 * @source_peer: optional peer who sent this
 *
 * Returns an error string if it wasn't redundant or included.
 */
const char *gossmap_manage_node_announcement(const tal_t *ctx,
					     struct gossmap_manage *gm,
					     const u8 *node_announcement TAKES,
					     const struct node_id *source_peer TAKES);

/**
 * gossmap_manage_new_block: handle block height update.
 * @gm: the gossmap_manage context
 * @new_blockheight: the new blockheight
 */
void gossmap_manage_new_block(struct gossmap_manage *gm, u32 new_blockheight);

/**
 * gossmap_manage_channel_spent: handle an UTXO being spent
 * @gm: the gossmap_manage context
 * @blockheight: the blockheight it was spent at
 * @scid: the short_channel_id
 *
 * lightningd tells us all the possible UTXOs spent every block: most
 * don't match channels.
 */
void gossmap_manage_channel_spent(struct gossmap_manage *gm,
				  u32 blockheight,
				  struct short_channel_id scid);

/**
 * gossmap_manage_channel_dying: dying channel loaded from store.
 * @gm: the gossmap_manage context
 * @offset: the offset of the dying marker in the store.
 * @deadline: the blockheight it is to expire
 * @scid: the short_channel_id
 *
 * Returns false if this channel does not exist (already dead!).
 */
bool gossmap_manage_channel_dying(struct gossmap_manage *gm,
				  u64 gossmap_offset,
				  u32 deadline,
				  struct short_channel_id scid);

/**
 * gossmap_manage_get_gossmap: get the (refreshed!) gossmap
 * @gm: the gossmap_manage context
 */
struct gossmap *gossmap_manage_get_gossmap(struct gossmap_manage *gm);

/**
 * gossmap_manage_new_peer: send all our own gossip to this peer.
 * @gm: the gossmap_manage context
 * @peer: the node_id of the peer.
 */
void gossmap_manage_new_peer(struct gossmap_manage *gm,
			     const struct node_id *peer);

/**
 * gossmap_manage_get_node_addresses: get addresses for this node.
 * @ctx: the allocation context
 * @gm: the gossmap_manage context
 * @node_id: the node_id to look up
 *
 * Returns NULL if we don't have node_announcement for it.
 */
struct wireaddr *gossmap_manage_get_node_addresses(const tal_t *ctx,
						   struct gossmap_manage *gm,
						   const struct node_id *node_id);

/**
 * gossmap_manage_tell_lightningd_locals: tell lightningd our latest updates.
 * @daemon: the gossip daemon
 * @gm: the gossmap_manage context
 *
 * Done before we reply to gossipd_init.
 */
void gossmap_manage_tell_lightningd_locals(struct daemon *daemon,
					   struct gossmap_manage *gm);
#endif /* LIGHTNING_GOSSIPD_GOSSMAP_MANAGE_H */
