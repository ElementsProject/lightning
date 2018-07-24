#ifndef LIGHTNING_LIGHTNINGD_OPENING_CONTROL_H
#define LIGHTNING_LIGHTNINGD_OPENING_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct channel_id;
struct crypto_state;
struct json_result;
struct lightningd;
struct pubkey;
struct uncommitted_channel;
struct wireaddr_internal;

void json_add_uncommitted_channel(struct json_result *response,
				  const struct uncommitted_channel *uc);

/* Peer has spontaneously exited from gossip due to open msg.  Return
 * NULL if we took over, otherwise hand back to gossipd with this
 * error (allocated off @ctx).
 */
u8 *peer_accept_channel(const tal_t *ctx,
			struct lightningd *ld,
			const struct pubkey *peer_id,
			const struct wireaddr_internal *addr,
			const struct crypto_state *cs,
			const u8 *gfeatures, const u8 *lfeatures,
			int peer_fd, int gossip_fd,
			const struct channel_id *channel_id,
			const u8 *open_msg);

/* Gossipd spat out peer: were we currently asking gossipd to release it
 * so we could open a channel?  Returns true if it took over. */
bool handle_opening_channel(struct lightningd *ld,
			    const struct pubkey *id,
			    const struct wireaddr_internal *addr,
			    const struct crypto_state *cs,
			    const u8 *gfeatures, const u8 *lfeatures,
			    int peer_fd, int gossip_fd);

void kill_uncommitted_channel(struct uncommitted_channel *uc,
			      const char *why);

void tell_connectd_peer_is_important(struct lightningd *ld,
				     const struct channel *channel);
#endif /* LIGHTNING_LIGHTNINGD_OPENING_CONTROL_H */
