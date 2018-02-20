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
struct wireaddr;

void json_add_uncommitted_channel(struct json_result *response,
				  const struct uncommitted_channel *uc);

/* Peer has spontaneously exited from gossip due to open msg.  Return
 * NULL if we took over, otherwise hand back to gossipd with this
 * error.
 */
u8 *peer_accept_channel(struct lightningd *ld,
			const struct pubkey *peer_id,
			const struct wireaddr *addr,
			const struct crypto_state *cs,
			u64 gossip_index,
			const u8 *gfeatures, const u8 *lfeatures,
			int peer_fd, int gossip_fd,
			const struct channel_id *channel_id,
			const u8 *open_msg);


void kill_uncommitted_channel(struct uncommitted_channel *uc,
			      const char *why);
#endif /* LIGHTNING_LIGHTNINGD_OPENING_CONTROL_H */
