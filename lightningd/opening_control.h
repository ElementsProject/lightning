#ifndef LIGHTNING_LIGHTNINGD_OPENING_CONTROL_H
#define LIGHTNING_LIGHTNINGD_OPENING_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct channel_id;
struct crypto_state;
struct json_result;
struct lightningd;
struct uncommitted_channel;

void json_add_uncommitted_channel(struct json_result *response,
				  const struct uncommitted_channel *uc);

void peer_start_openingd(struct peer *peer,
			 const struct crypto_state *cs,
			 int peer_fd, int gossip_fd,
			 const u8 *msg);

void kill_uncommitted_channel(struct uncommitted_channel *uc,
			      const char *why);

void tell_connectd_peer_is_important(struct lightningd *ld,
				     const struct channel *channel);
#endif /* LIGHTNING_LIGHTNINGD_OPENING_CONTROL_H */
