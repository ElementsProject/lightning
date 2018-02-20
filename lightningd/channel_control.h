#ifndef LIGHTNING_LIGHTNINGD_CHANNEL_CONTROL_H
#define LIGHTNING_LIGHTNINGD_CHANNEL_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct channel;
struct crypto_state;

bool peer_start_channeld(struct channel *channel,
			 const struct crypto_state *cs,
			 u64 gossip_index,
			 int peer_fd, int gossip_fd,
			 const u8 *funding_signed,
			 bool reconnected);

#endif /* LIGHTNING_LIGHTNINGD_CHANNEL_CONTROL_H */
