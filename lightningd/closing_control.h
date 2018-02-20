#ifndef LIGHTNING_LIGHTNINGD_CLOSING_CONTROL_H
#define LIGHTNING_LIGHTNINGD_CLOSING_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct channel_id;
struct crypto_state;

void peer_start_closingd(struct channel *channel,
			 struct crypto_state *cs,
			 u64 gossip_index,
			 int peer_fd, int gossip_fd,
			 bool reconnected);

#endif /* LIGHTNING_LIGHTNINGD_CLOSING_CONTROL_H */
