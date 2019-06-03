#ifndef LIGHTNING_LIGHTNINGD_CLOSING_CONTROL_H
#define LIGHTNING_LIGHTNINGD_CLOSING_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct channel_id;
struct crypto_state;
struct per_peer_state;

void peer_start_closingd(struct channel *channel,
			 struct per_peer_state *pps,
			 bool reconnected,
			 const u8 *channel_reestablish);

#endif /* LIGHTNING_LIGHTNINGD_CLOSING_CONTROL_H */
