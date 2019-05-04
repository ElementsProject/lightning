#ifndef LIGHTNING_LIGHTNINGD_CLOSING_CONTROL_H
#define LIGHTNING_LIGHTNINGD_CLOSING_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct channel_id;
struct crypto_state;
struct peer_comms;

void peer_start_closingd(struct channel *channel,
			 struct peer_comms *pcomms,
			 bool reconnected,
			 const u8 *channel_reestablish);

#endif /* LIGHTNING_LIGHTNINGD_CLOSING_CONTROL_H */
