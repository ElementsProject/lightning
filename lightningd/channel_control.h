#ifndef LIGHTNING_LIGHTNINGD_CHANNEL_CONTROL_H
#define LIGHTNING_LIGHTNINGD_CHANNEL_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct channel;
struct crypto_state;
struct lightningd;
struct peer_comms;

void peer_start_channeld(struct channel *channel,
			 struct peer_comms *pcomms,
			 const u8 *funding_signed,
			 bool reconnected);

/* Returns true if subd told, otherwise false. */
bool channel_tell_depth(struct lightningd *ld,
				 struct channel *channel,
				 const struct bitcoin_txid *txid,
				 u32 depth);
/* Notify channels of new blocks. */
void channel_notify_new_block(struct lightningd *ld,
			      u32 block_height);

#endif /* LIGHTNING_LIGHTNINGD_CHANNEL_CONTROL_H */
