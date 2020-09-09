#ifndef LIGHTNING_LIGHTNINGD_CHANNEL_CONTROL_H
#define LIGHTNING_LIGHTNINGD_CHANNEL_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct channel;
struct crypto_state;
struct lightningd;
struct per_peer_state;
struct peer;

void peer_start_channeld(struct channel *channel,
			 struct per_peer_state *pps,
			 const u8 *fwd_msg_1,
			 const u8 *fwd_msg_2,
			 bool reconnected);

/* Returns true if subd told, otherwise false. */
bool channel_tell_depth(struct lightningd *ld,
				 struct channel *channel,
				 const struct bitcoin_txid *txid,
				 u32 depth);
/* Notify channels of new blocks. */
void channel_notify_new_block(struct lightningd *ld,
			      u32 block_height);

/* Cancel the channel after `fundchannel_complete` succeeds
 * but before funding broadcasts. */
struct command_result *cancel_channel_before_broadcast(struct command *cmd,
						       struct peer *peer);

/* Forget a channel. Deletes the channel and handles all
 * associated waiting commands, if present. Notifies peer if available */
void forget_channel(struct channel *channel, const char *err_msg);
#endif /* LIGHTNING_LIGHTNINGD_CHANNEL_CONTROL_H */
