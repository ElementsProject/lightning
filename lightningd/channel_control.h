#ifndef LIGHTNING_LIGHTNINGD_CHANNEL_CONTROL_H
#define LIGHTNING_LIGHTNINGD_CHANNEL_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct channel;
struct crypto_state;
struct lightningd;
struct peer_fd;
struct peer;

void peer_start_channeld(struct channel *channel,
			 struct peer_fd *peer_fd,
			 const u8 *fwd_msg,
			 bool reconnected,
			 const u8 *reestablish_only);

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

/* Update the channel info on funding locked */
bool channel_on_funding_locked(struct channel *channel,
			       struct pubkey *next_per_commitment_point);

/* Record channel open (coin movement notifications) */
void channel_record_open(struct channel *channel);

/* A channel has unrecoverably fallen behind */
void channel_fallen_behind(struct channel *channel, const u8 *msg);

/* Fresh channel_update for this channel. */
void channel_replace_update(struct channel *channel, u8 *update TAKES);

#endif /* LIGHTNING_LIGHTNINGD_CHANNEL_CONTROL_H */
