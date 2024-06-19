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

bool peer_start_channeld(struct channel *channel,
			 struct peer_fd *peer_fd,
			 const u8 *fwd_msg,
			 bool reconnected,
			 bool reestablish_only);

/* Send message to channeld (if connected) to tell it about depth
 * c.f. dualopen_tell_depth! */
void channeld_tell_depth(struct channel *channel,
			 const struct bitcoin_txid *txid,
			 u32 depth);

/* Notify channels of new blocks. */
void channel_notify_new_block(struct lightningd *ld,
			      u32 block_height);

/* Cancel the channel after `fundchannel_complete` succeeds
 * but before funding broadcasts. */
struct command_result *cancel_channel_before_broadcast(struct command *cmd,
						       struct peer *peer);

/* Update the channel info on channel_ready */
bool channel_on_channel_ready(struct channel *channel,
			      const struct pubkey *next_per_commitment_point,
			      const struct short_channel_id *remote_alias);

/* Record channel open (coin movement notifications) */
void channel_record_open(struct channel *channel, u32 blockheight, bool record_push);

/* A channel has unrecoverably fallen behind */
void channel_fallen_behind(struct channel *channel);

/* Tell channel about new feerates (owner must be channeld!) */
void channel_update_feerates(struct lightningd *ld, const struct channel *channel);

/* This channel is now locked in (the normal way, not zeroconf) */
void lockin_complete(struct channel *channel,
		     enum channel_state expected_state);

/* Accessor for zeroconf to tell us we've actually got an scid */
void lockin_has_completed(struct channel *channel, bool record_push);

/* Watch this incoming splice */
void watch_splice_inflight(struct lightningd *ld,
			   struct channel_inflight *inflight);

/* Update/set scid now this txid is mined. */
bool depthcb_update_scid(struct channel *channel,
			 const struct bitcoin_txid *txid,
			 const struct bitcoin_outpoint *outpoint);
#endif /* LIGHTNING_LIGHTNINGD_CHANNEL_CONTROL_H */
