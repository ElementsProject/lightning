#ifndef LIGHTNING_LIGHTNINGD_CHANNEL_CONTROL_H
#define LIGHTNING_LIGHTNINGD_CHANNEL_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct channel;
struct crypto_state;
struct lightningd;
struct per_peer_state;

void peer_start_channeld(struct channel *channel,
			 struct per_peer_state *pps,
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

/* A utxo for the funding tx of this channel has been spent,
 * and not for the txid that we were expecting. Clean up this
 * channel, which is now Dead on Arrival.
 *
 * Note that 'maybe' has to do with the fact that for RBF'd
 * channel opens, we may have more eligible txid's issued,
 * so the nullification of one doesn't necessarily guarantee
 * that this channel is dead */
bool maybe_cleanup_channel(struct channel *channel,
			   const struct bitcoin_txid *txid);

/* A utxo for the funding tx of this channel has been
 * spotted as spent. It'll get cleaned up once the
 * transaction bearing the 'borking' utxo spend reaches
 * sufficient depth.
 *
 * Note that 'maybe' has to do with the fact that for RBF'd
 * channel opens, we may have more eligible txid's issued,
 * so the nullification of one doesn't necessarily guarantee
 * that this channel is borked */
bool maybe_bork_channel(struct channel *channel, struct bitcoin_txid *txid,
			struct bitcoin_txid *input_txid, u32 input_outpoint);

/* Cancel the channel after `fundchannel_complete` succeeds
 * but before funding broadcasts. */
struct command_result *cancel_channel_before_broadcast(struct command *cmd,
						       const char *buffer,
						       struct peer *peer,
						       const jsmntok_t *cidtok);

/* Forget a channel. Deletes the channel and handles all
 * associated waiting commands, if present. Notifies peer if available
 * and notify is `true` */
void forget_channel(struct channel *channel, bool notify, const char *err_msg);
#endif /* LIGHTNING_LIGHTNINGD_CHANNEL_CONTROL_H */
