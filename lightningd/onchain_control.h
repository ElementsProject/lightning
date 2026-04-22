#ifndef LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H
#define LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H
#include "config.h"
#include <lightningd/lightningd.h>

struct channel;
struct bitcoin_tx;
struct block;

enum watch_result onchaind_funding_spent(struct channel *channel,
					 const struct bitcoin_tx *tx,
					 u32 blockheight);

void onchaind_replay_channels(struct lightningd *ld);

/* Tear down all bwatch watches that onchaind registered for this channel.
 * Called when the funding-spend tx is reorged out (channel is no longer
 * closing) or when we lose track of an onchaind session for any reason. */
void onchaind_clear_watches(struct channel *channel);

/* bwatch handler "onchaind/outpoint/<dbid>/<txid>": one of the outputs of a tx
 * onchaind asked us to watch was spent.  Forwards the spending tx to onchaind. */
void onchaind_output_watch_found(struct lightningd *ld,
				 const char *suffix,
				 const struct bitcoin_tx *tx,
				 size_t innum,
				 u32 blockheight,
				 u32 txindex);

/* Revert: the spending tx was reorged away.  Drops the entry; onchaind will
 * recover from the re-mined block via its normal depth updates. */
void onchaind_output_watch_revert(struct lightningd *ld,
				  const char *suffix,
				  u32 blockheight);

/* Per-block depth driver: pushes the current depth of every tx onchaind is
 * tracking.  Called from channel_block_processed. */
void onchaind_send_depth_updates(struct channel *channel, u32 blockheight);

/* bwatch depth handler "onchaind/depth/<dbid>/<txid>": delivers the tx's
 * depth to onchaind for CSV / HTLC maturity gates. */
void onchaind_depth_found(struct lightningd *ld,
			  const char *suffix,
			  u32 depth,
			  u32 blockheight);

void onchaind_depth_revert(struct lightningd *ld,
			   const char *suffix,
			   u32 blockheight);

/* bwatch depth handler "onchaind/channel_close/<dbid>:<txid>": persistent
 * restart marker.  Normally a no-op; on crash recovery (channel->owner NULL)
 * looks up the spending tx in our_txs and re-launches onchaind. */
void onchaind_channel_close_depth_found(struct lightningd *ld,
					const char *suffix,
					u32 depth,
					u32 blockheight);

void onchaind_channel_close_depth_revert(struct lightningd *ld,
					 const char *suffix,
					 u32 blockheight);

#endif /* LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H */
