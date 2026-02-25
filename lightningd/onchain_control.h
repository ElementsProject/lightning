#ifndef LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H
#define LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H
#include "config.h"
#include <lightningd/lightningd.h>

struct channel;
struct bitcoin_tx;
struct block;

void onchaind_funding_spent(struct channel *channel,
			    const struct bitcoin_tx *tx,
			    u32 blockheight);

void onchaind_restart_closed_channels(struct lightningd *ld);

/** bwatch handler: "onchaind/txid/<dbid>" — txid confirmed, send depth to onchaind. */
void onchaind_tx_watch_found(struct lightningd *ld,
			     u32 dbid,
			     const struct bitcoin_tx *tx,
			     size_t outnum,
			     u32 blockheight,
			     u32 txindex);

/** bwatch handler: "onchaind/outpoint/<dbid>" — output spent, notify onchaind. */
void onchaind_output_watch_found(struct lightningd *ld,
				 u32 dbid,
				 const struct bitcoin_tx *tx,
				 size_t innum,
				 u32 blockheight,
				 u32 txindex);

/** Send current confirmation depths for all onchaind-tracked txs (per block). */
void onchaind_send_depth_updates(struct channel *channel, u32 blockheight);

#endif /* LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H */
