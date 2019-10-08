#ifndef LIGHTNING_WALLET_BURN_UNIT_H
#define LIGHTNING_WALLET_BURN_UNIT_H

#include "config.h"
#include <common/wallet.h>
#include <wallet/wallet.h>


/**
 * burn_channel_utxos - Spend 'shared' utxos for the given channel
 *
 * Given a set of utxos, spend them and notify the channel peer
 * that this channel is now dead.
 */
void burn_channel_utxos(struct wallet *w,
			const struct utxo **utxos);

/** burn_transactions - Spend 'shared' transactions that
 * have been left in that state for longer than
 * we're comfortable with.
 *
 */
void burn_transactions(struct wallet *w, u32 tip_height);

#endif /* LIGHTNING_WALLET_BURN_UNIT_H */
