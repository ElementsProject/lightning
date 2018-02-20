#ifndef LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H
#define LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct channel;
struct bitcoin_tx;
struct block;

enum watch_result funding_spent(struct channel *channel,
				const struct bitcoin_tx *tx,
				size_t input_num,
				const struct block *block);

#endif /* LIGHTNING_LIGHTNINGD_ONCHAIN_CONTROL_H */
