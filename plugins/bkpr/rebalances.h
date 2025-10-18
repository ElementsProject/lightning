#ifndef LIGHTNING_PLUGINS_BKPR_REBALANCES_H
#define LIGHTNING_PLUGINS_BKPR_REBALANCES_H
#include "config.h"

struct command;
struct bkpr;
struct sha256;
struct bitcoin_outpoint;
struct channel_event;

void add_rebalance_pair(struct command *cmd,
			struct bkpr *bkpr,
			u64 created_index1, u64 created_index2);

/* Return NULL, or pointer to the other part of this rebalance pair */
const u64 *find_rebalance(const struct bkpr *bkpr, u64 created_index);

struct rebalances *init_rebalances(const tal_t *ctx,
				   struct command *init_cmd);
#endif /* LIGHTNING_PLUGINS_BKPR_REBALANCES_H */
