#ifndef LIGHTNING_PLUGINS_BKPR_BLOCKHEIGHTS_H
#define LIGHTNING_PLUGINS_BKPR_BLOCKHEIGHTS_H
#include "config.h"

struct command;
struct bkpr;
struct bitcoin_txid;

void add_blockheight(struct command *cmd,
		     struct bkpr *bkpr,
		     const struct bitcoin_txid *txid,
		     u32 blockheight);

/* Returns blockheight for this txid, or 0 if not found. */
u32 find_blockheight(const struct bkpr *bkpr, const struct bitcoin_txid *txid);

struct blockheights *init_blockheights(const tal_t *ctx,
				       struct command *init_cmd);
#endif /* LIGHTNING_PLUGINS_BKPR_BLOCKHEIGHTS_H */
