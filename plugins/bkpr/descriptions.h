#ifndef LIGHTNING_PLUGINS_BKPR_DESCRIPTIONS_H
#define LIGHTNING_PLUGINS_BKPR_DESCRIPTIONS_H
#include "config.h"

struct command;
struct bkpr;
struct sha256;
struct bitcoin_outpoint;
struct chain_event;
struct channel_event;

void add_payment_hash_description(struct command *cmd,
				  struct bkpr *bkpr,
				  const struct sha256 *payment_hash,
				  const char *desc);

void add_utxo_description(struct command *cmd,
			  struct bkpr *bkpr,
			  const struct bitcoin_outpoint *outpoint,
			  const char *desc);

const char *chain_event_description(const struct bkpr *bkpr,
				    const struct chain_event *ce);

const char *channel_event_description(const struct bkpr *bkpr,
				      const struct channel_event *ce);

struct descriptions *init_descriptions(const tal_t *ctx,
				       struct command *init_cmd);
#endif /* LIGHTNING_PLUGINS_BKPR_DESCRIPTIONS_H */
