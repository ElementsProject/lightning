#ifndef LIGHTNING_LIGHTNINGD_CLOSING_CONTROL_H
#define LIGHTNING_LIGHTNINGD_CLOSING_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct bitcoin_tx;
struct channel;
struct lightningd;
struct peer_fd;

/* Sanity-check a close tx from a (simple)closing subdaemon before
 * we store and broadcast it: exactly one input spending our funding outpoint,
 * a closing-shaped tx (not a commitment), and every output to a known shutdown
 * script (or a zero-value OP_RETURN with option_simple_close).  Returns an
 * error string (child of @ctx), or NULL if it looks like a valid close. */
const char *close_tx_check(const tal_t *ctx,
			   const struct channel *channel,
			   const struct bitcoin_tx *tx);

/* Find cmd_id for closing command, if any. */
const char *cmd_id_from_close_command(const tal_t *ctx,
				      struct lightningd *ld, struct channel *channel);

/* Resolve a close command for a channel that will be closed soon. */
void resolve_close_command(struct lightningd *ld, struct channel *channel,
			   bool cooperative, const struct bitcoin_tx **close_txs);

void peer_start_closingd(struct channel *channel,
			 struct peer_fd *peer_fd);

#endif /* LIGHTNING_LIGHTNINGD_CLOSING_CONTROL_H */
