#ifndef LIGHTNING_LIGHTNINGD_CLOSING_CONTROL_H
#define LIGHTNING_LIGHTNINGD_CLOSING_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct channel;
struct lightningd;
struct peer_fd;

/* Find cmd_id for closing command, if any. */
const char *cmd_id_from_close_command(const tal_t *ctx,
				      struct lightningd *ld, struct channel *channel);

/* Resolve a close command for a channel that will be closed soon. */
void resolve_close_command(struct lightningd *ld, struct channel *channel,
			   bool cooperative, const struct bitcoin_tx **close_txs);

void peer_start_closingd(struct channel *channel,
			 struct peer_fd *peer_fd);

#endif /* LIGHTNING_LIGHTNINGD_CLOSING_CONTROL_H */
