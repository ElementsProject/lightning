#ifndef LIGHTNING_LIGHTNINGD_CLOSING_CONTROL_H
#define LIGHTNING_LIGHTNINGD_CLOSING_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>

struct channel;
struct lightningd;
struct per_peer_state;

void resolve_close_command(struct lightningd *ld, struct channel *channel,
			   bool cooperative);

void peer_start_closingd(struct channel *channel,
			 struct per_peer_state *pps);

#endif /* LIGHTNING_LIGHTNINGD_CLOSING_CONTROL_H */
