#ifndef LIGHTNING_LIGHTNINGD_CONNECT_CONTROL_H
#define LIGHTNING_LIGHTNINGD_CONNECT_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct lightningd;
struct peer;
struct pubkey;
struct wireaddr_internal;

/* Returns fd for gossipd to talk to connectd */
int connectd_init(struct lightningd *ld);
void connectd_activate(struct lightningd *ld);

void try_reconnect(const tal_t *ctx,
		   struct peer *peer,
		   u32 seconds_delay,
		   const struct wireaddr_internal *addrhint);
void connect_succeeded(struct lightningd *ld, const struct peer *peer,
		       bool incoming,
		       const struct wireaddr_internal *addr);

/* Disconnect a peer (if no subds want to talk any more) */
void maybe_disconnect_peer(struct lightningd *ld, struct peer *peer);

#endif /* LIGHTNING_LIGHTNINGD_CONNECT_CONTROL_H */
