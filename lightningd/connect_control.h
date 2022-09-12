#ifndef LIGHTNING_LIGHTNINGD_CONNECT_CONTROL_H
#define LIGHTNING_LIGHTNINGD_CONNECT_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/utils.h>

struct lightningd;
struct peer;
struct pubkey;
struct wireaddr_internal;

/* Speedy reconnect timeout! */
#define DEV_FAST_RECONNECT(dev_fast_reconnect_flag, fast, normal)	\
	IFDEV((dev_fast_reconnect_flag) ? (fast) : (normal), (normal))

/* Returns fd for gossipd to talk to connectd */
int connectd_init(struct lightningd *ld);
void connectd_activate(struct lightningd *ld);

void try_reconnect(const tal_t *ctx,
		   struct peer *peer,
		   const struct wireaddr_internal *addrhint);
void connect_succeeded(struct lightningd *ld, const struct peer *peer,
		       bool incoming,
		       const struct wireaddr_internal *addr);
void connect_failed_disconnect(struct lightningd *ld,
			       const struct node_id *id,
			       const struct wireaddr_internal *addr);

/* Get the id of any connect cmd which applies, to feed to hooks */
const char *connect_any_cmd_id(const tal_t *ctx,
			       struct lightningd *ld, const struct peer *peer);

#endif /* LIGHTNING_LIGHTNINGD_CONNECT_CONTROL_H */
