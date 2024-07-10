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

/* Returns fd for gossipd to talk to connectd */
int connectd_init(struct lightningd *ld);
void connectd_activate(struct lightningd *ld);
void connectd_start_shutdown(struct subd *connectd);

/* Kill subds, tell connectd to disconnect once they're drained. */
void force_peer_disconnect(struct lightningd *ld,
			   const struct peer *peer,
			   const char *why);

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

/* Tell connectd about an scid->peer mapping, so it can fwd onion
* messages.  Redundant sends are OK. */
void tell_connectd_scid(struct lightningd *ld,
			struct short_channel_id scid,
			const struct node_id *peer_id);

#endif /* LIGHTNING_LIGHTNINGD_CONNECT_CONTROL_H */
