#ifndef LIGHTNING_LIGHTNINGD_PEER_CONTROL_H
#define LIGHTNING_LIGHTNINGD_PEER_CONTROL_H
#include "config.h"
#include <stdbool.h>

struct peer {
	struct lightningd *ld;

	/* Unique ID (works before we know their pubkey) */
	u64 unique_id;

	/* Inside ld->peers. */
	struct list_node list;

	/* What stage is this in? */
	struct subdaemon *owner;

	/* ID of peer (NULL before initial handshake). */
	struct pubkey *id;

	/* Our fd to the peer. */
	int fd;

	/* HSM connection for this peer. */
	int hsmfd;

	/* Json command which made us connect (if any) */
	struct command *connect_cmd;
};

struct peer *peer_by_unique_id(struct lightningd *ld, u64 unique_id);

void setup_listeners(struct lightningd *ld);
#endif /* LIGHTNING_LIGHTNINGD_PEER_CONTROL_H */
