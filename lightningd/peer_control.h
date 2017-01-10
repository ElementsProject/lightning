#ifndef LIGHTNING_LIGHTNINGD_PEER_CONTROL_H
#define LIGHTNING_LIGHTNINGD_PEER_CONTROL_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <daemon/netaddr.h>
#include <stdbool.h>

struct peer {
	struct lightningd *ld;

	/* Unique ID (works before we know their pubkey) */
	u64 unique_id;

	/* Inside ld->peers. */
	struct list_node list;

	/* What stage is this in?  NULL during first creation. */
	struct subdaemon *owner;

	/* What's happening (doubles as error return for connect_cmd) */
	const char *condition;

	/* History */
	struct log_book *log_book;
	struct log *log;

	/* ID of peer (NULL before initial handshake). */
	struct pubkey *id;

	/* Our fd to the peer (-1 when we don't have it). */
	int fd;

	/* Where we connected to, or it connected from. */
	struct netaddr netaddr;

	/* HSM connection for this peer. */
	int hsmfd;

	/* Json command which made us connect (if any) */
	struct command *connect_cmd;
};

struct peer *peer_by_unique_id(struct lightningd *ld, u64 unique_id);

PRINTF_FMT(2,3) void peer_set_condition(struct peer *peer, const char *fmt, ...);
void setup_listeners(struct lightningd *ld);
#endif /* LIGHTNING_LIGHTNINGD_PEER_CONTROL_H */
