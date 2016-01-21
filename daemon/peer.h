#ifndef LIGHTNING_DAEMON_PEER_H
#define LIGHTNING_DAEMON_PEER_H
#include "config.h"
#include "netaddr.h"
#include <ccan/list/list.h>

struct peer {
	/* state->peers list */
	struct list_node list;

	/* Global state. */
	struct lightningd_state *state;

	/* The other end's address. */
	struct netaddr addr;

	/* What happened. */
	struct log *log;
};

struct io_conn;
struct io_plan *peer_connected_out(struct io_conn *conn,
				   struct lightningd_state *state,
				   const char *name, const char *port);

void setup_listeners(struct lightningd_state *state, unsigned int portnum);

#endif /* LIGHTNING_DAEMON_PEER_H */
