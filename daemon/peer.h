#ifndef LIGHTNING_DAEMON_PEER_H
#define LIGHTNING_DAEMON_PEER_H
#include "config.h"
#include "lightning.pb-c.h"
#include "netaddr.h"
#include <ccan/list/list.h>

struct peer {
	/* state->peers list */
	struct list_node list;

	/* Global state. */
	struct lightningd_state *state;

	/* The other end's address. */
	struct netaddr addr;

	/* Their ID. */
	struct pubkey id;

	/* Current received packet. */
	Pkt *inpkt;
	
	/* Current ongoing packetflow */
	struct io_data *io_data;
	
	/* What happened. */
	struct log *log;
};

void setup_listeners(struct lightningd_state *state, unsigned int portnum);

#endif /* LIGHTNING_DAEMON_PEER_H */
