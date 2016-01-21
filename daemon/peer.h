#ifndef LIGHTNING_DAEMON_PEER_H
#define LIGHTNING_DAEMON_PEER_H
#include "config.h"
#include "bitcoin/pubkey.h"
#include "lightning.pb-c.h"
#include "netaddr.h"
#include "state_types.h"
#include <ccan/list/list.h>

struct peer_visible_state {
	/* CMD_OPEN_WITH_ANCHOR or CMD_OPEN_WITHOUT_ANCHOR */
	enum state_input offer_anchor;
	/* Key for commitment tx inputs, then key for commitment tx outputs */
	struct pubkey commitkey, finalkey;
	/* How long to they want the other's outputs locked (seconds) */
	unsigned int locktime;
	/* Minimum depth of anchor before channel usable. */
	unsigned int mindepth;
	/* Commitment fee they're offering (satoshi). */
	u64 commit_fee;
};

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

	/* Things we're watching for (see watches.c) */
	struct list_head watches;

	/* Private keys for dealing with this peer. */
	struct peer_secrets *secrets;

	/* Stuff we have in common. */
	struct peer_visible_state us, them;
};

void setup_listeners(struct lightningd_state *state, unsigned int portnum);

#endif /* LIGHTNING_DAEMON_PEER_H */
