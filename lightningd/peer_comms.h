#ifndef LIGHTNING_LIGHTNINGD_PEER_COMMS_H
#define LIGHTNING_LIGHTNINGD_PEER_COMMS_H
#include "config.h"

#include <ccan/tal/tal.h>
#include <common/crypto_state.h>

/* Things we hand between daemons to talk to peers. */
struct peer_comms {
	struct crypto_state cs;
	/* If not -1, closed on freeing */
	int peer_fd, gossip_fd, gossip_store_fd;
};

struct peer_comms *new_peer_comms(const tal_t *ctx);
#endif /* LIGHTNING_LIGHTNINGD_PEER_COMMS_H */
