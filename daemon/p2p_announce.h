#ifndef LIGHTNING_DAEMON_P2P_ANNOUNCE_H
#define LIGHTNING_DAEMON_P2P_ANNOUNCE_H
#include "config.h"
#include "daemon/broadcast.h"
#include "daemon/lightningd.h"
#include "daemon/routing.h"
#include "lightningd.h"
#include "wire/gen_peer_wire.h"

void setup_p2p_announce(struct lightningd_state *dstate);

/* Used to announce the existence of a channel and the endpoints */
void announce_channel(struct lightningd_state *dstate, struct peer *peer);

#endif /* LIGHTNING_DAEMON_P2P_ANNOUNCE_H */
