#ifndef LIGHTNING_DAEMON_P2P_ANNOUNCE_H
#define LIGHTNING_DAEMON_P2P_ANNOUNCE_H
#include "config.h"
#include "daemon/broadcast.h"
#include "daemon/lightningd.h"
#include "daemon/routing.h"
#include "lightningd.h"
#include "wire/gen_peer_wire.h"

void setup_p2p_announce(struct lightningd_state *dstate);

/* Handlers for incoming messages */
void handle_channel_announcement(struct peer *peer, const u8 *announce, size_t len);
void handle_channel_update(struct peer *peer, const u8 *update, size_t len);
void handle_node_announcement(struct peer *peer, const u8 *node, size_t len);

/* Used to announce the existence of a channel and the endpoints */
void announce_channel(struct lightningd_state *dstate, struct peer *peer);

#endif /* LIGHTNING_DAEMON_P2P_ANNOUNCE_H */
