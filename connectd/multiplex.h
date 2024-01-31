#ifndef LIGHTNING_CONNECTD_MULTIPLEX_H
#define LIGHTNING_CONNECTD_MULTIPLEX_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <common/crypto_state.h>
#include <common/msg_queue.h>
#include <common/node_id.h>

struct peer;
struct io_conn;
struct feature_set;

/* Take over peer_conn as peer->to_peer */
struct io_plan *multiplex_peer_setup(struct io_conn *peer_conn,
				     struct peer *peer);

/* Inject a message into the output stream.  Unlike a raw msg_enqueue,
 * this does io logging. */
void inject_peer_msg(struct peer *peer, const u8 *msg TAKES);

void setup_peer_gossip_store(struct peer *peer,
			     const struct feature_set *our_features,
			     const u8 *their_features);

/* When lightningd says to send a ping */
void send_manual_ping(struct daemon *daemon, const u8 *msg);

/* When lightningd says to send a custom message (from a plugin) */
void send_custommsg(struct daemon *daemon, const u8 *msg);

/* When lightningd says what custom messages we can recv */
void set_custommsgs(struct daemon *daemon, const u8 *msg);

/* Lightningd wants to talk to you. */
void peer_connect_subd(struct daemon *daemon, const u8 *msg, int fd);

/* Start shutting down peer. */
void drain_peer(struct peer *peer);

#endif /* LIGHTNING_CONNECTD_MULTIPLEX_H */
