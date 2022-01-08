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

/* Set up peer->to_subd; sets fd_for_subd to pass to lightningd. */
bool multiplex_subd_setup(struct peer *peer, int *fd_for_subd);

/* Take over peer_conn as peer->to_peer */
struct io_plan *multiplex_peer_setup(struct io_conn *peer_conn,
				     struct peer *peer);

/* Send this message to peer and disconnect. */
void multiplex_final_msg(struct peer *peer,
			 const u8 *final_msg TAKES);

/* Inject a message into the output stream */
void queue_peer_msg(struct peer *peer, const u8 *msg TAKES);

void setup_peer_gossip_store(struct peer *peer,
			     const struct feature_set *our_features,
			     const u8 *their_features);
#endif /* LIGHTNING_CONNECTD_MULTIPLEX_H */
