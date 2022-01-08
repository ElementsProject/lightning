#ifndef LIGHTNING_CONNECTD_MULTIPLEX_H
#define LIGHTNING_CONNECTD_MULTIPLEX_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <common/msg_queue.h>
#include <common/node_id.h>

struct peer {
	struct node_id id;
	struct per_peer_state *pps;

	/* Connection to the peer */
	struct io_conn *to_peer;

	/* Connection to the subdaemon */
	struct io_conn *to_subd;

	/* Final message to send to peer (and hangup) */
	u8 *final_msg;

	/* Input buffers. */
	u8 *subd_in, *peer_in;

	/* Output buffers. */
	struct msg_queue *subd_outq, *peer_outq;

	/* Peer sent buffer (for freeing after sending) */
	const u8 *sent_to_peer;
};

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

#endif /* LIGHTNING_CONNECTD_MULTIPLEX_H */
