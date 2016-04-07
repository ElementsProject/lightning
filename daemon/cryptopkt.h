#ifndef LIGHTNING_DAEMON_CRYPTOPKT_H
#define LIGHTNING_DAEMON_CRYPTOPKT_H
#include "config.h"
#include "lightning.pb-c.h"
#include <ccan/io/io.h>
#include <ccan/typesafe_cb/typesafe_cb.h>

struct peer;

struct io_plan *peer_crypto_setup(struct io_conn *conn,
				  struct peer *peer,
				  struct io_plan *(*cb)(struct io_conn *,
							struct peer *));

/* Reads packet into peer->inpkt/peer->inpkt_len */
struct io_plan *peer_read_packet(struct io_conn *conn,
				 struct peer *peer,
				 struct io_plan *(*cb)(struct io_conn *,
						       struct peer *));

struct io_plan *peer_write_packet_(struct io_conn *conn,
				   struct peer *peer,
				   const Pkt *pkt,
				   void (*ack_cb)(struct peer *peer, void *),
				   void *ack_arg,
				   struct io_plan *(*next)(struct io_conn *,
							   struct peer *));

#define peer_write_packet(conn, peer, pkt, ack_cb, ack_arg, next) \
	peer_write_packet_((conn), (peer), (pkt),			\
			   typesafe_cb_preargs(void, void *,		\
					       (ack_cb), (ack_arg),	\
					       struct peer *),		\
			   (ack_arg), (next))
#endif /* LIGHTNING_DAEMON_CRYPTOPKT_H */
