#ifndef LIGHTNING_DAEMON_CRYPTOPKT_H
#define LIGHTNING_DAEMON_CRYPTOPKT_H
#include "config.h"
#include "lightning.pb-c.h"
#include <ccan/io/io.h>
#include <ccan/typesafe_cb/typesafe_cb.h>

struct io_data;
struct json_connecting;
struct lightningd_state;
struct peer;

struct io_plan *peer_crypto_setup_(struct io_conn *conn,
				   struct lightningd_state *dstate,
				   const struct pubkey *id,
				   struct io_plan *(*cb)(struct io_conn *conn,
						 struct lightningd_state *dstate,
						 struct io_data *iod,
						 const struct pubkey *id,
						 void *arg),
				   void *arg);

#define peer_crypto_setup(conn, dstate, id, cb, arg)			\
	peer_crypto_setup_((conn), (dstate), (id),			\
			   typesafe_cb_preargs(struct io_plan *, void *, \
					       (cb), (arg),		\
					       struct io_conn *,	\
					       struct lightningd_state *, \
					       struct io_data *,	\
					       const struct pubkey *),	\
			   (arg))

/* Reads packet into peer->inpkt/peer->inpkt_len */
struct io_plan *peer_read_packet(struct io_conn *conn,
				 struct peer *peer,
				 struct io_plan *(*cb)(struct io_conn *,
						       struct peer *));

struct io_plan *peer_write_packet(struct io_conn *conn,
				  struct peer *peer,
				  const Pkt *pkt,
				  struct io_plan *(*next)(struct io_conn *,
							  struct peer *));
#endif /* LIGHTNING_DAEMON_CRYPTOPKT_H */
