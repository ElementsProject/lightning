#ifndef LIGHTNING_DAEMON_CRYPTOPKT_H
#define LIGHTNING_DAEMON_CRYPTOPKT_H
#include "config.h"
#include "lightning.pb-c.h"
#include <ccan/io/io.h>

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

struct io_plan *peer_write_packet(struct io_conn *conn,
				  struct peer *peer,
				  const Pkt *pkt,
				  struct io_plan *(*next)(struct io_conn *,
							  struct peer *));

#endif /* LIGHTNING_DAEMON_CRYPTOPKT_H */
