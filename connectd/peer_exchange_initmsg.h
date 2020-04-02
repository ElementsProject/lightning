#ifndef LIGHTNING_CONNECTD_PEER_EXCHANGE_INITMSG_H
#define LIGHTNING_CONNECTD_PEER_EXCHANGE_INITMSG_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct crypto_state;
struct daemon;
struct io_conn;
struct node_id;
struct wireaddr_internal;

/* If successful, calls peer_connected() */
struct io_plan *peer_exchange_initmsg(struct io_conn *conn,
				      struct daemon *daemon,
				      const struct feature_set *fset,
				      const struct crypto_state *cs,
				      const struct node_id *id,
				      const struct wireaddr_internal *addr);

#endif /* LIGHTNING_CONNECTD_PEER_EXCHANGE_INITMSG_H */
