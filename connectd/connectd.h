#ifndef LIGHTNING_CONNECTD_CONNECTD_H
#define LIGHTNING_CONNECTD_CONNECTD_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <common/crypto_state.h>

struct io_conn;
struct connecting;
struct daemon;

/* Called by io_tor_connect once it has a connection out. */
struct io_plan *connection_out(struct io_conn *conn, struct connecting *connect);

/* Called by peer_exchange_initmsg if successful. */
struct io_plan *peer_connected(struct io_conn *conn,
			       struct daemon *daemon,
			       const struct pubkey *id TAKES,
			       const u8 *peer_connected_msg TAKES,
			       const u8 *lfeatures TAKES);

#endif /* LIGHTNING_CONNECTD_CONNECTD_H */
