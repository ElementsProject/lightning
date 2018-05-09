#ifndef LIGHTNING_GOSSIPD_TOR_H
#define LIGHTNING_GOSSIPD_TOR_H
#include "config.h"
#include <stdbool.h>

struct wireaddr;
struct io_conn;
struct reaching;

bool do_we_use_tor_addr(const struct wireaddr *wireaddrs);

struct io_plan *io_tor_connect(struct io_conn *conn,
			       const struct wireaddr *tor_proxyaddrs,
			       const struct wireaddr *addr,
			       struct reaching *reach);

#endif /* LIGHTNING_GOSSIPD_TOR_H */
