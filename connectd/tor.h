#ifndef LIGHTNING_CONNECTD_TOR_H
#define LIGHTNING_CONNECTD_TOR_H
#include "config.h"
#include <stdbool.h>

struct addrinfo;
struct wireaddr;
struct io_conn;
struct reaching;

struct io_plan *io_tor_connect(struct io_conn *conn,
			       const struct addrinfo *tor_proxyaddr,
			       const char *host, u16 port,
			       struct reaching *reach);

#endif /* LIGHTNING_CONNECTD_TOR_H */
