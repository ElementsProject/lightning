#ifndef PETTYCOIN_DNS_H
#define PETTYCOIN_DNS_H
#include "config.h"
#include <ccan/io/io.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>

struct lightningd_state;
struct netaddr;
struct dns_async *dns_resolve_and_connect(struct lightningd_state *state,
		  const char *name, const char *port,
		  struct io_plan *(*init)(struct io_conn *,
					  struct lightningd_state *,
					  const char *name, const char *port));

#endif /* PETTYCOIN_DNS_H */
