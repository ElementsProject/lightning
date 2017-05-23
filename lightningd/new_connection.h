#ifndef LIGHTNING_LIGHTNINGD_NEW_CONNECTION_H
#define LIGHTNING_LIGHTNINGD_NEW_CONNECTION_H
#include "config.h"
#include <stdbool.h>

struct command;
struct io_conn;
struct lightningd;
struct lightningd_state;
struct netaddr;
struct pubkey;

struct connection *new_connection(const tal_t *ctx,
				  struct lightningd *ld,
				  struct command *cmd,
				  const struct pubkey *known_id);

struct io_plan *connection_out(struct io_conn *conn,
			       struct lightningd_state *dstate,
			       const struct netaddr *netaddr,
			       struct connection *c);

struct io_plan *connection_in(struct io_conn *conn, struct lightningd *ld);

const struct pubkey *connection_known_id(const struct connection *c);
#endif /* LIGHTNING_LIGHTNINGD_NEW_CONNECTION_H */
