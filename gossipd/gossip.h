#ifndef LIGHTNING_GOSSIPD_GOSSIP_H
#define LIGHTNING_GOSSIPD_GOSSIP_H
#include "config.h"

struct io_conn;
struct reaching;

struct io_plan *connection_out(struct io_conn *conn, struct reaching *reach);

#endif /* LIGHTNING_GOSSIPD_GOSSIP_H */
