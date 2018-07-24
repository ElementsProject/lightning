#ifndef LIGHTNING_CONNECTD_CONNECT_H
#define LIGHTNING_CONNECTD_CONNECT_H
#include "config.h"

struct io_conn;
struct reaching;

struct io_plan *connection_out(struct io_conn *conn, struct reaching *reach);

#endif /* LIGHTNING_CONNECTD_CONNECT_H */
