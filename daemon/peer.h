#ifndef LIGHTNING_DAEMON_PEER_H
#define LIGHTNING_DAEMON_PEER_H
#include "config.h"
#include <ccan/list/list.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/socket.h>

/* This can be extended to support other protocols in future. */
struct netaddr {
	int type; /* See socket(2): SOCK_STREAM currently */
	int protocol; /* See socket(2): 0 currently */
	socklen_t addrlen;
	union {
		struct sockaddr s;
		struct sockaddr_in ipv4;
		struct sockaddr_in6 ipv6;
	} saddr;
};

struct peer {
	/* state->peers list */
	struct list_node list;

	/* Global state. */
	struct lightningd_state *state;

	/* The other end's address. */
	struct netaddr addr;

	/* What happened. */
	struct log *log;
};

struct io_conn;
struct io_plan *peer_connected_out(struct io_conn *conn,
				   struct lightningd_state *state,
				   const char *name, const char *port);

void setup_listeners(struct lightningd_state *state, unsigned int portnum);

#endif /* LIGHTNING_DAEMON_PEER_H */
