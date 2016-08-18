#ifndef LIGHTNING_DAEMON_NETADDR_H
#define LIGHTNING_DAEMON_NETADDR_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>

struct addrinfo;

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

/* Get the name for this netaddr. */
char *netaddr_name(const tal_t *ctx, const struct netaddr *a);

/* Create a addrinfo (as wanted by io_connect) for this address. */
void netaddr_to_addrinfo(struct addrinfo *ai, const struct netaddr *a);

bool netaddr_from_fd(int fd, int type, int protocol, struct netaddr *a);

bool netaddr_from_blob(const void *linear, size_t len, struct netaddr *a);
char *netaddr_to_hex(const tal_t *ctx, const struct netaddr *a);

#endif /* LIGHTNING_DAEMON_NETADDR_H */
