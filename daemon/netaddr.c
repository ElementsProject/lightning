#include "netaddr.h"
#include <arpa/inet.h>
#include <ccan/cast/cast.h>
#include <ccan/tal/str/str.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>

void netaddr_to_addrinfo(struct addrinfo *ai, const struct netaddr *a)
{
	ai->ai_flags = 0;
	ai->ai_family = a->saddr.s.sa_family;
	ai->ai_socktype = a->type;
	ai->ai_protocol = a->protocol;
	ai->ai_addrlen = a->addrlen;
	ai->ai_addr = cast_const(struct sockaddr *, &a->saddr.s);
	ai->ai_canonname = NULL;
	ai->ai_next = NULL;
}

char *netaddr_name(const tal_t *ctx, const struct netaddr *a)
{
	char name[INET6_ADDRSTRLEN];
	const void *sockaddr;
	uint16_t port;

	switch (a->saddr.s.sa_family) {
	case AF_INET:
		sockaddr = &a->saddr.ipv4.sin_addr;
		port = ntohs(a->saddr.ipv4.sin_port);
		break;
	case AF_INET6:
		sockaddr = &a->saddr.ipv6.sin6_addr;
		port = ntohs(a->saddr.ipv6.sin6_port);
		break;
	default:
		return tal_fmt(ctx, "Unknown protocol %u", a->saddr.s.sa_family);
	}

	if (!inet_ntop(a->saddr.s.sa_family, sockaddr, name, sizeof(name)))
		sprintf(name, "Unprintable-%u-address", a->saddr.s.sa_family);

	return tal_fmt(ctx, "%s:%u", name, port);
}
