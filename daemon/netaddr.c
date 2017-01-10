#include "bitcoin/pullpush.h"
#include "netaddr.h"
#include "type_to_string.h"
#include "utils.h"
#include <arpa/inet.h>
#include <assert.h>
#include <ccan/cast/cast.h>
#include <ccan/endian/endian.h>
#include <ccan/short_types/short_types.h>
#include <ccan/str/hex/hex.h>
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

char *netaddr_to_hex(const tal_t *ctx, const struct netaddr *a)
{
	u8 *blob = tal_arr(ctx, u8, 0);
	char *hex;

	push_le32(a->type, push, &blob);
	push_le32(a->protocol, push, &blob);
	push_le32(a->addrlen, push, &blob);
	assert(a->addrlen <= sizeof(a->saddr));
	push(&a->saddr, a->addrlen, &blob);

	hex = tal_hex(ctx, blob);
	tal_free(blob);
	return hex;
}

bool netaddr_from_blob(const void *linear, size_t len, struct netaddr *a)
{
	const u8 *p = linear;

	a->type = pull_le32(&p, &len);
	a->protocol = pull_le32(&p, &len);
	a->addrlen = pull_le32(&p, &len);
	if (a->addrlen > sizeof(a->saddr))
		return false;
	pull(&p, &len, &a->saddr, a->addrlen);
	return p != NULL && len == 0;
}

bool netaddr_from_fd(int fd, int type, int protocol, struct netaddr *a)
{
	a->type = type;
	a->protocol = protocol;
	a->addrlen = sizeof(a->saddr);
	return getpeername(fd, &a->saddr.s, &a->addrlen) == 0;
}

REGISTER_TYPE_TO_STRING(netaddr, netaddr_name);
