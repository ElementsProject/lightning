#include <arpa/inet.h>
#include <assert.h>
#include <ccan/tal/str/str.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/wireaddr.h>
#include <wire/wire.h>

/* Returns false if we didn't parse it, and *cursor == NULL if malformed. */
bool fromwire_wireaddr(const u8 **cursor, size_t *max, struct wireaddr *addr)
{
	addr->type = fromwire_u8(cursor, max);

	switch (addr->type) {
	case ADDR_TYPE_IPV4:
		addr->addrlen = 4;
		break;
	case ADDR_TYPE_IPV6:
		addr->addrlen = 16;
		break;
	default:
		return false;
	}
	fromwire(cursor, max, addr->addr, addr->addrlen);
	addr->port = fromwire_u16(cursor, max);

	return *cursor != NULL;
}

void towire_wireaddr(u8 **pptr, const struct wireaddr *addr)
{
	if (!addr || addr->type == ADDR_TYPE_PADDING) {
		towire_u8(pptr, ADDR_TYPE_PADDING);
		return;
	}
	towire_u8(pptr, addr->type);
	towire(pptr, addr->addr, addr->addrlen);
	towire_u16(pptr, addr->port);
}

char *fmt_wireaddr(const tal_t *ctx, const struct wireaddr *a)
{
	char addrstr[INET6_ADDRSTRLEN];
	char *ret, *hex;

	switch (a->type) {
	case ADDR_TYPE_IPV4:
		if (!inet_ntop(AF_INET, a->addr, addrstr, INET_ADDRSTRLEN))
			return "Unprintable-ipv4-address";
		return tal_fmt(ctx, "%s:%u", addrstr, a->port);
	case ADDR_TYPE_IPV6:
		if (!inet_ntop(AF_INET6, a->addr, addrstr, INET6_ADDRSTRLEN))
			return "Unprintable-ipv6-address";
		return tal_fmt(ctx, "[%s]:%u", addrstr, a->port);
	case ADDR_TYPE_PADDING:
		break;
	}

	hex = tal_hexstr(ctx, a->addr, a->addrlen);
	ret = tal_fmt(ctx, "Unknown type %u %s:%u", a->type, hex, a->port);
	tal_free(hex);
	return ret;
}
REGISTER_TYPE_TO_STRING(wireaddr, fmt_wireaddr);


bool parse_wireaddr(const char *arg, struct wireaddr *addr, u16 defport)
{
	struct in6_addr v6;
	struct in_addr v4;
	u16 port;
	char *ip;
	bool res;
	tal_t *tmpctx = tal_tmpctx(NULL);

	res = false;
	port = defport;

	if (!parse_ip_port(tmpctx, arg, &ip, &port))
		port = defport;

	/* FIXME: change arg to addr[:port] and use getaddrinfo? */
	if (streq(arg, "localhost"))
		ip = "127.0.0.1";
	else if (streq(arg, "ip6-localhost"))
		ip = "::1";

	memset(&addr->addr, 0, sizeof(addr->addr));

	if (inet_pton(AF_INET, ip, &v4) == 1) {
		addr->type = ADDR_TYPE_IPV4;
		addr->addrlen = 4;
		addr->port = port;
		memcpy(&addr->addr, &v4, addr->addrlen);
		res = true;
	} else if (inet_pton(AF_INET6, ip, &v6) == 1) {
		addr->type = ADDR_TYPE_IPV6;
		addr->addrlen = 16;
		addr->port = port;
		memcpy(&addr->addr, &v6, addr->addrlen);
		res = true;
	}

	tal_free(tmpctx);
	return res;
}

// NOTE: arg is assumed to be an ipv4/6 addr string with optional port
bool parse_ip_port(tal_t *ctx, const char *arg, char **ip, u16 *port) {
	bool ipv6, has_brackets, has_colon;

	*port = 0;
	ipv6 = true;
	has_brackets = false;
	has_colon = false;

	*ip = tal_strdup(ctx, arg);

	ipv6 = strchr(*ip, '.') == NULL;
	has_brackets = strchr(*ip, '[');
	has_colon = strchr(*ip, ':');

	// we have an ip addr with no port
	if ((ipv6 && !has_brackets) || (!ipv6 && !has_colon))
		return false;

	/* IPv6 can have [ ], trim them here */
	if (ipv6 && strstarts(*ip, "[") && strends(*ip, "]")) {
		(*ip)++;
		(*ip)[strlen(*ip)-1] = '\0';
		return false;
	}

	// we have a port, let's go to it
	const char *last_colon = strrchr(*ip, ':');
	assert(last_colon);

	// chop off port
	(*ip)[last_colon - *ip - ipv6] = '\0';

	// skip over first [ if ipv6
	if (ipv6) (*ip)++;

	*port = atoi(last_colon + 1);
	return *port != 0;
}
