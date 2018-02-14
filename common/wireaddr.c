#include <arpa/inet.h>
#include <assert.h>
#include <ccan/tal/str/str.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/wireaddr.h>
#include <netinet/in.h>
#include <sys/socket.h>
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

/* Valid forms:
 *
 * [anything]:<number>
 * anything-without-colons-or-left-brace:<number>
 * anything-without-colons
 * string-with-multiple-colons
 *
 * Returns false if it wasn't one of these forms.  If it returns true,
 * it only overwrites *port if it was specified by <number> above.
 */
static bool separate_address_and_port(tal_t *ctx, const char *arg,
				      char **addr, u16 *port)
{
	char *portcolon;

	if (strstarts(arg, "[")) {
		char *end = strchr(arg, ']');
		if (!end)
			return false;
		/* Copy inside [] */
		*addr = tal_strndup(ctx, arg + 1, end - arg - 1);
		portcolon = strchr(end+1, ':');
	} else {
		portcolon = strchr(arg, ':');
		if (portcolon) {
			/* Disregard if there's more than one : or if it's at
			   the start or end */
			if (portcolon != strrchr(arg, ':')
			    || portcolon == arg
			    || portcolon[1] == '\0')
				portcolon = NULL;
		}
		if (portcolon)
			*addr = tal_strndup(ctx, arg, portcolon - arg);
		else
			*addr = tal_strdup(ctx, arg);
	}

	if (portcolon) {
		char *endp;
		*port = strtol(portcolon + 1, &endp, 10);
		return *port != 0 && *endp == '\0';
	}
	return true;
}

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

	if (!separate_address_and_port(tmpctx, arg, &ip, &port)) {
		tal_free(tmpctx);
		return false;
	}

	/* FIXME: change arg to addr[:port] and use getaddrinfo? */
	if (streq(ip, "localhost"))
		ip = "127.0.0.1";
	else if (streq(ip, "ip6-localhost"))
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
