#include <arpa/inet.h>
#include <assert.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/io/io.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/base32.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/wireaddr.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <unistd.h>
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
	case ADDR_TYPE_TOR_V2:
		addr->addrlen = TOR_V2_ADDRLEN;
		break;
	case ADDR_TYPE_TOR_V3:
		addr->addrlen = TOR_V3_ADDRLEN;
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

enum addr_listen_announce fromwire_addr_listen_announce(const u8 **cursor,
							size_t *max)
{
	return fromwire_u8(cursor, max);
}

void towire_addr_listen_announce(u8 **pptr, enum addr_listen_announce ala)
{
	towire_u8(pptr, ala);
}

void towire_wireaddr_internal(u8 **pptr, const struct wireaddr_internal *addr)
{
	towire_u8(pptr, addr->itype);
	switch (addr->itype) {
	case ADDR_INTERNAL_SOCKNAME:
		towire_u8_array(pptr, (const u8 *)addr->u.sockname,
				sizeof(addr->u.sockname));
		return;
	case ADDR_INTERNAL_ALLPROTO:
		towire_u16(pptr, addr->u.port);
		return;
	case ADDR_INTERNAL_WIREADDR:
		towire_wireaddr(pptr, &addr->u.wireaddr);
		return;
	}
	abort();
}

bool fromwire_wireaddr_internal(const u8 **cursor, size_t *max,
				struct wireaddr_internal *addr)
{
	addr->itype = fromwire_u8(cursor, max);
	switch (addr->itype) {
	case ADDR_INTERNAL_SOCKNAME:
		fromwire_u8_array(cursor, max, (u8 *)addr->u.sockname,
				  sizeof(addr->u.sockname));
		/* Must be NUL terminated */
		if (!memchr(addr->u.sockname, 0, sizeof(addr->u.sockname)))
			fromwire_fail(cursor, max);
		return *cursor != NULL;
	case ADDR_INTERNAL_ALLPROTO:
		addr->u.port = fromwire_u16(cursor, max);
		return *cursor != NULL;
	case ADDR_INTERNAL_WIREADDR:
		return fromwire_wireaddr(cursor, max, &addr->u.wireaddr);
	}
	fromwire_fail(cursor, max);
	return false;
}

void wireaddr_from_ipv4(struct wireaddr *addr,
			const struct in_addr *ip4,
			const u16 port)
{
	addr->type = ADDR_TYPE_IPV4;
	addr->addrlen = sizeof(*ip4);
	addr->port = port;
	memset(addr->addr, 0, sizeof(addr->addr));
	memcpy(addr->addr, ip4, addr->addrlen);
}

void wireaddr_from_ipv6(struct wireaddr *addr,
			const struct in6_addr *ip6,
			const u16 port)
{
	addr->type = ADDR_TYPE_IPV6;
	addr->addrlen = sizeof(*ip6);
	addr->port = port;
	memset(addr->addr, 0, sizeof(addr->addr));
	memcpy(&addr->addr, ip6, addr->addrlen);
}

bool wireaddr_to_ipv4(const struct wireaddr *addr, struct sockaddr_in *s4)
{
	if (addr->type != ADDR_TYPE_IPV4)
		return false;
	s4->sin_family = AF_INET;
	s4->sin_port = htons(addr->port);
	assert(addr->addrlen == sizeof(s4->sin_addr));
	memcpy(&s4->sin_addr, addr->addr, sizeof(s4->sin_addr));
	return true;
}

bool wireaddr_to_ipv6(const struct wireaddr *addr, struct sockaddr_in6 *s6)
{
	if (addr->type != ADDR_TYPE_IPV6)
		return false;
	s6->sin6_family = AF_INET6;
	s6->sin6_port = htons(addr->port);
	assert(addr->addrlen == sizeof(s6->sin6_addr));
	memcpy(&s6->sin6_addr, addr->addr, sizeof(s6->sin6_addr));
	return true;
}

bool wireaddr_is_wildcard(const struct wireaddr *addr)
{
	switch (addr->type) {
	case ADDR_TYPE_IPV6:
	case ADDR_TYPE_IPV4:
		return memeqzero(addr->addr, addr->addrlen);
	case ADDR_TYPE_PADDING:
	case ADDR_TYPE_TOR_V2:
	case ADDR_TYPE_TOR_V3:
		return false;
	}
	abort();
}

char *fmt_wireaddr_internal(const tal_t *ctx,
			       const struct wireaddr_internal *a)
{
	switch (a->itype) {
	case ADDR_INTERNAL_SOCKNAME:
		return tal_fmt(ctx, "%s", a->u.sockname);
	case ADDR_INTERNAL_ALLPROTO:
		return tal_fmt(ctx, ":%u", a->u.port);
	case ADDR_INTERNAL_WIREADDR:
		return fmt_wireaddr(ctx, &a->u.wireaddr);
	}
	abort();
}
REGISTER_TYPE_TO_STRING(wireaddr_internal, fmt_wireaddr_internal);

char *fmt_wireaddr_without_port(const tal_t * ctx, const struct wireaddr *a)
{
	char addrstr[LARGEST_ADDRLEN];
	char *ret, *hex;

	switch (a->type) {
	case ADDR_TYPE_IPV4:
		if (!inet_ntop(AF_INET, a->addr, addrstr, INET_ADDRSTRLEN))
			return "Unprintable-ipv4-address";
		return tal_fmt(ctx, "%s", addrstr);
	case ADDR_TYPE_IPV6:
		if (!inet_ntop(AF_INET6, a->addr, addrstr, INET6_ADDRSTRLEN))
			return "Unprintable-ipv6-address";
		return tal_fmt(ctx, "[%s]", addrstr);
	case ADDR_TYPE_TOR_V2:
		return tal_fmt(ctx, "%.16s.onion",
			       b32_encode(addrstr, (u8 *) a->addr, 2));
	case ADDR_TYPE_TOR_V3:
		return tal_fmt(ctx, "%.56s.onion",
			       b32_encode(addrstr, (u8 *) a->addr, 3));
	case ADDR_TYPE_PADDING:
		break;
	}

	hex = tal_hexstr(ctx, a->addr, a->addrlen);
	ret = tal_fmt(ctx, "Unknown type %u %s", a->type, hex);
	tal_free(hex);
	return ret;
}

char *fmt_wireaddr(const tal_t *ctx, const struct wireaddr *a)
{
	char *ret = fmt_wireaddr_without_port(ctx, a);
	tal_append_fmt(&ret, ":%u", a->port);
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
static bool separate_address_and_port(const tal_t *ctx, const char *arg,
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

bool wireaddr_from_hostname(struct wireaddr *addr, const char *hostname,
			    const u16 port, const char **err_msg)
{
	struct sockaddr_in6 *sa6;
	struct sockaddr_in *sa4;
	struct addrinfo *addrinfo;
	struct addrinfo hints;
	int gai_err;
	u8 tor_dec_bytes[TOR_V3_ADDRLEN];
	bool res = false;

	/* Don't do lookup on onion addresses. */
	if (strends(hostname, ".onion")) {
		if (strlen(hostname) < 25) { //FIXME bool is_V2_or_V3_TOR(addr);
			addr->type = ADDR_TYPE_TOR_V2;
			addr->addrlen = TOR_V2_ADDRLEN;
			addr->port = port;
			b32_decode((u8 *) tor_dec_bytes, (u8 *)hostname, 2);
			memcpy(&addr->addr, tor_dec_bytes, addr->addrlen);
			return true;
		} else {
			addr->type = ADDR_TYPE_TOR_V3;
			addr->addrlen = TOR_V3_ADDRLEN;
			addr->port = port;
			b32_decode((u8 *) tor_dec_bytes, (u8 *)hostname, 3);
			memcpy(&addr->addr, tor_dec_bytes, addr->addrlen);
			return true;
		}
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_ADDRCONFIG;
	gai_err = getaddrinfo(hostname, tal_fmt(tmpctx, "%d", port),
			      &hints, &addrinfo);
	if (gai_err != 0) {
		if (err_msg)
			*err_msg = gai_strerror(gai_err);
		return false;
	}
	/* Use only the first found address */
	if (addrinfo->ai_family == AF_INET) {
		sa4 = (struct sockaddr_in *) addrinfo->ai_addr;
		wireaddr_from_ipv4(addr, &sa4->sin_addr, port);
		res = true;
	} else if (addrinfo->ai_family == AF_INET6) {
		sa6 = (struct sockaddr_in6 *) addrinfo->ai_addr;
		wireaddr_from_ipv6(addr, &sa6->sin6_addr, port);
		res = true;
	}

	/* Clean up */
	freeaddrinfo(addrinfo);
	return res;
}

bool parse_wireaddr(const char *arg, struct wireaddr *addr, u16 defport,
		    const char **err_msg)
{
	struct in6_addr v6;
	struct in_addr v4;
	u16 port;
	char *ip;
	bool res;

	res = false;
	port = defport;
	if (err_msg)
		*err_msg = NULL;

	if (!separate_address_and_port(tmpctx, arg, &ip, &port))
		goto finish;

	if (streq(ip, "localhost"))
		ip = "127.0.0.1";
	else if (streq(ip, "ip6-localhost"))
		ip = "::1";

	memset(&addr->addr, 0, sizeof(addr->addr));

	if (inet_pton(AF_INET, ip, &v4) == 1) {
		wireaddr_from_ipv4(addr, &v4, port);
		res = true;
	} else if (inet_pton(AF_INET6, ip, &v6) == 1) {
		wireaddr_from_ipv6(addr, &v6, port);
		res = true;
	}

	/* Resolve with getaddrinfo */
	if (!res)
		res = wireaddr_from_hostname(addr, ip, port, err_msg);

finish:
	if (!res && err_msg && !*err_msg)
		*err_msg = "Error parsing hostname";
	return res;
}

bool parse_wireaddr_internal(const char *arg, struct wireaddr_internal *addr,
			     u16 port, bool wildcard_ok, const char **err_msg)
{
	u16 wildport;
	char *ip;

	/* Addresses starting with '/' are local socket paths */
	if (arg[0] == '/') {
		addr->itype = ADDR_INTERNAL_SOCKNAME;

		/* Check if the path is too long */
		if (strlen(arg) >= sizeof(addr->u.sockname)) {
			if (err_msg)
				*err_msg = "Socket name too long";
			return false;
		}
		strcpy(addr->u.sockname, arg);
		return true;
	}

	/* An empty string means IPv4 and IPv6 (which under Linux by default
	 * means just IPv6, and IPv4 gets autobound). */
	if (wildcard_ok
	    && separate_address_and_port(tmpctx, arg, &ip, &wildport)
	    && streq(ip, "")) {
		addr->itype = ADDR_INTERNAL_ALLPROTO;
		addr->u.port = wildport;
		return true;
	}

	addr->itype = ADDR_INTERNAL_WIREADDR;
	return parse_wireaddr(arg, &addr->u.wireaddr, port, err_msg);
}

void wireaddr_from_sockname(struct wireaddr_internal *addr,
			    const char *sockname)
{
	addr->itype = ADDR_INTERNAL_SOCKNAME;
	memset(addr->u.sockname, 0, sizeof(addr->u.sockname));
	strncpy(addr->u.sockname, sockname, sizeof(addr->u.sockname)-1);
}

bool wireaddr_to_sockname(const struct wireaddr_internal *addr,
			  struct sockaddr_un *sun)
{
	if (addr->itype != ADDR_INTERNAL_SOCKNAME)
		return false;
	sun->sun_family = AF_LOCAL;
	BUILD_ASSERT(sizeof(sun->sun_path) == sizeof(addr->u.sockname));
	memcpy(sun->sun_path, addr->u.sockname, sizeof(addr->u.sockname));
	return true;
}
