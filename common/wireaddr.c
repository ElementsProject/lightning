#include "config.h"
#include <arpa/inet.h>
#include <assert.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/base32.h>
#include <common/type_to_string.h>
#include <common/wireaddr.h>
#include <netdb.h>
#include <netinet/in.h>
#include <wire/wire.h>

bool wireaddr_eq(const struct wireaddr *a, const struct wireaddr *b)
{
	if (a->type != b->type)
		return false;
	if (a->port != b->port)
		return false;
	return memeq(a->addr, a->addrlen, b->addr, b->addrlen);
}

bool wireaddr_eq_without_port(const struct wireaddr *a, const struct wireaddr *b)
{
	if (a->type != b->type)
		return false;
	return memeq(a->addr, a->addrlen, b->addr, b->addrlen);
}

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
	case ADDR_TYPE_TOR_V2_REMOVED:
		addr->addrlen = TOR_V2_ADDRLEN;
		break;
	case ADDR_TYPE_TOR_V3:
		addr->addrlen = TOR_V3_ADDRLEN;
		break;
	case ADDR_TYPE_DNS:
		addr->addrlen = fromwire_u8(cursor, max);
		memset(&addr->addr, 0, sizeof(addr->addr));
		addr->addr[addr->addrlen] = 0;
		break;
	case ADDR_TYPE_WEBSOCKET:
		addr->addrlen = 0;
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
	towire_u8(pptr, addr->type);
	if (addr->type == ADDR_TYPE_DNS)
		towire_u8(pptr, addr->addrlen);
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
	case ADDR_INTERNAL_AUTOTOR:
		towire_wireaddr(pptr, &addr->u.torservice.address);
		towire_u16(pptr, addr->u.torservice.port);
		return;
	case ADDR_INTERNAL_STATICTOR:
		towire_wireaddr(pptr, &addr->u.torservice.address);
		towire_u8_array(pptr, (const u8 *)addr->u.torservice.blob,
				sizeof(addr->u.torservice.blob));
		towire_u16(pptr, addr->u.torservice.port);
		return;
	case ADDR_INTERNAL_ALLPROTO:
		towire_u16(pptr, addr->u.port);
		return;
	case ADDR_INTERNAL_WIREADDR:
		towire_wireaddr(pptr, &addr->u.wireaddr);
		return;
	case ADDR_INTERNAL_FORPROXY:
		towire_u8_array(pptr, (const u8 *)addr->u.unresolved.name,
				sizeof(addr->u.unresolved.name));
		towire_u16(pptr, addr->u.unresolved.port);
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
	case ADDR_INTERNAL_AUTOTOR:
		fromwire_wireaddr(cursor, max, &addr->u.torservice.address);
		addr->u.torservice.port = fromwire_u16(cursor, max);
		return *cursor != NULL;
	case ADDR_INTERNAL_STATICTOR:
		fromwire_wireaddr(cursor, max, &addr->u.torservice.address);
		fromwire_u8_array(cursor, max, (u8 *)addr->u.torservice.blob,
				 sizeof(addr->u.torservice.blob));
		addr->u.torservice.port = fromwire_u16(cursor, max);
		return *cursor != NULL;
	case ADDR_INTERNAL_WIREADDR:
		return fromwire_wireaddr(cursor, max, &addr->u.wireaddr);
	case ADDR_INTERNAL_FORPROXY:
		fromwire_u8_array(cursor, max, (u8 *)addr->u.unresolved.name,
				  sizeof(addr->u.unresolved.name));
		/* Must be NUL terminated */
		if (!memchr(addr->u.unresolved.name, 0,
			    sizeof(addr->u.unresolved.name)))
			fromwire_fail(cursor, max);
		addr->u.unresolved.port = fromwire_u16(cursor, max);
		return *cursor != NULL;
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

void wireaddr_from_websocket(struct wireaddr *addr, const u16 port)
{
	addr->type = ADDR_TYPE_WEBSOCKET;
	addr->addrlen = 0;
	addr->port = port;
	memset(addr->addr, 0, sizeof(addr->addr));
}

bool wireaddr_to_ipv4(const struct wireaddr *addr, struct sockaddr_in *s4)
{
	if (addr->type != ADDR_TYPE_IPV4)
		return false;
	memset(s4, 0, sizeof(*s4));
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
	memset(s6, 0, sizeof(*s6));
	s6->sin6_family = AF_INET6;
	s6->sin6_port = htons(addr->port);
	assert(addr->addrlen == sizeof(s6->sin6_addr));
	memcpy(&s6->sin6_addr, addr->addr, sizeof(s6->sin6_addr));
	return true;
}

bool wireaddr_to_websocket(const struct wireaddr *addr, u16 *port)
{
	if (addr->type != ADDR_TYPE_WEBSOCKET)
		return false;
	*port = addr->port;
	return true;
}

bool wireaddr_is_wildcard(const struct wireaddr *addr)
{
	switch (addr->type) {
	case ADDR_TYPE_IPV6:
	case ADDR_TYPE_IPV4:
		return memeqzero(addr->addr, addr->addrlen);
	case ADDR_TYPE_TOR_V2_REMOVED:
	case ADDR_TYPE_TOR_V3:
	case ADDR_TYPE_DNS:
	case ADDR_TYPE_WEBSOCKET:
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
	case ADDR_INTERNAL_FORPROXY:
		return tal_fmt(ctx, "%s:%u",
			       a->u.unresolved.name, a->u.unresolved.port);
	case ADDR_INTERNAL_AUTOTOR:
		return tal_fmt(ctx, "autotor:%s",
			       fmt_wireaddr(tmpctx, &a->u.torservice.address));
	case ADDR_INTERNAL_STATICTOR:
		return tal_fmt(ctx, "statictor:%s",
			       fmt_wireaddr(tmpctx, &a->u.torservice.address));
}
	abort();
}
REGISTER_TYPE_TO_STRING(wireaddr_internal, fmt_wireaddr_internal);

char *fmt_wireaddr_without_port(const tal_t * ctx, const struct wireaddr *a)
{
	char *ret, *hex;
	char addrstr[INET6_ADDRSTRLEN];

	switch (a->type) {
	case ADDR_TYPE_IPV4:
		if (!inet_ntop(AF_INET, a->addr, addrstr, INET_ADDRSTRLEN))
			return "Unprintable-ipv4-address";
		return tal_fmt(ctx, "%s", addrstr);
	case ADDR_TYPE_IPV6:
		if (!inet_ntop(AF_INET6, a->addr, addrstr, INET6_ADDRSTRLEN))
			return "Unprintable-ipv6-address";
		return tal_fmt(ctx, "[%s]", addrstr);
	case ADDR_TYPE_TOR_V2_REMOVED:
	case ADDR_TYPE_TOR_V3:
		return tal_fmt(ctx, "%s.onion",
			       b32_encode(tmpctx, a->addr, a->addrlen));
	case ADDR_TYPE_DNS:
		return tal_fmt(ctx, "%s", a->addr);
	case ADDR_TYPE_WEBSOCKET:
		return tal_strdup(ctx, "websocket");
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
bool separate_address_and_port(const tal_t *ctx, const char *arg,
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
			   the end */
			if (portcolon != strrchr(arg, ':')
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

bool is_ipaddr(const char *arg)
{
	struct in_addr v4;
	struct in6_addr v6;
	if (inet_pton(AF_INET, arg, &v4))
		return true;
	if (inet_pton(AF_INET6, arg, &v6))
		return true;
	return false;
}

bool is_toraddr(const char *arg)
{
	size_t i, arglen;
	arglen = strlen(arg);
	if (!strends(arg, ".onion"))
		return false;
	if (arglen != 16 + 6 && arglen != 56 + 6)
		return false;
	for (i = 0; i < arglen - 6; i++) {
		if (arg[i] >= 'a' && arg[i] <= 'z')
			continue;
		if (arg[i] >= '0' && arg[i] <= '9')
			continue;
		return false;
	}
	return true;
}

bool is_wildcardaddr(const char *arg)
{
	return streq(arg, "");
}

/* Rules:
 *
 * - not longer than 255
 * - segments are separated with . dot
 * - segments do not start or end with - hyphen
 * - segments must be longer thant zero
 * - lowercase a-z and digits 0-9 and - hyphen
 */
bool is_dnsaddr(const char *arg)
{
	size_t i, arglen;
	int lastdot;

	if (is_ipaddr(arg) || is_toraddr(arg) || is_wildcardaddr(arg))
		return false;

	/* now that its not IP or TOR, check its a DNS name */
	arglen = strlen(arg);
	if (arglen > 255)
		return false;
	lastdot = -1;
	for (i = 0; i < arglen; i++) {
		if (arg[i] == '.') {
			/* segment must be longer than zero */
			if (i - lastdot == 1)
				return false;
			/* last segment can not end with hypen */
			if (i != 0 && arg[i-1] == '-')
				return false;
			lastdot = i;
			continue;
		}
		/* segment cannot start with hyphen */
		if (i == lastdot + 1 && arg[i] == '-')
			return false;
		if (arg[i] >= 'a' && arg[i] <= 'z')
			continue;
		if (arg[i] >= '0' && arg[i] <= '9')
			continue;
		if (arg[i] == '-')
			continue;
		return false;
	}
	return true;
}

struct wireaddr *
wireaddr_from_hostname(const tal_t *ctx,
		       const char *hostname,
                       const u16 port, bool *no_dns,
                       struct sockaddr *broken_reply,
                       const char **err_msg)
{
	struct wireaddr *addrs;
	struct sockaddr_in6 *sa6;
	struct sockaddr_in *sa4;
	struct addrinfo *addrinfo, *addrinfos;
	struct addrinfo hints;
	int gai_err;

	addrs = tal_arr(ctx, struct wireaddr, 0);
	if (no_dns)
		*no_dns = false;

	/* Don't do lookup on onion addresses. */
	if (strends(hostname, ".onion")) {
		u8 *dec = b32_decode(tmpctx, hostname,
				     strlen(hostname) - strlen(".onion"));
		tal_resize(&addrs, 1);
		if (tal_count(dec) == TOR_V3_ADDRLEN) {
			addrs[0].type = ADDR_TYPE_TOR_V3;
		} else {
			if (err_msg)
				*err_msg = "Invalid Tor address";
			return tal_free(addrs);
		}

		addrs[0].addrlen = tal_count(dec);
		addrs[0].port = port;
		memcpy(addrs[0].addr, dec, tal_count(dec));
		return addrs;
	}

	/* Tell them we wanted DNS and fail. */
	if (no_dns) {
		if (err_msg)
			*err_msg = "Needed DNS, but lookups suppressed";
		*no_dns = true;
		return tal_free(addrs);
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_ADDRCONFIG;
	gai_err = getaddrinfo(hostname, tal_fmt(tmpctx, "%d", port),
			      &hints, &addrinfos);
	if (gai_err != 0) {
		if (err_msg)
			*err_msg = gai_strerror(gai_err);
		return tal_free(addrs);
	}

	if (broken_reply != NULL && memeq(addrinfos->ai_addr, addrinfos->ai_addrlen, broken_reply, tal_count(broken_reply)))
		goto cleanup;

	for (addrinfo = addrinfos; addrinfo; addrinfo = addrinfo->ai_next) {
		struct wireaddr addr;
		if (addrinfo->ai_family == AF_INET) {
			sa4 = (struct sockaddr_in *) addrinfo->ai_addr;
			wireaddr_from_ipv4(&addr, &sa4->sin_addr, port);
		} else if (addrinfo->ai_family == AF_INET6) {
			sa6 = (struct sockaddr_in6 *) addrinfo->ai_addr;
			wireaddr_from_ipv6(&addr, &sa6->sin6_addr, port);
		} else
			/* Ignore any other address types. */
			continue;
		tal_arr_expand(&addrs, addr);
	}

cleanup:
	/* Clean up */
	freeaddrinfo(addrinfos);
	if (tal_count(addrs))
		return addrs;
	return tal_free(addrs);
}

bool parse_wireaddr(const char *arg, struct wireaddr *addr, u16 defport,
		    bool *no_dns, const char **err_msg)
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
	if (!res) {
		struct wireaddr *addresses = wireaddr_from_hostname(NULL, ip, port,
		                                                    no_dns, NULL, err_msg);
		if (addresses) {
			*addr = addresses[0];
			tal_free(addresses);
			res = true;
		}
	}

finish:
	if (!res && err_msg && !*err_msg)
		*err_msg = "Error parsing hostname";
	return res;
}

bool wireaddr_internal_eq(const struct wireaddr_internal *a,
			  const struct wireaddr_internal *b)
{
	if (a->itype != b->itype)
		return false;

	switch (a->itype) {
	case ADDR_INTERNAL_SOCKNAME:
		return streq(a->u.sockname, b->u.sockname);
	case ADDR_INTERNAL_ALLPROTO:
		return a->u.port == b->u.port;
	case ADDR_INTERNAL_STATICTOR:
		if (!memeq(a->u.torservice.blob, sizeof(a->u.torservice.blob),
			   b->u.torservice.blob, sizeof(b->u.torservice.blob)))
			return false;
		/* fall thru */
	case ADDR_INTERNAL_AUTOTOR:
		if (!wireaddr_eq(&a->u.torservice.address,
				 &b->u.torservice.address))
			return false;
		return a->u.torservice.port == b->u.torservice.port;
	case ADDR_INTERNAL_FORPROXY:
		if (!streq(a->u.unresolved.name, b->u.unresolved.name))
			return false;
		return a->u.unresolved.port == b->u.unresolved.port;
	case ADDR_INTERNAL_WIREADDR:
		return wireaddr_eq(&a->u.wireaddr, &b->u.wireaddr);
	}
	abort();
}

bool parse_wireaddr_internal(const char *arg, struct wireaddr_internal *addr,
			     u16 port, bool wildcard_ok, bool dns_ok,
			     bool unresolved_ok, bool allow_deprecated,
			     const char **err_msg)
{
	u16 splitport;
	char *ip = NULL;
	char *service_addr;
	bool needed_dns = false;

	/* Addresses starting with '/' are local socket paths */
	if (arg[0] == '/') {
		addr->itype = ADDR_INTERNAL_SOCKNAME;

		/* Check if the path is too long */
		if (strlen(arg) >= sizeof(addr->u.sockname)) {
			if (err_msg)
				*err_msg = "Socket name too long";
			return false;
		}
		/* Zero it out for passing across the wire */
		memset(addr->u.sockname, 0, sizeof(addr->u.sockname));
		strcpy(addr->u.sockname, arg);
		return true;
	}

	/* 'autotor:' is a special prefix meaning talk to Tor to create
	 * an onion address. */
	if (strstarts(arg, "autotor:")) {
		addr->itype = ADDR_INTERNAL_AUTOTOR;
		addr->u.torservice.port = DEFAULT_PORT;
		/* Format is separated by slash. */
		char **parts = tal_strsplit(tmpctx, arg, "/", STR_EMPTY_OK);

		for (size_t i = 1; i < tal_count(parts)-1; i++) {
			if (strstarts(parts[i], "torport=")) {
				char *endp = NULL;
				addr->u.torservice.port = strtol(parts[i]+strlen("torport="), &endp, 10);
				if (addr->u.torservice.port <= 0 || *endp != '\0') {
					if (err_msg)
						*err_msg = "Bad :torport: number";
					return false;
				}
			} else {
				if (err_msg)
					*err_msg = tal_fmt(tmpctx, "unknown tor arg %s", parts[i]);
				return false;
			}
		}

		service_addr = tal_fmt(tmpctx, "%s", parts[0] + strlen("autotor:"));

		return parse_wireaddr(service_addr,
				      &addr->u.torservice.address, 9051,
				      dns_ok ? NULL : &needed_dns, err_msg);
	}

	/* 'statictor:' is a special prefix meaning talk to Tor to create
	 * an static onion address from a blob or node id */
	if (strstarts(arg, "statictor:")) {
		bool use_magic_blob = true;
		addr->itype = ADDR_INTERNAL_STATICTOR;
		addr->u.torservice.port = DEFAULT_PORT;
		memset(addr->u.torservice.blob, 0, sizeof(addr->u.torservice.blob));

		/* Format is separated by slash. */
		char **parts = tal_strsplit(tmpctx, arg, "/", STR_EMPTY_OK);
		for (size_t i = 1; i < tal_count(parts)-1; i++) {
			if (strstarts(parts[i], "torport=")) {
				char *endp = NULL;
				addr->u.torservice.port = strtol(parts[i]+strlen("torport="), &endp, 10);
				if (addr->u.torservice.port <= 0 || *endp != '\0') {
					if (err_msg)
						*err_msg = "Bad :torport: number";
					return false;
				}
			} else if (strstarts(parts[i], "torblob=")) {
				const char *blobdata = parts[i] + strlen("torblob=");
				if (strlen(blobdata) > TOR_V3_BLOBLEN) {
					if (err_msg)
						*err_msg = "torblob too long";
					return false;
				}
				strcpy(addr->u.torservice.blob, blobdata);
				use_magic_blob = false;
			} else {
				if (err_msg)
					*err_msg = tal_fmt(tmpctx, "unknown tor arg %s", parts[i]);
				return false;
			}
		}

		if (use_magic_blob) {
			/* when statictor called just with the service address and or port generate the unique onion */
			strcpy(addr->u.torservice.blob, STATIC_TOR_MAGIC_STRING);
		}

		service_addr = tal_fmt(tmpctx, "%s", parts[0] + strlen("statictor:"));

		return parse_wireaddr(service_addr,
				      &addr->u.torservice.address, 9051,
				      dns_ok ? NULL : &needed_dns, err_msg);
	}

	splitport = port;
	if (!separate_address_and_port(tmpctx, arg, &ip, &splitport)) {
		if (err_msg) {
			*err_msg = tal_fmt(tmpctx, "Error parsing hostname %s  %s", (char *)arg, ip);
		}
		return false;
	}

	/* An empty string means IPv4 and IPv6 (which under Linux by default
	 * means just IPv6, and IPv4 gets autobound). */
	if (wildcard_ok && is_wildcardaddr(ip)) {
		addr->itype = ADDR_INTERNAL_ALLPROTO;
		addr->u.port = splitport;
		return true;
	}

	addr->itype = ADDR_INTERNAL_WIREADDR;
	if (parse_wireaddr(arg, &addr->u.wireaddr, port,
			   dns_ok ? NULL : &needed_dns, err_msg)) {
		if (addr->u.wireaddr.type == ADDR_TYPE_TOR_V2_REMOVED) {
			if (err_msg)
				*err_msg = "v2 Tor onion services not supported";
			return false;
		}

		return true;
	}

	if (!needed_dns || !unresolved_ok)
		return false;

	/* We can't do DNS, so keep unresolved. */
	if (!wireaddr_from_unresolved(addr, ip, splitport)) {
		if (err_msg)
			*err_msg = "Name too long";
		return false;
	}
	return true;
}

bool wireaddr_from_unresolved(struct wireaddr_internal *addr,
			      const char *name, u16 port)
{
	addr->itype = ADDR_INTERNAL_FORPROXY;
	if (strlen(name) >= sizeof(addr->u.unresolved.name))
		return false;

	memset(addr->u.unresolved.name, 0, sizeof(addr->u.unresolved.name));
	strcpy(addr->u.unresolved.name, name);
	addr->u.unresolved.port = port;
	return true;
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

struct addrinfo *wireaddr_internal_to_addrinfo(const tal_t *ctx,
					       const struct wireaddr_internal *wireaddr)
{
	struct addrinfo *ai = talz(ctx, struct addrinfo);
	struct sockaddr_un *sun;

	ai->ai_socktype = SOCK_STREAM;

	switch (wireaddr->itype) {
	case ADDR_INTERNAL_SOCKNAME:
		sun = tal(ai, struct sockaddr_un);
		wireaddr_to_sockname(wireaddr, sun);
		ai->ai_family = sun->sun_family;
		ai->ai_addrlen = sizeof(*sun);
		ai->ai_addr = (struct sockaddr *)sun;
		return ai;
	case ADDR_INTERNAL_ALLPROTO:
	case ADDR_INTERNAL_AUTOTOR:
	case ADDR_INTERNAL_STATICTOR:
	case ADDR_INTERNAL_FORPROXY:
		break;
	case ADDR_INTERNAL_WIREADDR:
		return wireaddr_to_addrinfo(ctx, &wireaddr->u.wireaddr);
	}
	abort();
}

struct addrinfo *wireaddr_to_addrinfo(const tal_t *ctx,
				      const struct wireaddr *wireaddr)
{
	struct addrinfo *ai = talz(ctx, struct addrinfo);
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	ai->ai_socktype = SOCK_STREAM;

	switch (wireaddr->type) {
	case ADDR_TYPE_IPV4:
		sin = tal(ai, struct sockaddr_in);
		wireaddr_to_ipv4(wireaddr, sin);
		ai->ai_family = sin->sin_family;
		ai->ai_addrlen = sizeof(*sin);
		ai->ai_addr = (struct sockaddr *)sin;
		return ai;
	case ADDR_TYPE_IPV6:
		sin6 = tal(ai, struct sockaddr_in6);
		wireaddr_to_ipv6(wireaddr, sin6);
		ai->ai_family = sin6->sin6_family;
		ai->ai_addrlen = sizeof(*sin6);
		ai->ai_addr = (struct sockaddr *)sin6;
		return ai;
	case ADDR_TYPE_TOR_V2_REMOVED:
	case ADDR_TYPE_TOR_V3:
	case ADDR_TYPE_DNS:
	case ADDR_TYPE_WEBSOCKET:
		break;
	}
	abort();
}

struct wireaddr *fromwire_wireaddr_array(const tal_t *ctx, const u8 *ser)
{
	const u8 *cursor = ser;
	size_t len = tal_count(ser);
	struct wireaddr *wireaddrs = tal_arr(ctx, struct wireaddr, 0);

	while (cursor && len) {
		struct wireaddr wireaddr;

		/* BOLT #7:
		 *
		 * The receiving node:
		 *...
		 *   - SHOULD ignore the first `address descriptor` that does
		 *     NOT match the types defined above.
		 */
		if (!fromwire_wireaddr(&cursor, &len, &wireaddr)) {
			if (!cursor)
				/* Parsing address failed */
				return tal_free(wireaddrs);
			/* Unknown type, stop there. */
			break;
		}

		tal_arr_expand(&wireaddrs, wireaddr);
	}
	return wireaddrs;
}

bool all_tor_addresses(const struct wireaddr_internal *wireaddr)
{
	for (int i = 0; i < tal_count(wireaddr); i++) {
		switch (wireaddr[i].itype) {
		case ADDR_INTERNAL_SOCKNAME:
			return false;
		case ADDR_INTERNAL_FORPROXY:
			abort();
		case ADDR_INTERNAL_ALLPROTO:
			return false;
		case ADDR_INTERNAL_AUTOTOR:
		case ADDR_INTERNAL_STATICTOR:
			continue;
		case ADDR_INTERNAL_WIREADDR:
			switch (wireaddr[i].u.wireaddr.type) {
			case ADDR_TYPE_IPV4:
			case ADDR_TYPE_IPV6:
			case ADDR_TYPE_DNS:
				return false;
			case ADDR_TYPE_TOR_V2_REMOVED:
			case ADDR_TYPE_TOR_V3:
			case ADDR_TYPE_WEBSOCKET:
				continue;
			}
		}
		abort();
	}
	return true;
}

/*~ ccan/asort provides a type-safe sorting function; it requires a comparison
 * function, which takes an optional extra argument which is usually unused as
 * here, but deeply painful if you need it and don't have it! */
int wireaddr_cmp_type(const struct wireaddr *a,
			     const struct wireaddr *b, void *unused)
{
	/* This works, but of course it's inefficient.  We don't
	 * really care, since it's called only once at startup. */
	u8 *a_wire = tal_arr(tmpctx, u8, 0), *b_wire = tal_arr(tmpctx, u8, 0);
	int cmp, minlen;

	towire_wireaddr(&a_wire, a);
	towire_wireaddr(&b_wire, b);

	minlen = tal_bytelen(a_wire) < tal_bytelen(b_wire)
		? tal_bytelen(a_wire) : tal_bytelen(b_wire);
	cmp = memcmp(a_wire, b_wire, minlen);
	/* On a tie, shorter one goes first. */
	if (cmp == 0)
		return tal_bytelen(a_wire) - tal_bytelen(b_wire);
	return cmp;
}
