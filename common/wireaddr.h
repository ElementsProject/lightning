#ifndef LIGHTNING_COMMON_WIREADDR_H
#define LIGHTNING_COMMON_WIREADDR_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <lightningd/lightningd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>

struct in6_addr;
struct in_addr;
struct sockaddr_in6;
struct sockaddr_in;
struct sockaddr_un;

/* BOLT #1:
 *
 * The default TCP port is 9735. This corresponds to hexadecimal
 * `0x2607`: the Unicode code point for LIGHTNING.
 */
#define DEFAULT_PORT 9735


/* BOLT #7:
 *
 * The following `address descriptor` types are defined:
 *
 *   * `0`: padding; data = none (length 0)
 *   * `1`: ipv4; data = `[4:ipv4_addr][2:port]` (length 6)
 *   * `2`: ipv6; data = `[16:ipv6_addr][2:port]` (length 18)
 *   * `3`: Tor v2 onion service; data = `[10:onion_addr][2:port]` (length 12)
 *       * version 2 onion service addresses; Encodes an 80-bit, truncated `SHA-1` hash
 *         of a 1024-bit `RSA` public key for the onion service (a.k.a. Tor
 *	   hidden service).
 *   * `4`: Tor v3 onion service; data = `[35:onion_addr][2:port]` (length 37)
 *       * version 3 ([prop224](https://gitweb.torproject.org/torspec.git/tree/proposals/224-rend-spec-ng.txt))
 *         onion service addresses; Encodes:
 *            `[32:32_byte_ed25519_pubkey] || [2:checksum] || [1:version]`,
 *             where `checksum = sha3(".onion checksum" | pubkey || version)[:2]`
 */

#define	TOR_V2_ADDRLEN 10
#define	TOR_V3_ADDRLEN 35
#define	LARGEST_ADDRLEN TOR_V3_ADDRLEN

enum wire_addr_type {
	ADDR_TYPE_PADDING = 0,
	ADDR_TYPE_IPV4 = 1,
	ADDR_TYPE_IPV6 = 2,
	ADDR_TYPE_TOR_V2 = 3,
	ADDR_TYPE_TOR_V3 = 4
};

/* Structure now fit for tor support */
struct wireaddr {
	enum wire_addr_type type;
	u8 addrlen;
	u8 addr[LARGEST_ADDRLEN];
	u16 port;
};

/* We use wireaddr to tell gossipd both what to listen on, and what to
 * announce */
enum addr_listen_announce {
	ADDR_LISTEN = (1 << 0),
	ADDR_ANNOUNCE = (1 << 1),
	ADDR_LISTEN_AND_ANNOUNCE = ADDR_LISTEN|ADDR_ANNOUNCE
};

/* Inserts a single ADDR_TYPE_PADDING if addr is NULL */
void towire_wireaddr(u8 **pptr, const struct wireaddr *addr);
bool fromwire_wireaddr(const u8 **cursor, size_t *max, struct wireaddr *addr);

enum addr_listen_announce fromwire_addr_listen_announce(const u8 **cursor,
							size_t *max);
void towire_addr_listen_announce(u8 **pptr, enum addr_listen_announce ala);

/* If no_dns is non-NULL, we will set it to true and return false if
 * we wanted to do a DNS lookup. */
bool parse_wireaddr(const char *arg, struct wireaddr *addr, u16 port,
		    bool *no_dns, const char **err_msg);

char *fmt_wireaddr(const tal_t *ctx, const struct wireaddr *a);
char *fmt_wireaddr_without_port(const tal_t *ctx, const struct wireaddr *a);

/* If no_dns is non-NULL, we will set it to true and return false if
 * we wanted to do a DNS lookup. */
bool wireaddr_from_hostname(struct wireaddr *addr, const char *hostname,
			    const u16 port, bool *no_dns,
			    struct sockaddr *broken_reply,
			    const char **err_msg);

void wireaddr_from_ipv4(struct wireaddr *addr,
			const struct in_addr *ip4,
			const u16 port);
void wireaddr_from_ipv6(struct wireaddr *addr,
			const struct in6_addr *ip6,
			const u16 port);
bool wireaddr_to_ipv4(const struct wireaddr *addr, struct sockaddr_in *s4);
bool wireaddr_to_ipv6(const struct wireaddr *addr, struct sockaddr_in6 *s6);

bool wireaddr_is_wildcard(const struct wireaddr *addr);

enum wireaddr_internal_type {
	ADDR_INTERNAL_SOCKNAME,
	ADDR_INTERNAL_ALLPROTO,
	ADDR_INTERNAL_AUTOTOR,
	ADDR_INTERNAL_FORPROXY,
	ADDR_INTERNAL_WIREADDR,
};

/* For internal use, where we can also supply a local socket, wildcard. */
struct wireaddr_internal {
	enum wireaddr_internal_type itype;
	union {
		/* ADDR_INTERNAL_WIREADDR */
		struct wireaddr wireaddr;
		/* ADDR_INTERNAL_ALLPROTO */
		u16 port;
		/* ADDR_INTERNAL_AUTOTOR */
		struct wireaddr torservice;
		/* ADDR_INTERNAL_FORPROXY */
		struct unresolved {
			char name[256];
			u16 port;
		} unresolved;
		/* ADDR_INTERNAL_SOCKNAME */
		char sockname[sizeof(((struct sockaddr_un *)0)->sun_path)];
	} u;
};
bool parse_wireaddr_internal(const char *arg, struct wireaddr_internal *addr,
			     u16 port, bool wildcard_ok, bool dns_ok,
			     bool unresolved_ok, const char **err_msg);

void towire_wireaddr_internal(u8 **pptr,
				 const struct wireaddr_internal *addr);
bool fromwire_wireaddr_internal(const u8 **cursor, size_t *max,
				   struct wireaddr_internal *addr);
char *fmt_wireaddr_internal(const tal_t *ctx,
			       const struct wireaddr_internal *a);

bool wireaddr_from_unresolved(struct wireaddr_internal *addr,
			      const char *name, u16 port);

void wireaddr_from_sockname(struct wireaddr_internal *addr,
			    const char *sockname);
bool wireaddr_to_sockname(const struct wireaddr_internal *addr,
			  struct sockaddr_un *sun);

struct addrinfo *wireaddr_to_addrinfo(const tal_t *ctx,
				      const struct wireaddr *wireaddr);
struct addrinfo *wireaddr_internal_to_addrinfo(const tal_t *ctx,
					       const struct wireaddr_internal *wireaddr);

bool all_tor_addresses(const struct wireaddr_internal *wireaddr);

#endif /* LIGHTNING_COMMON_WIREADDR_H */
