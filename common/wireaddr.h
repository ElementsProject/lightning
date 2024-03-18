#ifndef LIGHTNING_COMMON_WIREADDR_H
#define LIGHTNING_COMMON_WIREADDR_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <sys/socket.h>
#include <sys/un.h>

struct in6_addr;
struct in_addr;
struct sockaddr_in6;
struct sockaddr_in;
struct sockaddr_un;

/* BOLT #7:
 *
 * The following `address descriptor` types are defined:
 *
 *   * `1`: ipv4; data = `[4:ipv4_addr][2:port]` (length 6)
 *   * `2`: ipv6; data = `[16:ipv6_addr][2:port]` (length 18)
 *   * `3`: Deprecated (length 12). Used to contain Tor v2 onion services.
 *   * `4`: Tor v3 onion service; data = `[35:onion_addr][2:port]` (length 37)
 *       * version 3 ([prop224](https://gitweb.torproject.org/torspec.git/tree/proposals/224-rend-spec-ng.txt))
 *         onion service addresses; Encodes:
 *            `[32:32_byte_ed25519_pubkey] || [2:checksum] || [1:version]`,
 *             where `checksum = sha3(".onion checksum" || pubkey || version)[:2]`.
 *   * `5`: DNS hostname; data = `[1:hostname_len][hostname_len:hostname][2:port]` (length up to 258)
 */

#define	TOR_V2_ADDRLEN 10
#define	TOR_V3_ADDRLEN 35
#define	DNS_ADDRLEN 255
#define	LARGEST_ADDRLEN DNS_ADDRLEN
#define	TOR_V3_BLOBLEN 64
#define	STATIC_TOR_MAGIC_STRING "gen-default-toraddress"

enum wire_addr_type {
	ADDR_TYPE_IPV4 = 1,
	ADDR_TYPE_IPV6 = 2,
	ADDR_TYPE_TOR_V2_REMOVED = 3,
	ADDR_TYPE_TOR_V3 = 4,
	ADDR_TYPE_DNS = 5,
};

struct wireaddr {
	enum wire_addr_type type;
	u8 addrlen;
	u8 addr[LARGEST_ADDRLEN];
	u16 port;
};

bool wireaddr_eq(const struct wireaddr *a, const struct wireaddr *b);
bool wireaddr_eq_without_port(const struct wireaddr *a, const struct wireaddr *b);

/* We use wireaddr to tell gossipd both what to listen on, and what to
 * announce */
enum addr_listen_announce {
	ADDR_LISTEN = (1 << 0),
	ADDR_ANNOUNCE = (1 << 1),
	ADDR_LISTEN_AND_ANNOUNCE = ADDR_LISTEN|ADDR_ANNOUNCE
};

void towire_wireaddr(u8 **pptr, const struct wireaddr *addr);
bool fromwire_wireaddr(const u8 **cursor, size_t *max, struct wireaddr *addr);

enum addr_listen_announce fromwire_addr_listen_announce(const u8 **cursor,
							size_t *max);
void towire_addr_listen_announce(u8 **pptr, enum addr_listen_announce ala);

/**
 * parse_wireaddr - parse a string into the various defaults we have.
 * @ctx: context to allocate returned error string
 * @arg: the string
 * @defport: the port to use if none specified in string
 * @no_dns: if non-NULL, don't do DNS lookups.
 * @addr: the addr to write, set if non-NULL return.
 *
 * If it returns NULL, check addr->itype to see if it's suitable for
 * you!  Otherwise, it returns a string allocated off @ctx.  If you
 * handed @no_dns, it will be set to true if the failure was due to
 * the fact we wanted to do an DNS lookup, and false for other
 * failures.
 */
const char *parse_wireaddr(const tal_t *ctx,
			   const char *arg,
			   u16 defport,
			   bool *no_dns,
			   struct wireaddr *addr);

char *fmt_wireaddr(const tal_t *ctx, const struct wireaddr *a);
char *fmt_wireaddr_without_port(const tal_t *ctx, const struct wireaddr *a);

/* If no_dns is non-NULL, we will set it to true and return NULL if
 * we wanted to do a DNS lookup. */
struct wireaddr *
wireaddr_from_hostname(const tal_t *ctx,
		       const char *hostname,
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
	ADDR_INTERNAL_STATICTOR,
};

/* For internal use, where we can also supply a local socket, wildcard. */
struct wireaddr_internal {
	enum wireaddr_internal_type itype;
	union {
		/* ADDR_INTERNAL_WIREADDR */
		struct waddr {
			struct wireaddr wireaddr;
			bool is_websocket;
		} wireaddr;
		/* ADDR_INTERNAL_ALLPROTO */
		struct allproto {
			u16 port;
			bool is_websocket;
		} allproto;
		/* ADDR_INTERNAL_AUTOTOR
		 * ADDR_INTERNAL_STATICTOR */
		struct torservice {
			/* Where to connect to Tor proxy */
			struct wireaddr address;
			/* Tor port to use */
			u16 port;
			/* Nul-terminated blob to use to create tor service */
			char blob[TOR_V3_BLOBLEN + 1];
		} torservice;
		/* ADDR_INTERNAL_FORPROXY */
		struct unresolved {
			char name[256];
			u16 port;
		} unresolved;
		/* ADDR_INTERNAL_SOCKNAME */
		char sockname[sizeof(((struct sockaddr_un *)0)->sun_path)];
	} u;
};

bool wireaddr_internal_eq(const struct wireaddr_internal *a,
			  const struct wireaddr_internal *b);

bool separate_address_and_port(const tal_t *ctx, const char *arg,
			       char **addr, u16 *port);

bool is_ipaddr(const char *arg);

bool is_toraddr(const char *arg);

bool is_wildcardaddr(const char *arg);

bool is_dnsaddr(const char *arg);

/**
 * parse_wireaddr_internal - parse a string into the various defaults we have.
 * @ctx: context to allocate returned error string
 * @arg: the string
 * @default_port: the port to use if none specified in string
 * @dns_lookup_ok: true if it's OK to do DNS name lookups.
 * @addr: the addr to write, set if non-NULL return.
 *
 * If it returns NULL, you want to check addr->itype to see if it's
 * suitable for you! */
const char *parse_wireaddr_internal(const tal_t *ctx,
				    const char *arg,
				    u16 default_port,
				    bool dns_lookup_ok,
				    struct wireaddr_internal *addr);

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

/* Decode an array of serialized addresses from node_announcement */
struct wireaddr *fromwire_wireaddr_array(const tal_t *ctx, const u8 *ser);

int wireaddr_cmp_type(const struct wireaddr *a,
		      const struct wireaddr *b, void *unused);

bool wireaddr_arr_contains(const struct wireaddr *was,
			   const struct wireaddr *wa);

#endif /* LIGHTNING_COMMON_WIREADDR_H */
