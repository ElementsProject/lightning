#ifndef LIGHTNING_DAEMON_ROUTING_H
#define LIGHTNING_DAEMON_ROUTING_H
#include "config.h"
#include "bitcoin/pubkey.h"

#define ROUTING_MAX_HOPS 20

struct node_connection {
	struct node *src, *dst;
	/* millisatoshi. */
	u32 base_fee;
	/* millionths */
	s32 proportional_fee;

	/* Delay for HTLC in blocks.*/
	u32 delay;
	/* Minimum allowable HTLC expiry in blocks. */
	u32 min_blocks;
};

struct node {
	struct pubkey id;

	/* IP/Hostname and port of this node */
	char *hostname;
	int port;

	/* Routes connecting to us, from us. */
	struct node_connection **in, **out;

	/* Temporary data for routefinding. */
	struct {
		/* Total to get to here from target. */
		s64 total;
		/* Total risk premium of this route. */
		u64 risk;
		/* Where that came from. */
		struct node_connection *prev;
	} bfg[ROUTING_MAX_HOPS+1];

	/* UTF-8 encoded alias as tal_arr, not zero terminated */
	u8 *alias;
};

struct lightningd_state;

struct node *new_node(struct lightningd_state *dstate,
		      const struct pubkey *id);

struct node *get_node(struct lightningd_state *dstate,
		      const struct pubkey *id);

/* msatoshi must be possible (< 21 million BTC), ie < 2^60.
 * If it returns more than msatoshi, it overflowed. */
s64 connection_fee(const struct node_connection *c, u64 msatoshi);

/* Updates existing node, or creates a new one as required. */
struct node *add_node(struct lightningd_state *dstate,
		      const struct pubkey *pk,
		      char *hostname,
		      int port);

/* Updates existing connection, or creates new one as required. */
struct node_connection *add_connection(struct lightningd_state *dstate,
				       const struct pubkey *from,
				       const struct pubkey *to,
				       u32 base_fee, s32 proportional_fee,
				       u32 delay, u32 min_blocks);

void remove_connection(struct lightningd_state *dstate,
		       const struct pubkey *src, const struct pubkey *dst);

struct peer *find_route(struct lightningd_state *dstate,
			const struct pubkey *to,
			u64 msatoshi,
			double riskfactor,
			s64 *fee,
			struct node_connection ***route);

struct node_map *empty_node_map(struct lightningd_state *dstate);

char *opt_add_route(const char *arg, struct lightningd_state *dstate);

#endif /* LIGHTNING_DAEMON_ROUTING_H */
