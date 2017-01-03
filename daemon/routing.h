#ifndef LIGHTNING_DAEMON_ROUTING_H
#define LIGHTNING_DAEMON_ROUTING_H
#include "config.h"
#include "bitcoin/pubkey.h"
#include "wire/wire.h"

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

	/* Is this connection active? */
	bool active;

	u32 last_timestamp;

	/* Minimum number of msatoshi in an HTLC */
	u32 htlc_minimum_msat;
	
	/* The channel ID, as determined by the anchor transaction */
	struct channel_id channel_id;

	/* Flags as specified by the `channel_update`s, among other
	 * things indicated direction wrt the `channel_id` */
	u16 flags;

	/* Cached `channel_announcement` and `channel_update` we might forward to new peers*/
	u8 *channel_announcement;
	u8 *channel_update;
};

struct node {
	struct pubkey id;

	/* IP/Hostname and port of this node */
	char *hostname;
	int port;

	u32 last_timestamp;

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

	/* Color to be used when displaying the name */
	u8 rgb_color[3];

	/* Cached `node_announcement` we might forward to new peers. */
	u8 *node_announcement;
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

/* Add a connection to the routing table, but do not mark it as usable
 * yet. Used by channel_announcements before the channel_update comes
 * in. */

struct node_connection *half_add_connection(struct lightningd_state *dstate,
					    const struct pubkey *from,
					    const struct pubkey *to,
					    const struct channel_id *chanid,
					    const u16 flags);

/* Get an existing connection between `from` and `to`, NULL if no such
 * connection exists. */
struct node_connection *get_connection(struct lightningd_state *dstate,
				       const struct pubkey *from,
				       const struct pubkey *to);

/* Given a channel_id, retrieve the matching connection, or NULL if it is
 * unknown. */
struct node_connection *get_connection_by_cid(const struct lightningd_state *dstate,
					      const struct channel_id *chanid,
					      const u8 direction);

void remove_connection(struct lightningd_state *dstate,
		       const struct pubkey *src, const struct pubkey *dst);

struct peer *find_route(const tal_t *ctx,
			struct lightningd_state *dstate,
			const struct pubkey *to,
			u64 msatoshi,
			double riskfactor,
			s64 *fee,
			struct node_connection ***route);

struct node_map *empty_node_map(struct lightningd_state *dstate);

char *opt_add_route(const char *arg, struct lightningd_state *dstate);

/* Dump all known channels and nodes to the peer. Used when a new connection was established. */
void sync_routing_table(struct lightningd_state *dstate, struct peer *peer);

#endif /* LIGHTNING_DAEMON_ROUTING_H */
