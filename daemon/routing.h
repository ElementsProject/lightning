#ifndef LIGHTNING_DAEMON_ROUTING_H
#define LIGHTNING_DAEMON_ROUTING_H
#include "config.h"
#include "bitcoin/pubkey.h"
#include "daemon/broadcast.h"
#include "wire/wire.h"
#include <ccan/htable/htable_type.h>

#define ROUTING_MAX_HOPS 20
#define ROUTING_FLAGS_DISABLED 2

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
	struct short_channel_id short_channel_id;

	/* Flags as specified by the `channel_update`s, among other
	 * things indicated direction wrt the `channel_id` */
	u16 flags;

	/* Cached `channel_announcement` and `channel_update` we might forward to new peers*/
	u8 *channel_announcement;
	u8 *channel_update;
};

struct node {
	struct pubkey id;

	/* IP/Hostname and port of this node (may be NULL) */
	struct ipaddr *addresses;

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

const secp256k1_pubkey *node_map_keyof_node(const struct node *n);
size_t node_map_hash_key(const secp256k1_pubkey *key);
bool node_map_node_eq(const struct node *n, const secp256k1_pubkey *key);
HTABLE_DEFINE_TYPE(struct node, node_map_keyof_node, node_map_hash_key, node_map_node_eq, node_map);

struct lightningd_state;

struct routing_state {
	/* All known nodes. */
	struct node_map *nodes;

	struct log *base_log;

	struct broadcast_state *broadcasts;
};

struct route_hop {
	struct short_channel_id channel_id;
	struct pubkey nodeid;
	u32 amount;
	u32 delay;
};

//FIXME(cdecker) The log will have to be replaced for the new subdaemon, keeping for now to keep changes small.
struct routing_state *new_routing_state(const tal_t *ctx, struct log *base_log);

struct node *new_node(struct routing_state *rstate,
		      const struct pubkey *id);

struct node *get_node(struct routing_state *rstate,
		      const struct pubkey *id);

/* msatoshi must be possible (< 21 million BTC), ie < 2^60.
 * If it returns more than msatoshi, it overflowed. */
s64 connection_fee(const struct node_connection *c, u64 msatoshi);

/* Updates existing node, or creates a new one as required. */
struct node *add_node(struct routing_state *rstate,
		      const struct pubkey *pk);

/* Updates existing connection, or creates new one as required. */
struct node_connection *add_connection(struct routing_state *rstate,
				       const struct pubkey *from,
				       const struct pubkey *to,
				       u32 base_fee, s32 proportional_fee,
				       u32 delay, u32 min_blocks);

/* Add a connection to the routing table, but do not mark it as usable
 * yet. Used by channel_announcements before the channel_update comes
 * in. */

struct node_connection *half_add_connection(struct routing_state *rstate,
					    const struct pubkey *from,
					    const struct pubkey *to,
					    const struct short_channel_id *schanid,
					    const u16 flags);

/* Get an existing connection between `from` and `to`, NULL if no such
 * connection exists. */
struct node_connection *get_connection(struct routing_state *rstate,
				       const struct pubkey *from,
				       const struct pubkey *to);

/* Given a short_channel_id, retrieve the matching connection, or NULL if it is
 * unknown. */
struct node_connection *get_connection_by_scid(const struct routing_state *rstate,
					       const struct short_channel_id *schanid,
					      const u8 direction);

void remove_connection(struct routing_state *rstate,
		       const struct pubkey *src, const struct pubkey *dst);

struct node_connection *
find_route(const tal_t *ctx, struct routing_state *rstate,
	   const struct pubkey *from, const struct pubkey *to, u64 msatoshi,
	   double riskfactor, s64 *fee, struct node_connection ***route);

struct node_map *empty_node_map(const tal_t *ctx);

char *opt_add_route(const char *arg, struct lightningd_state *dstate);

bool add_channel_direction(struct routing_state *rstate,
			   const struct pubkey *from,
			   const struct pubkey *to,
			   const struct short_channel_id *short_channel_id,
			   const u8 *announcement);

bool read_ip(const tal_t *ctx, const u8 *addresses, char **hostname, int *port);
u8 *write_ip(const tal_t *ctx, const char *srcip, int port);

/* Handlers for incoming messages */
void handle_channel_announcement(struct routing_state *rstate, const u8 *announce, size_t len);
void handle_channel_update(struct routing_state *rstate, const u8 *update, size_t len);
void handle_node_announcement(struct routing_state *rstate, const u8 *node, size_t len);

/* Compute a route to a destination, for a given amount and riskfactor. */
struct route_hop *get_route(tal_t *ctx, struct routing_state *rstate,
			    const struct pubkey *source,
			    const struct pubkey *destination,
			    const u32 msatoshi, double riskfactor);

/* Utility function that, given a source and a destination, gives us
 * the direction bit the matching channel should get */
#define get_channel_direction(from, to) (pubkey_cmp(from, to) > 0)

bool short_channel_id_from_str(const char *str, size_t strlen,
			       struct short_channel_id *dst);

bool short_channel_id_eq(const struct short_channel_id *a,
			 const struct short_channel_id *b);

#endif /* LIGHTNING_DAEMON_ROUTING_H */
