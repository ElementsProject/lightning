#ifndef LIGHTNING_LIGHTNINGD_PEER_CONTROL_H
#define LIGHTNING_LIGHTNINGD_PEER_CONTROL_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/list/list.h>
#include <daemon/json.h>
#include <daemon/netaddr.h>
#include <lightningd/channel_config.h>
#include <stdbool.h>

#define ANNOUNCE_MIN_DEPTH 6

struct crypto_state;

struct peer {
	struct lightningd *ld;

	/* Unique ID (works before we know their pubkey) */
	u64 unique_id;

	/* Inside ld->peers. */
	struct list_node list;

	/* What stage is this in?  NULL during first creation. */
	struct subd *owner;

	/* What's happening (doubles as error return for connect_cmd) */
	const char *condition;

	/* History */
	struct log_book *log_book;
	struct log *log;

	/* ID of peer (NULL before initial handshake). */
	struct pubkey *id;

	/* Our fd to the peer (-1 when we don't have it). */
	int fd;

	/* Where we connected to, or it connected from. */
	struct netaddr netaddr;

	/* Json command which made us connect (if any) */
	struct command *connect_cmd;

	/* Our channel config. */
	struct channel_config our_config;

	/* Channel if locked. */
	struct short_channel_id *scid;

	/* Minimum funding depth (specified by us if they fund). */
	u32 minimum_depth;

	/* Funding txid and amounts (once known) */
	struct sha256_double *funding_txid;
	u16 funding_outnum;
	u64 funding_satoshi, push_msat;

	/* Channel balance (LOCAL and REMOTE); if we have one. */
	u64 *balance;

	/* Secret seed (FIXME: Move to hsm!) */
	struct privkey *seed;

	/* Gossip client fd, forwarded to the respective owner */
	int gossip_client_fd;
};

struct peer *peer_by_unique_id(struct lightningd *ld, u64 unique_id);
struct peer *peer_by_id(struct lightningd *ld, const struct pubkey *id);
struct peer *peer_from_json(struct lightningd *ld,
			    const char *buffer,
			    jsmntok_t *peeridtok);

void peer_accept_open(struct peer *peer,
		      const struct crypto_state *cs, const u8 *msg);

/* Peer has failed. */
PRINTF_FMT(2,3) void peer_fail(struct peer *peer, const char *fmt, ...);

PRINTF_FMT(2,3) void peer_set_condition(struct peer *peer, const char *fmt, ...);
void setup_listeners(struct lightningd *ld);
#endif /* LIGHTNING_LIGHTNINGD_PEER_CONTROL_H */
