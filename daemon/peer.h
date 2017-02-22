#ifndef LIGHTNING_DAEMON_PEER_H
#define LIGHTNING_DAEMON_PEER_H
#include "config.h"
#include "bitcoin/locktime.h"
#include "bitcoin/privkey.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/script.h"
#include "bitcoin/shadouble.h"
#include "channel.h"
#include "failure.h"
#include "feechange.h"
#include "htlc.h"
#include "lightning.pb-c.h"
#include "netaddr.h"
#include "protobuf_convert.h"
#include "state.h"
#include "wire/gen_peer_wire.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/list/list.h>
#include <ccan/time/time.h>
#include <ccan/io/io.h>

struct io_plan *pkt_in(struct io_conn *conn, struct peer *peer);

struct log;
struct lightningd_state;
struct peer;

/* Mapping for id -> network address. */
struct peer_address {
	struct list_node list;
	struct pubkey id;
	struct netaddr addr;
};

void setup_listeners(struct lightningd_state *dstate);

void peer_debug(struct peer *peer, const char *fmt, ...)
	PRINTF_FMT(2,3);

struct peer *find_peer(struct lightningd_state *dstate, const struct pubkey *id);
struct peer *find_peer_by_pkhash(struct lightningd_state *dstate, const u8 *pkhash);

struct peer *new_peer(struct lightningd_state *dstate,
		      struct log *log,
		      enum state state,
		      bool offer_anchor);

/* Populates very first peer->{local,remote}.commit->{tx,cstate} */
bool setup_first_commit(struct peer *peer);

/* Whenever we send a signature, remember the txid -> commit_num mapping */
void peer_add_their_commit(struct peer *peer,
			   const struct sha256_double *txid, u64 commit_num);

/* Allocate a new commit_info struct. */
struct commit_info *new_commit_info(const tal_t *ctx, u64 commit_num);

/* Freeing removes from map, too */
struct htlc *peer_new_htlc(struct peer *peer,
			   u64 id,
			   u64 msatoshi,
			   const struct sha256 *rhash,
			   u32 expiry,
			   const u8 *route,
			   size_t route_len,
			   struct htlc *src,
			   enum htlc_state state);

const char *command_htlc_add(struct peer *peer, u64 msatoshi,
			     unsigned int expiry,
			     const struct sha256 *rhash,
			     struct htlc *src,
			     const u8 *route,
			     enum fail_error *error_code,
			     struct htlc **htlc);

/* Peer has an issue, breakdown and fail. */
void peer_fail(struct peer *peer, const char *caller);

void peer_watch_anchor(struct peer *peer, int depth);

struct bitcoin_tx *peer_create_close_tx(const tal_t *ctx,
					struct peer *peer, u64 fee);

u32 get_peer_min_block(struct lightningd_state *dstate);

void debug_dump_peers(struct lightningd_state *dstate);

void reconnect_peers(struct lightningd_state *dstate);
void rebroadcast_anchors(struct lightningd_state *dstate);
void cleanup_peers(struct lightningd_state *dstate);
#endif /* LIGHTNING_DAEMON_PEER_H */
