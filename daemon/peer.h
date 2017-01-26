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

struct anchor_input {
	struct sha256_double txid;
	unsigned int index;
	/* Amount of input (satoshis), and output (satoshis) */
	u64 in_amount, out_amount;
	/* Wallet entry to use to spend. */
	struct pubkey walletkey;
};

/* Information we remember for their commitment txs which we signed.
 *
 * Given the commit_num, we can use shachain to derive the revocation preimage
 * (if we've received it yet: we might have not, for the last).
 */
struct their_commit {
	struct list_node list;

	struct sha256_double txid;
	u64 commit_num;
};

struct commit_info {
	/* Commit number (0 == from open) */
	u64 commit_num;
	/* Revocation hash. */
	struct sha256 revocation_hash;
	/* Commit tx & txid */
	struct bitcoin_tx *tx;
	struct sha256_double txid;
	/* Channel state for this tx. */
	struct channel_state *cstate;
	/* Other side's signature for last commit tx (if known) */
	secp256k1_ecdsa_signature *sig;
	/* Order which commit was sent (theirs) / revocation was sent (ours) */
	s64 order;
};

struct peer_visible_state {
	/* Is this side funding the channel? */
	bool offer_anchor;
	/* Key for commitment tx inputs, then key for commitment tx outputs */
	struct pubkey commitkey, finalkey;
	/* How long to they want the other's outputs locked (blocks) */
	struct rel_locktime locktime;
	/* Minimum depth of anchor before channel usable. */
	unsigned int mindepth;
	/* Commitment fee they're offering (satoshi). */
	u64 commit_fee_rate;
	/* Revocation hash for next commit tx. */
	struct sha256 next_revocation_hash;
	/* Commit txs: last one is current. */
	struct commit_info *commit;

	/* cstate to generate next commitment tx. */
	struct channel_state *staging_cstate;
};

/* Off peer->outgoing_txs */
struct outgoing_tx {
	struct list_node list;
	struct peer *peer;
	const char *hextx;
	struct sha256_double txid;
	void (*failed)(struct peer *peer, int exitstatus, const char *err);
};

struct peer {
	/* dstate->peers list */
	struct list_node list;

	/* State in state machine. */
	enum state state;

	/* Network connection. */
	struct io_conn *conn;

	/* Are we connected now? (Crypto handshake completed). */
	bool connected;

	/* If we're doing an open, this is the command which triggered it */
	struct command *open_jsoncmd;

	/* If we're doing a commit, this is the command which triggered it */
	struct command *commit_jsoncmd;

	/* Global state. */
	struct lightningd_state *dstate;

	/* Their ID. */
	struct pubkey *id;

	/* Order counter for transmission of revocations/commitments. */
	s64 order_counter;

	/* Current received packet. */
	Pkt *inpkt;

	/* Queue of output packets. */
	Pkt **outpkt;

	/* Their commitments we have signed (which could appear on chain). */
	struct list_head their_commits;

	/* Number of commitment signatures we've received. */
	u64 their_commitsigs;

	/* Anchor tx output */
	struct {
		struct sha256_double txid;
		unsigned int index;
		u64 satoshis;
		u8 *witnessscript;

		/* Minimum possible depth for anchor */
		unsigned int min_depth;

		/* If we're creating anchor, this tells us where to source it */
		struct anchor_input *input;

		/* If we created it, we keep entire tx. */
		const struct bitcoin_tx *tx;

		/* Depth to trigger anchor if still opening, or -1. */
		int ok_depth;

		/* Did we create anchor? */
		bool ours;
	} anchor;

	struct {
		/* Their signature for our current commit sig. */
		secp256k1_ecdsa_signature theirsig;
		/* The watch we have on a live commit tx. */
		struct txwatch *watch;
	} cur_commit;

	/* Counter to make unique HTLC ids. */
	u64 htlc_id_counter;

	/* Mutual close info. */
	struct {
		/* Our last suggested closing fee. */
		u64 our_fee;
		/* If they've offered a signature, these are set: */
		secp256k1_ecdsa_signature *their_sig;
		/* If their_sig is non-NULL, this is the fee. */
		u64 their_fee;
		/* scriptPubKey we/they want for closing. */
		u8 *our_script, *their_script;
		/* Last sent (in case we need to retransmit) */
		s64 shutdown_order, closing_order;
		/* How many closing sigs have we receieved? */
		u32 sigs_in;
	} closing;

	/* If we're closing on-chain */
	struct {
		/* Everything (watches, resolved[], etc) tal'ed off this:
		 * The commit which spends the anchor tx. */
		const struct bitcoin_tx *tx;
		struct sha256_double txid;

		/* If >= 0, indicates which txout is to us and to them. */
		int to_us_idx, to_them_idx;
		/* Maps what txouts are HTLCs (NULL implies to_us/them_idx). */
		struct htlc **htlcs;
		/* Witness scripts for each output (where appropriate) */
		const u8 **wscripts;
		/* The tx which resolves each txout. */
		const struct bitcoin_tx **resolved;
	} onchain;

	/* All HTLCs. */
	struct htlc_map htlcs;

	/* We only track one feechange per state: last one counts. */
	struct feechange *feechanges[FEECHANGE_STATE_INVALID];

	/* Current ongoing packetflow */
	struct io_data *io_data;

	/* What happened. */
	struct log *log;

	/* Things we're watching for (see watches.c) */
	struct list_head watches;

	/* Bitcoin transctions we're broadcasting (see chaintopology.c) */
	struct list_head outgoing_txs;

	/* Timeout for collecting changes before sending commit. */
	struct oneshot *commit_timer;

	/* Private keys for dealing with this peer. */
	struct peer_secrets *secrets;

	/* Our route connection to peer: NULL until we are in normal mode. */
	struct node_connection *nc;

	/* For testing. */
	bool fake_close;
	bool output_enabled;

	/* Stuff we have in common. */
	struct peer_visible_state local, remote;

	/* If we have sent a new commit tx, but not received their revocation */
	struct sha256 *their_prev_revocation_hash;

	/* this is where we will store their revocation preimages*/
	struct shachain their_preimages;

	/* High water mark for the staggered broadcast */
	u64 broadcast_index;
};

/* Mapping for id -> network address. */
struct peer_address {
	struct list_node list;
	struct pubkey id;
	struct netaddr addr;
};

void setup_listeners(struct lightningd_state *dstate);

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

void peers_new_block(struct lightningd_state *dstate, unsigned int height);

/* Peer has an issue, breakdown and fail. */
void peer_fail(struct peer *peer, const char *caller);

void peer_watch_anchor(struct peer *peer, int depth);

struct bitcoin_tx *peer_create_close_tx(const tal_t *ctx,
					struct peer *peer, u64 fee);

void debug_dump_peers(struct lightningd_state *dstate);

void reconnect_peers(struct lightningd_state *dstate);
void rebroadcast_anchors(struct lightningd_state *dstate);
void cleanup_peers(struct lightningd_state *dstate);
#endif /* LIGHTNING_DAEMON_PEER_H */
