#ifndef LIGHTNING_DAEMON_PEER_H
#define LIGHTNING_DAEMON_PEER_H
#include "config.h"
#include "bitcoin/locktime.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/script.h"
#include "bitcoin/shadouble.h"
#include "funding.h"
#include "lightning.pb-c.h"
#include "netaddr.h"
#include "state.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/list/list.h>

struct peer_visible_state {
	/* CMD_OPEN_WITH_ANCHOR or CMD_OPEN_WITHOUT_ANCHOR */
	enum state_input offer_anchor;
	/* Key for commitment tx inputs, then key for commitment tx outputs */
	struct pubkey commitkey, finalkey;
	/* How long to they want the other's outputs locked (seconds) */
	struct rel_locktime locktime;
	/* Minimum depth of anchor before channel usable. */
	unsigned int mindepth;
	/* Commitment fee they're offering (satoshi). */
	u64 commit_fee;
	/* Revocation hash for latest commit tx. */
	struct sha256 revocation_hash;
	/* Current commit tx. */
	struct bitcoin_tx *commit;
};

struct htlc_progress {
	/* The HTLC we're working on. */
	struct channel_htlc *htlc;

	/* Set if we're fulfilling. */
	struct sha256 r;
	
	/* Our next state. */
	/* Channel funding state, after we've completed htlc. */
	struct channel_state *cstate;
	struct sha256 our_revocation_hash, their_revocation_hash;
	struct bitcoin_tx *our_commit, *their_commit;
	struct bitcoin_signature their_sig;
};

struct peer {
	/* dstate->peers list */
	struct list_node list;

	/* State in state machine. */
	enum state state;

	/* Condition of communications */
	enum state_peercond cond;

	/* Network connection. */
	struct io_conn *conn;

	/* Current command (or INPUT_NONE) */
	struct {
		enum state_input cmd;
		union input cmddata;
		struct command *jsoncmd;
	} curr_cmd;

	/* Pending commands. */
	struct list_head pending_cmd;
	
	/* Global state. */
	struct lightningd_state *dstate;

	/* Funding status for current commit tx (from our PoV). */
	struct channel_state *cstate;

	/* The other end's address. */
	struct netaddr addr;

	/* Their ID. */
	struct pubkey id;

	/* Current received packet. */
	Pkt *inpkt;

	/* Queue of output packets. */
	Pkt *outpkt[5];
	size_t num_outpkt;

	/* Anchor tx output */
	struct {
		struct sha256_double txid;
		unsigned int index;
		u64 satoshis;
		u8 *redeemscript;
		/* If we created it, we keep entire tx. */
		const struct bitcoin_tx *tx;
	} anchor;

	/* Their signature for our current commit sig. */
	struct bitcoin_signature cur_commit_theirsig;

	/* Current HTLC, if any. */
	struct htlc_progress *current_htlc;
	/* Number of HTLC updates (== number of previous commit txs) */
	u64 num_htlcs;

	/* Closing tx and signature once we've generated it */
	struct bitcoin_tx *close_tx;
	struct bitcoin_signature our_close_sig;
	
	/* Current ongoing packetflow */
	struct io_data *io_data;
	
	/* What happened. */
	struct log *log;

	/* Things we're watching for (see watches.c) */
	struct list_head watches;

	/* Timeout for close_watch. */
	struct oneshot *close_watch_timeout;
	
	/* Private keys for dealing with this peer. */
	struct peer_secrets *secrets;

	/* Stuff we have in common. */
	struct peer_visible_state us, them;
};

void setup_listeners(struct lightningd_state *dstate, unsigned int portnum);

void make_commit_txs(const tal_t *ctx,
		     const struct peer *peer,
		     const struct sha256 *our_revocation_hash,
		     const struct sha256 *their_revocation_hash,
		     const struct channel_state *cstate,
		     struct bitcoin_tx **ours, struct bitcoin_tx **theirs);

void peer_add_htlc_expiry(struct peer *peer,
			  const struct abs_locktime *expiry);

bool peer_create_close_tx(struct peer *peer, u64 fee_satoshis);

#endif /* LIGHTNING_DAEMON_PEER_H */
