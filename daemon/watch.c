/* Code to talk to bitcoind to watch for various events.
 *
 * Here's what we want to know:
 *
 * - An anchor tx:
 *   - Reached given depth
 *   - Times out.
 *   - Is unspent after reaching given depth.
 *
 * - Our own commitment tx:
 *   - Reached a given depth.
 *
 * - HTLC spend tx:
 *   - Reached a given depth.
 * 
 * - Anchor tx output:
 *   - Is spent by their current tx.
 *   - Is spent by a revoked tx.
 *
 * - Commitment tx HTLC outputs:
 *   - HTLC timed out
 *   - HTLC spent
 *
 * We do this by adding the P2SH address to the wallet, and then querying
 * that using listtransactions.
 *
 * WE ASSUME NO MALLEABILITY!  This requires segregated witness.
 */
#include "bitcoin/script.h"
#include "bitcoin/tx.h"
#include "bitcoind.h"
#include "lightningd.h"
#include "log.h"
#include "peer.h"
#include "timeout.h"
#include "watch.h"
#include <ccan/hash/hash.h>
#include <ccan/structeq/structeq.h>

const struct txwatch_output *txowatch_keyof(const struct txowatch *w)
{
	return &w->out;
}

size_t txo_hash(const struct txwatch_output *out)
{
	return hash(&out->txid, 1, out->index);
}

bool txowatch_eq(const struct txowatch *w, const struct txwatch_output *out)
{
	return structeq(&w->out.txid, &out->txid)
		&& w->out.index == out->index;
}

static void destroy_txowatch(struct txowatch *w)
{
	txowatch_hash_del(&w->peer->dstate->txowatches, w);
}

const struct sha256_double *txwatch_keyof(const struct txwatch *w)
{
	return &w->txid;
}

size_t txid_hash(const struct sha256_double *txid)
{
	return hash(txid->sha.u.u8, sizeof(txid->sha.u.u8), 0);
}

bool txwatch_eq(const struct txwatch *w, const struct sha256_double *txid)
{
	return structeq(&w->txid, txid);
}

static void destroy_txwatch(struct txwatch *w)
{
	txwatch_hash_del(&w->dstate->txwatches, w);
}

/* FIXME: This is a hack! */
void peer_watch_setup(struct peer *peer)
{
	struct sha256 h;
	struct ripemd160 redeemhash;

	/* Telling bitcoind to watch the redeemhash address means
	 * it'll tell is about the anchor itself (spend to that
	 * address), and any commit txs (spend from that address).*/
	sha256(&h, peer->anchor.redeemscript,
	       tal_count(peer->anchor.redeemscript));
	ripemd160(&redeemhash, h.u.u8, sizeof(h));

	bitcoind_watch_addr(peer->dstate, &redeemhash);
}

struct txwatch *watch_txid_(const tal_t *ctx,
			    struct peer *peer,
			    const struct sha256_double *txid,
			    void (*cb)(struct peer *peer, int depth,
				       const struct sha256_double *blkhash,
				       const struct sha256_double *txid,
				       void *arg),
			    void *cb_arg)
{
	struct txwatch *w;

	assert(!txwatch_hash_get(&peer->dstate->txwatches, txid));

	w = tal(ctx, struct txwatch);
	w->depth = -1;
	w->txid = *txid;
	w->dstate = peer->dstate;
	w->peer = peer;
	w->cb = cb;
	w->cbdata = cb_arg;

	txwatch_hash_add(&w->dstate->txwatches, w);
	tal_add_destructor(w, destroy_txwatch);

	return w;
}

struct txwatch *watch_tx_(const tal_t *ctx,
			 struct peer *peer,
			 const struct bitcoin_tx *tx,
			 void (*cb)(struct peer *peer, int depth,
				    const struct sha256_double *blkhash,
				    const struct sha256_double *txid,
				    void *arg),
			  void *cb_arg)
{
	struct sha256_double txid;

	normalized_txid(tx, &txid);
	return watch_txid(ctx, peer, &txid, cb, cb_arg);
}

struct txowatch *watch_txo_(const tal_t *ctx,
			    struct peer *peer,
			    const struct sha256_double *txid,
			    unsigned int output,
			    void (*cb)(struct peer *peer,
				       const struct bitcoin_tx *tx,
				       void *),
			    void *cbdata)
{
	struct txowatch *w = tal(ctx, struct txowatch);

	w->out.txid = *txid;
	w->out.index = output;
	w->peer = peer;
	w->cb = cb;
	w->cbdata = cbdata;

	txowatch_hash_add(&w->peer->dstate->txowatches, w);
	tal_add_destructor(w, destroy_txowatch);

	return w;
}

struct tx_info {
	struct sha256_double blkhash;
	int conf;
};

static void insert_null_txwatch(struct lightningd_state *dstate,
				const struct sha256_double *txid)
{
	struct txwatch *w = tal(dstate, struct txwatch);
	w->depth = 0;
	w->txid = *txid;
	w->dstate = dstate;
	w->peer = NULL;
	w->cb = NULL;
	w->cbdata = NULL;

	txwatch_hash_add(&w->dstate->txwatches, w);
	tal_add_destructor(w, destroy_txwatch);
}

static void watched_normalized_txid(struct lightningd_state *dstate,
				    const struct bitcoin_tx *tx,
				    struct tx_info *txinfo)
{
	struct txwatch *txw;
	struct sha256_double txid;
	size_t i;
	
	normalized_txid(tx, &txid);
	txw = txwatch_hash_get(&dstate->txwatches, &txid);

	/* Reset to real txid for logging. */
	bitcoin_txid(tx, &txid);

	if (txw) {
		if (txinfo->conf != txw->depth) {
			log_debug(txw->peer->log,
				  "Got depth change %u for %02x%02x%02x...\n",
				  txinfo->conf,
				  txid.sha.u.u8[0],
				  txid.sha.u.u8[1],
				  txid.sha.u.u8[2]);
			txw->depth = txinfo->conf;
			txw->cb(txw->peer, txw->depth, &txinfo->blkhash, &txid,
				txw->cbdata);
		}
		return;
	}

	/* Hmm, otherwise it may be new */
	for (i = 0; i < tx->input_count; i++) {
		struct txowatch *txo;
		struct txwatch_output out;

		out.txid = tx->input[i].txid;
		out.index = tx->input[i].index;
		txo = txowatch_hash_get(&dstate->txowatches, &out);

		/* Presumably, this sets a watch on it. */
		if (txo) {
			log_debug(txo->peer->log,
				  "New tx spending %02x%02x%02x output %u:"
				  " %02x%02x%02x...\n",
				  out.txid.sha.u.u8[0],
				  out.txid.sha.u.u8[1],
				  out.txid.sha.u.u8[2],
				  out.index,
				  txid.sha.u.u8[0],
				  txid.sha.u.u8[1],
				  txid.sha.u.u8[2]);
			txo->cb(txo->peer, tx, txo->cbdata);
			return;
		}
	}

	/* OK, not interesting.  Put in fake (on original txid). */
	log_debug(dstate->base_log, "Ignoring tx %02x%02x%02x...\n",
		  txid.sha.u.u8[0],
		  txid.sha.u.u8[1],
		  txid.sha.u.u8[2]);
	insert_null_txwatch(dstate, &txid);
}

static void watched_txid(struct lightningd_state *dstate,
			 const struct sha256_double *txid,
			 int confirmations,
			 bool is_coinbase,
			 const struct sha256_double *blkhash)

{
	struct txwatch *txw;
	struct tx_info *txinfo;

	/* Maybe it spent an output we're watching? */
	if (is_coinbase)
		return;

	/* Are we watching this txid directly (or already reported)? */
	txw = txwatch_hash_get(&dstate->txwatches, txid);
	if (txw) {
		if (txw->cb && confirmations != txw->depth) {
			txw->depth = confirmations;
			txw->cb(txw->peer, txw->depth, blkhash, txid,
				txw->cbdata);
		}
		return;
	}

	txinfo = tal(dstate, struct tx_info);
	txinfo->conf = confirmations;
	if (blkhash)
		txinfo->blkhash = *blkhash;
	/* FIXME: Since we don't use segwit, we need to normalize txids. */
	bitcoind_txid_lookup(dstate, txid, watched_normalized_txid, txinfo);
}

static struct timeout watch_timeout;

static void start_poll_transactions(struct lightningd_state *dstate)
{
	if (!list_empty(&dstate->bitcoin_req)) {
		log_unusual(dstate->base_log,
			    "Delaying start poll: commands in progress");
	} else
		bitcoind_poll_transactions(dstate, watched_txid);
	refresh_timeout(dstate, &watch_timeout);
}

void setup_watch_timer(struct lightningd_state *dstate)
{
	init_timeout(&watch_timeout, dstate->config.poll_seconds,
		     start_poll_transactions, dstate);
	/* Run once immediately, in case there are issues. */
	start_poll_transactions(dstate);
}
