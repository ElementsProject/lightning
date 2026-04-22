#include "config.h"
#include <ccan/tal/str/str.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/timeout.h>
#include <lightningd/bitcoind.h>
#include <lightningd/broadcast.h>
#include <lightningd/chaintopology.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <wallet/wallet.h>

bool we_broadcast(const struct lightningd *ld,
		  const struct bitcoin_txid *txid)
{
	return outgoing_tx_map_exists(ld->topology->outgoing_txs, txid);
}

struct tx_rebroadcast {
	/* otx destructor sets this to NULL if it's been freed */
	struct outgoing_tx *otx;

	/* Pointer to how many are remaining: last one frees! */
	size_t *num_rebroadcast_remaining;
};

/* We are last.  Refresh timer, and free refcnt */
static void rebroadcasts_complete(struct lightningd *ld,
				  size_t *num_rebroadcast_remaining)
{
	tal_free(num_rebroadcast_remaining);
	ld->topology->rebroadcast_timer
		= new_reltimer(ld->timers, ld->topology,
			       time_from_sec(30 + pseudorand(30)),
			       rebroadcast_txs, ld);
}

static void destroy_tx_broadcast(struct tx_rebroadcast *txrb,
				 struct lightningd *ld)
{
	if (--*txrb->num_rebroadcast_remaining == 0)
		rebroadcasts_complete(ld, txrb->num_rebroadcast_remaining);
}

static void rebroadcast_done(struct bitcoind *bitcoind,
			     bool success, const char *msg,
			     struct tx_rebroadcast *txrb)
{
	if (!success)
		log_debug(bitcoind->log,
			  "Expected error broadcasting tx %s: %s",
			  fmt_bitcoin_tx(tmpctx, txrb->otx->tx), msg);

	/* Last one freed calls rebroadcasts_complete */
	tal_free(txrb);
}

/* FIXME: This is dumb.  We can group txs and avoid bothering bitcoind
 * if any one tx is in the main chain. */
void rebroadcast_txs(struct lightningd *ld)
{
	/* Copy txs now (peers may go away, and they own txs). */
	struct outgoing_tx *otx;
	struct outgoing_tx_map_iter it;
	tal_t *cleanup_ctx = tal(NULL, char);
	size_t *num_rebroadcast_remaining = notleak(tal(ld, size_t));

	*num_rebroadcast_remaining = 0;
	for (otx = outgoing_tx_map_first(ld->topology->outgoing_txs, &it); otx;
	     otx = outgoing_tx_map_next(ld->topology->outgoing_txs, &it)) {
		struct tx_rebroadcast *txrb;
		/* Already sent? */
		if (wallet_transaction_height(ld->wallet, &otx->txid))
			continue;

		/* Don't send ones which aren't ready yet.  Note that if the
		 * minimum block is N, we broadcast it when we have block N-1! */
		if (get_block_height(ld->topology) + 1 < otx->minblock)
			continue;

		/* Don't free from txmap inside loop! */
		if (otx->refresh
		    && !otx->refresh(otx->channel, &otx->tx, otx->cbarg)) {
			tal_steal(cleanup_ctx, otx);
			continue;
		}

		txrb = tal(otx, struct tx_rebroadcast);
		txrb->otx = otx;
		txrb->num_rebroadcast_remaining = num_rebroadcast_remaining;
		(*num_rebroadcast_remaining)++;
		tal_add_destructor2(txrb, destroy_tx_broadcast, ld);
		bitcoind_sendrawtx(txrb, ld->topology->bitcoind,
				   tal_strdup_or_null(tmpctx, otx->cmd_id),
				   fmt_bitcoin_tx(tmpctx, otx->tx),
				   otx->allowhighfees,
				   rebroadcast_done,
				   txrb);
	}
	tal_free(cleanup_ctx);

	/* Free explicitly in case we were called because a block came in. */
	ld->topology->rebroadcast_timer
		= tal_free(ld->topology->rebroadcast_timer);

	/* Nothing to broadcast?  Reset timer immediately */
	if (*num_rebroadcast_remaining == 0)
		rebroadcasts_complete(ld, num_rebroadcast_remaining);
}

static void destroy_outgoing_tx(struct outgoing_tx *otx, struct lightningd *ld)
{
	outgoing_tx_map_del(ld->topology->outgoing_txs, otx);
}

static void broadcast_done(struct bitcoind *bitcoind,
			   bool success, const char *msg,
			   struct outgoing_tx *otx)
{
	struct lightningd *ld = bitcoind->ld;

	if (otx->finished) {
		if (otx->finished(otx->channel, otx->tx, success, msg, otx->cbarg)) {
			tal_free(otx);
			return;
		}
	}

	if (we_broadcast(ld, &otx->txid)) {
		log_debug(ld->log,
			  "Not adding %s to list of outgoing transactions, already "
			  "present",
			  fmt_bitcoin_txid(tmpctx, &otx->txid));
		tal_free(otx);
		return;
	}

	/* For continual rebroadcasting, until context freed. */
	outgoing_tx_map_add(ld->topology->outgoing_txs, otx);
	tal_add_destructor2(otx, destroy_outgoing_tx, ld);
}

void broadcast_tx_(const tal_t *ctx,
		   struct lightningd *ld,
		   struct channel *channel, const struct bitcoin_tx *tx,
		   const char *cmd_id, bool allowhighfees, u32 minblock,
		   bool (*finished)(struct channel *channel,
				    const struct bitcoin_tx *tx,
				    bool success,
				    const char *err,
				    void *cbarg),
		   bool (*refresh)(struct channel *channel,
				   const struct bitcoin_tx **tx,
				   void *cbarg),
		   void *cbarg)
{
	struct outgoing_tx *otx = tal(ctx, struct outgoing_tx);

	otx->channel = channel;
	bitcoin_txid(tx, &otx->txid);
	otx->tx = clone_bitcoin_tx(otx, tx);
	otx->minblock = minblock;
	otx->allowhighfees = allowhighfees;
	otx->finished = finished;
	otx->refresh = refresh;
	otx->cbarg = cbarg;
	if (taken(otx->cbarg))
		tal_steal(otx, otx->cbarg);
	otx->cmd_id = tal_strdup_or_null(otx, cmd_id);

	/* Note that if the minimum block is N, we broadcast it when
	 * we have block N-1! */
	if (get_block_height(ld->topology) + 1 < otx->minblock) {
		log_debug(ld->log,
			  "Deferring broadcast of txid %s until block %u",
			  fmt_bitcoin_txid(tmpctx, &otx->txid),
			  otx->minblock - 1);

		/* For continual rebroadcasting, until channel freed. */
		tal_steal(otx->channel, otx);
		outgoing_tx_map_add(ld->topology->outgoing_txs, otx);
		tal_add_destructor2(otx, destroy_outgoing_tx, ld);
		return;
	}

	log_debug(ld->log, "Broadcasting txid %s%s%s",
		  fmt_bitcoin_txid(tmpctx, &otx->txid),
		  cmd_id ? " for " : "", cmd_id ? cmd_id : "");

	wallet_transaction_add(ld->wallet, tx->wtx, 0, 0);
	bitcoind_sendrawtx(otx, ld->topology->bitcoind, otx->cmd_id,
			   fmt_bitcoin_tx(tmpctx, otx->tx),
			   allowhighfees,
			   broadcast_done, otx);
}

void broadcast_shutdown(struct lightningd *ld)
{
	struct outgoing_tx *otx;
	struct outgoing_tx_map_iter it;
	for (otx = outgoing_tx_map_first(ld->topology->outgoing_txs, &it); otx;
	     otx = outgoing_tx_map_next(ld->topology->outgoing_txs, &it)) {
		tal_del_destructor2(otx, destroy_outgoing_tx, ld);
		tal_free(otx);
	}
}
