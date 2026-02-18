#include "config.h"
#include "bwatch.h"
#include "bwatch_store.h"
#include "bwatch_scanner.h"
#include "bwatch_interface.h"
#include <bitcoin/tx.h>
#include <ccan/mem/mem.h>
#include <plugins/libplugin.h>

/*
 * ============================================================================
 * TRANSACTION WATCH CHECKING
 * ============================================================================
 */

/* Check all txid watches via hash lookup */
static void check_txid_watches(struct command *cmd,
			       struct bwatch *bwatch,
			       const struct bitcoin_tx *tx,
			       u32 blockheight,
			       const struct bitcoin_blkid *blockhash,
			       u32 txindex)
{
	struct bitcoin_txid txid;
	struct watch *w;

	bitcoin_txid(tx, &txid);
	w = txid_watches_get(bwatch->txid_watches, &txid);
	if (!w)
		return;

	if (blockheight < w->start_block) {
		plugin_log(cmd->plugin, LOG_BROKEN,
			   "Watch for txid %s on height >= %u found on block %u???",
			   fmt_bitcoin_txid(tmpctx, &txid),
			   w->start_block, blockheight);
		return;
	}
	bwatch_send_watch_found(cmd, tx, blockheight, w, txindex, UINT32_MAX, UINT32_MAX);
}

/* Check all scriptpubkey watches via hash lookup */
static void check_scriptpubkey_watches(struct command *cmd,
				       struct bwatch *bwatch,
				       const struct bitcoin_tx *tx,
				       u32 blockheight,
				       const struct bitcoin_blkid *blockhash,
				       u32 txindex)
{
	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		struct watch *w;
		struct scriptpubkey k = {
			.script = tx->wtx->outputs[i].script,
			.len = tx->wtx->outputs[i].script_len
		};

		w = scriptpubkey_watches_get(bwatch->scriptpubkey_watches, &k);
		if (!w)
			continue;
		if (blockheight < w->start_block) {
			plugin_log(cmd->plugin, LOG_BROKEN,
				   "Watch for script %s on height >= %u found on block %u???",
				   tal_hexstr(tmpctx, k.script, k.len),
				   w->start_block, blockheight);
			continue;
		}
		bwatch_send_watch_found(cmd, tx, blockheight, w, txindex, i, UINT32_MAX);
	}
}

/* Check all outpoint watches via hash lookup */
static void check_outpoint_watches(struct command *cmd,
				   struct bwatch *bwatch,
				   const struct bitcoin_tx *tx,
				   u32 blockheight,
				   const struct bitcoin_blkid *blockhash,
				   u32 txindex)
{
	for (size_t i = 0; i < tx->wtx->num_inputs; i++) {
		struct watch *w;
		struct bitcoin_outpoint outpoint;

		bitcoin_tx_input_get_txid(tx, i, &outpoint.txid);
		outpoint.n = tx->wtx->inputs[i].index;

		w = outpoint_watches_get(bwatch->outpoint_watches, &outpoint);
		if (!w)
			continue;
		if (blockheight < w->start_block) {
			plugin_log(cmd->plugin, LOG_BROKEN,
				   "Watch for outpoint %s on height >= %u found on block %u???",
				   fmt_bitcoin_outpoint(tmpctx, &outpoint),
				   w->start_block, blockheight);
			continue;
		}
		bwatch_send_watch_found(cmd, tx, blockheight, w, txindex, UINT32_MAX, i);
	}
}

/* Check a tx against all watches (during normal block processing) */
static void check_tx_against_all_watches(struct command *cmd,
					 struct bwatch *bwatch,
					 const struct bitcoin_tx *tx,
					 u32 blockheight,
					 const struct bitcoin_blkid *blockhash,
					 u32 txindex)
{
	check_txid_watches(cmd, bwatch, tx, blockheight, blockhash, txindex);
	check_scriptpubkey_watches(cmd, bwatch, tx, blockheight, blockhash, txindex);
	check_outpoint_watches(cmd, bwatch, tx, blockheight, blockhash, txindex);
}

/* Check tx against a specific txid */
static void check_tx_txid(struct command *cmd,
			  const struct bitcoin_tx *tx,
			  const struct bitcoin_txid *tx_txid,
			  const struct watch *w,
			  u32 blockheight,
			  const struct bitcoin_blkid *blockhash,
			  u32 txindex)
{
	if (bitcoin_txid_eq(tx_txid, &w->key.txid))
		bwatch_send_watch_found(cmd, tx, blockheight, w, txindex, UINT32_MAX, UINT32_MAX);
}

/* Check tx outputs against a specific scriptpubkey */
static void check_tx_scriptpubkey(struct command *cmd,
				  const struct bitcoin_tx *tx,
				  const struct watch *w,
				  u32 blockheight,
				  const struct bitcoin_blkid *blockhash,
				  u32 txindex)
{
	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		if (memeq(tx->wtx->outputs[i].script, tx->wtx->outputs[i].script_len,
			  w->key.scriptpubkey.script, w->key.scriptpubkey.len)) {
			bwatch_send_watch_found(cmd, tx, blockheight, w, txindex, i, UINT32_MAX);
			/* Don't return - tx might have multiple outputs to same scriptpubkey */
		}
	}
}

/* Check tx inputs against a specific outpoint */
static void check_tx_outpoint(struct command *cmd,
			      const struct bitcoin_tx *tx,
			      const struct watch *w,
			      u32 blockheight,
			      const struct bitcoin_blkid *blockhash,
			      u32 txindex)
{
	for (size_t i = 0; i < tx->wtx->num_inputs; i++) {
		struct bitcoin_outpoint outpoint;

		bitcoin_tx_input_get_txid(tx, i, &outpoint.txid);
		outpoint.n = tx->wtx->inputs[i].index;

		if (bitcoin_outpoint_eq(&outpoint, &w->key.outpoint)) {
			bwatch_send_watch_found(cmd, tx, blockheight, w, txindex, UINT32_MAX, i);
			return; /* An outpoint can only be spent once */
		}
	}
}

/* Check a tx against a single watch key (during rescan) */
static void check_tx_for_single_watch(struct command *cmd,
				      const struct watch *w,
				      const struct bitcoin_tx *tx,
				      u32 blockheight,
				      const struct bitcoin_blkid *blockhash,
				      u32 txindex)
{
	struct bitcoin_txid txid;

	switch (w->type) {
	case WATCH_TXID:
		bitcoin_txid(tx, &txid);
		check_tx_txid(cmd, tx, &txid, w, blockheight, blockhash, txindex);
		break;
	case WATCH_SCRIPTPUBKEY:
		check_tx_scriptpubkey(cmd, tx, w, blockheight, blockhash, txindex);
		break;
	case WATCH_OUTPOINT:
		check_tx_outpoint(cmd, tx, w, blockheight, blockhash, txindex);
		break;
	}
}

/* Process all transactions in a block against watches.
 * If w is NULL, checks all watches (normal polling).
 * If w is non-NULL, checks only that specific watch (rescan). */
void bwatch_process_block_txs(struct command *cmd,
			      struct bwatch *bwatch,
			      const struct bitcoin_block *block,
			      u32 blockheight,
			      const struct bitcoin_blkid *blockhash,
			      const struct watch *w)
{
	for (size_t i = 0; i < tal_count(block->tx); i++) {
		if (w)
			check_tx_for_single_watch(cmd, w, block->tx[i],
						  blockheight, blockhash, i);
		else
			check_tx_against_all_watches(cmd, bwatch, block->tx[i],
						      blockheight, blockhash, i);
	}
}
