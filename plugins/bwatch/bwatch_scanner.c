#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/mem/mem.h>
#include <common/utils.h>
#include <plugins/bwatch/bwatch_interface.h>
#include <plugins/bwatch/bwatch_scanner.h>
#include <plugins/bwatch/bwatch_store.h>
#include <plugins/libplugin.h>

/*
 * ============================================================================
 * TRANSACTION WATCH CHECKING
 * ============================================================================
 */

/* Check all scriptpubkey watches via hash lookup */
static void check_scriptpubkey_watches(struct command *cmd,
				       struct bwatch *bwatch,
				       const struct bitcoin_tx *tx,
				       u32 blockheight,
				       const struct bitcoin_blkid *blockhash,
				       u32 txindex)
{
	struct bitcoin_txid txid;

	bitcoin_txid(tx, &txid);

	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		struct watch *w;
		struct scriptpubkey k = {
			.script = tx->wtx->outputs[i].script,
			.len = tx->wtx->outputs[i].script_len
		};

		w = scriptpubkey_watches_get(bwatch->scriptpubkey_watches, &k);
		if (!w)
			continue;
		if (w->start_block != UINT32_MAX
		    && blockheight < w->start_block) {
			plugin_log(cmd->plugin, LOG_BROKEN,
				   "Watch for script %s on height >= %u found on block %u???",
				   tal_hexstr(tmpctx, k.script, k.len),
				   w->start_block, blockheight);
			continue;
		}
		bwatch_send_watch_found(cmd, tx, blockheight, w, txindex, i);
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
		if (w->start_block != UINT32_MAX
		    && blockheight < w->start_block) {
			plugin_log(cmd->plugin, LOG_BROKEN,
				   "Watch for outpoint %s on height >= %u found on block %u???",
				   fmt_bitcoin_outpoint(tmpctx, &outpoint),
				   w->start_block, blockheight);
			continue;
		}
		bwatch_send_watch_found(cmd, tx, blockheight, w, txindex, i);
	}
}

/* Check a tx against all watches (during normal block processing).
 * UTXO spend tracking is handled by lightningd via outpoint watches
 * (wallet/utxo/<outpoint> fires wallet_utxo_spent_watch_found). */
static void check_tx_against_all_watches(struct command *cmd,
					 struct bwatch *bwatch,
					 const struct bitcoin_tx *tx,
					 u32 blockheight,
					 const struct bitcoin_blkid *blockhash,
					 u32 txindex)
{
	check_scriptpubkey_watches(cmd, bwatch, tx, blockheight, blockhash, txindex);
	check_outpoint_watches(cmd, bwatch, tx, blockheight, blockhash, txindex);
}

/* Check tx outputs against a single scriptpubkey watch (rescan path). */
static void check_tx_scriptpubkey(struct command *cmd,
				  const struct bitcoin_tx *tx,
				  const struct watch *w,
				  u32 blockheight,
				  const struct bitcoin_blkid *blockhash,
				  u32 txindex)
{
	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		if (memeq(tx->wtx->outputs[i].script,
			  tx->wtx->outputs[i].script_len,
			  w->key.scriptpubkey.script,
			  w->key.scriptpubkey.len)) {
			bwatch_send_watch_found(cmd, tx, blockheight, w,
						txindex, i);
			/* Same scriptpubkey may appear in multiple outputs. */
		}
	}
}

/* Check tx inputs against a single outpoint watch (rescan path). */
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
			bwatch_send_watch_found(cmd, tx, blockheight, w,
						txindex, i);
			return; /* an outpoint can only be spent once */
		}
	}
}

/* Dispatch a single watch against one tx (rescan path). */
static void check_tx_for_single_watch(struct command *cmd,
				      const struct watch *w,
				      const struct bitcoin_tx *tx,
				      u32 blockheight,
				      const struct bitcoin_blkid *blockhash,
				      u32 txindex)
{
	switch (w->type) {
	case WATCH_SCRIPTPUBKEY:
		check_tx_scriptpubkey(cmd, tx, w, blockheight, blockhash, txindex);
		break;
	case WATCH_OUTPOINT:
		check_tx_outpoint(cmd, tx, w, blockheight, blockhash, txindex);
		break;
	case WATCH_SCID:
		/* scid watches don't scan transactions: txindex is encoded in
		 * the scid key, so bwatch_check_scid_watches handles them
		 * directly at the block level. */
		break;
	case WATCH_BLOCKDEPTH:
		/* blockdepth watches fire per block; no per-tx work. */
		break;
	}
}

/* Fire watch_found for a scid watch anchored to this block. */
static void maybe_fire_scid_watch(struct command *cmd,
				  const struct bitcoin_block *block,
				  u32 blockheight,
				  const struct watch *w)
{
	struct bitcoin_tx *tx;
	u32 scid_blockheight, txindex, outnum;

	assert(w->type == WATCH_SCID);

	/* The scid pins the watch to one specific block. */
	scid_blockheight = short_channel_id_blocknum(w->key.scid);
	if (scid_blockheight != blockheight)
		return;

	txindex = short_channel_id_txnum(w->key.scid);
	outnum = short_channel_id_outnum(w->key.scid);

	/* Out-of-range (txindex or outnum) means the scid doesn't match
	 * anything on this chain; fire watch_found with tx=NULL so
	 * lightningd cleans the watch up. */
	if (txindex >= tal_count(block->tx)) {
		plugin_log(cmd->plugin, LOG_BROKEN,
			   "scid watch blockheight=%u txindex=%u outnum=%u: txindex out of range (block has %zu txs)",
			   blockheight, txindex, outnum, tal_count(block->tx));
		bwatch_send_watch_found(cmd, NULL, blockheight, w, txindex, outnum);
		return;
	}
	tx = block->tx[txindex];
	if (outnum >= tx->wtx->num_outputs) {
		plugin_log(cmd->plugin, LOG_BROKEN,
			   "scid watch blockheight=%u txindex=%u outnum=%u: outnum out of range (tx has %zu outputs)",
			   blockheight, txindex, outnum, tx->wtx->num_outputs);
		bwatch_send_watch_found(cmd, NULL, blockheight, w, txindex, outnum);
		return;
	}

	/* Found it: tell lightningd the scid output is confirmed. */
	bwatch_send_watch_found(cmd, tx, blockheight, w, txindex, outnum);
}

void bwatch_check_scid_watches(struct command *cmd,
			       struct bwatch *bwatch,
			       const struct bitcoin_block *block,
			       u32 blockheight,
			       const struct watch *w)
{
	if (w) {
		if (w->type == WATCH_SCID)
			maybe_fire_scid_watch(cmd, block, blockheight, w);
		return;
	}

	struct scid_watches_iter it;
	struct watch *scid_w;

	for (scid_w = scid_watches_first(bwatch->scid_watches, &it);
	     scid_w;
	     scid_w = scid_watches_next(bwatch->scid_watches, &it)) {
		maybe_fire_scid_watch(cmd, block, blockheight, scid_w);
	}
}

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

	bwatch_check_scid_watches(cmd, bwatch, block, blockheight, w);
}

/* Fire depth notifications for every active blockdepth watch.
 * A watch with start_block > new_height is stale: its confirming block
 * was reorged away, watch_revert has been sent, but the del hasn't
 * arrived yet — skip it until deletion clears it from the table. */
void bwatch_check_blockdepth_watches(struct command *cmd,
				     struct bwatch *bwatch,
				     u32 new_height)
{
	struct blockdepth_watches_iter it;
	struct watch *w;

	/* We only have one per channel or so in practice, so don't optimize */
	for (w = blockdepth_watches_first(bwatch->blockdepth_watches, &it);
	     w;
	     w = blockdepth_watches_next(bwatch->blockdepth_watches, &it)) {
		if (w->start_block > new_height)
			continue; /* stale — awaiting deletion */

		u32 depth = new_height - w->start_block + 1;
		bwatch_send_blockdepth_found(cmd, w, depth, new_height);
	}
}
