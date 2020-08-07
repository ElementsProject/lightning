/* Code for talking to bitcoind.  We use a plugin as the Bitcoin backend.
 * The default one shipped with C-lightning is a plugin which talks to bitcoind
 * by using bitcoin-cli, but the interface we use to gather Bitcoin data is
 * standardized and you can use another plugin as the Bitcoin backend, or
 * even make your own! */
#include "bitcoin/base58.h"
#include "bitcoin/block.h"
#include "bitcoin/feerate.h"
#include "bitcoin/script.h"
#include "bitcoin/shadouble.h"
#include "bitcoind.h"
#include "lightningd.h"
#include "log.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/io/io.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/str/hex/hex.h>
#include <ccan/str/str.h>
#include <ccan/take/take.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/json_helpers.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <common/utils.h>
#include <errno.h>
#include <inttypes.h>
#include <lightningd/chaintopology.h>
#include <lightningd/plugin.h>

/* The names of the requests we can make to our Bitcoin backend. */
static const char *methods[] = {"getchaininfo", "getrawblockbyheight",
                                "sendrawtransaction", "getutxout",
                                "estimatefees"};

static void bitcoin_destructor(struct plugin *p)
{
	if (p->plugins->ld->state == LD_STATE_SHUTDOWN)
		return;

	/* FIXME */
	sleep(3);

	fatal("The Bitcoin backend died.");
}

static void plugin_config_cb(const char *buffer,
			     const jsmntok_t *toks,
			     const jsmntok_t *idtok,
			     struct plugin *plugin)
{
	plugin->plugin_state = INIT_COMPLETE;
	io_break(plugin);
}

static void config_plugin(struct plugin *plugin)
{
	struct jsonrpc_request *req;

	req = jsonrpc_request_start(plugin, "init", plugin->log,
	                            plugin_config_cb, plugin);
	plugin_populate_init_request(plugin, req);
	jsonrpc_request_end(req);
	plugin_request_send(plugin, req);

	tal_add_destructor(plugin, bitcoin_destructor);

	io_loop_with_timers(plugin->plugins->ld);
}

static void wait_plugin(struct bitcoind *bitcoind, const char *method,
			struct plugin *p)
{
	/* We need our Bitcoin backend to be initialized, but the plugins have
	 * not yet been started at this point.
	 * So send `init` to each plugin which registered for a Bitcoin method
	 * and wait for its response, which we take as an ACK that it is
	 * operational (i.e. bcli will wait for `bitcoind` to be warmed up
	 * before responding to `init`).
	 * Note that lightningd/plugin will not send `init` to an already
	 * configured plugin. */
	if (p->plugin_state == NEEDS_INIT)
		config_plugin(p);

	strmap_add(&bitcoind->pluginsmap, method, p);
}

void bitcoind_check_commands(struct bitcoind *bitcoind)
{
	size_t i;
	struct plugin *p;

	for (i = 0; i < ARRAY_SIZE(methods); i++) {
		p = find_plugin_for_command(bitcoind->ld, methods[i]);
		if (p == NULL) {
			/* For testing .. */
			log_debug(bitcoind->ld->log, "Missing a Bitcoin plugin"
						     " command");
			fatal("Could not access the plugin for %s, is a "
			      "Bitcoin plugin (by default plugins/bcli) "
			      "registered ?", methods[i]);
		}
		wait_plugin(bitcoind, methods[i], p);
	}
}

/* Our Bitcoin backend plugin gave us a bad response. We can't recover. */
static void bitcoin_plugin_error(struct bitcoind *bitcoind, const char *buf,
				 const jsmntok_t *toks, const char *method,
				 const char *fmt, ...)
{
	va_list ap;
	char *reason;
	struct plugin *p;

	va_start(ap, fmt);
	reason = tal_vfmt(NULL, fmt, ap);
	va_end(ap);

	p = strmap_get(&bitcoind->pluginsmap, method);
	fatal("%s error: bad response to %s (%s), response was %.*s",
	      p->cmd, method, reason,
	      toks->end - toks->start, buf + toks->start);
}

/* Send a request to the Bitcoin plugin which registered that method,
 * if it's still alive. */
static void bitcoin_plugin_send(struct bitcoind *bitcoind,
				struct jsonrpc_request *req)
{
	struct plugin *plugin = strmap_get(&bitcoind->pluginsmap, req->method);
	if (!plugin)
		fatal("Bitcoin backend plugin for %s died.", req->method);

	plugin_request_send(plugin, req);
}

/* `estimatefees`
 *
 * Gather feerate from our Bitcoin backend. Will set the feerate to `null`
 * if estimation failed.
 *
 *   - `opening` is used for funding and also misc transactions
 *   - `mutual_close` is used for the mutual close transaction
 *   - `unilateral_close` is used for unilateral close (commitment transactions)
 *   - `delayed_to_us` is used for resolving our output from our unilateral close
 *   - `htlc_resolution` is used for resolving onchain HTLCs
 *   - `penalty` is used for resolving revoked transactions
 *   - `min` is the minimum acceptable feerate
 *   - `max` is the maximum acceptable feerate
 *
 * Plugin response:
 * {
 *	"opening": <sat per kVB>,
 *	"mutual_close": <sat per kVB>,
 *	"unilateral_close": <sat per kVB>,
 *	"delayed_to_us": <sat per kVB>,
 *	"htlc_resolution": <sat per kVB>,
 *	"penalty": <sat per kVB>,
 *	"min_acceptable": <sat per kVB>,
 *	"max_acceptable": <sat per kVB>,
 * }
 */

struct estimatefee_call {
	struct bitcoind *bitcoind;
	void (*cb)(struct bitcoind *bitcoind, const u32 satoshi_per_kw[],
		   void *);
	void *arg;
};

static void estimatefees_callback(const char *buf, const jsmntok_t *toks,
				  const jsmntok_t *idtok,
				  struct estimatefee_call *call)
{
	const jsmntok_t *resulttok, *feeratetok;
	u32 *feerates = tal_arr(call, u32, NUM_FEERATES);

	resulttok = json_get_member(buf, toks, "result");
	if (!resulttok)
		bitcoin_plugin_error(call->bitcoind, buf, toks,
				     "estimatefees",
				     "bad 'result' field");

	for (enum feerate f = 0; f < NUM_FEERATES; f++) {
		feeratetok = json_get_member(buf, resulttok, feerate_name(f));
		if (!feeratetok)
			bitcoin_plugin_error(call->bitcoind, buf, toks,
					     "estimatefees",
					     "missing '%s' field", feerate_name(f));

		/* FIXME: We could trawl recent blocks for median fee... */
		if (!json_to_u32(buf, feeratetok, &feerates[f])) {
			log_unusual(call->bitcoind->log,
				    "Unable to estimate %s fees",
				    feerate_name(f));

#if DEVELOPER
			/* This is needed to test for failed feerate estimates
			* in DEVELOPER mode */
			feerates[f] = 0;
#else
			/* If we are in testnet mode we want to allow payments
			* with the minimal fee even if the estimate didn't
			* work out. This is less disruptive than erring out
			* all the time. */
			if (chainparams->testnet)
				feerates[f] = FEERATE_FLOOR;
			else
				feerates[f] = 0;
#endif
		} else
			/* Rate in satoshi per kw. */
			feerates[f] = feerate_from_style(feerates[f],
							 FEERATE_PER_KBYTE);
	}

	call->cb(call->bitcoind, feerates, call->arg);
	tal_free(call);
}

void bitcoind_estimate_fees_(struct bitcoind *bitcoind,
			     size_t num_estimates,
			     void (*cb)(struct bitcoind *bitcoind,
					const u32 satoshi_per_kw[], void *),
			     void *arg)
{
	struct jsonrpc_request *req;
	struct estimatefee_call *call = tal(bitcoind, struct estimatefee_call);

	call->bitcoind = bitcoind;
	call->cb = cb;
	call->arg = arg;

	req = jsonrpc_request_start(bitcoind, "estimatefees", bitcoind->log,
				    estimatefees_callback, call);
	jsonrpc_request_end(req);
	plugin_request_send(strmap_get(&bitcoind->pluginsmap,
				       "estimatefees"), req);
}

/* `sendrawtransaction`
 *
 * Send a transaction to the Bitcoin backend plugin. If the broadcast was
 * not successful on its end, the plugin will populate the `errmsg` with
 * the reason.
 *
 * Plugin response:
 * {
 *	"success": <true|false>,
 *	"errmsg": "<not empty if !success>"
 * }
 */

struct sendrawtx_call {
	struct bitcoind *bitcoind;
	void (*cb)(struct bitcoind *bitcoind,
		   bool success,
		   const char *err_msg,
		   void *);
	void *cb_arg;
};

static void sendrawtx_callback(const char *buf, const jsmntok_t *toks,
			       const jsmntok_t *idtok,
			       struct sendrawtx_call *call)
{
	const jsmntok_t *resulttok, *successtok, *errtok;
	bool success = false;

	resulttok = json_get_member(buf, toks, "result");
	if (!resulttok)
		bitcoin_plugin_error(call->bitcoind, buf, toks,
				     "sendrawtransaction",
				     "bad 'result' field");

	successtok = json_get_member(buf, resulttok, "success");
	if (!successtok || !json_to_bool(buf, successtok, &success))
		bitcoin_plugin_error(call->bitcoind, buf, toks,
				     "sendrawtransaction",
				     "bad 'success' field");

	errtok = json_get_member(buf, resulttok, "errmsg");
	if (!success && !errtok)
		bitcoin_plugin_error(call->bitcoind, buf, toks,
				     "sendrawtransaction",
				     "bad 'errmsg' field");

	db_begin_transaction(call->bitcoind->ld->wallet->db);
	call->cb(call->bitcoind, success,
		 errtok ? json_strdup(tmpctx, buf, errtok) : NULL,
		 call->cb_arg);
	db_commit_transaction(call->bitcoind->ld->wallet->db);

	tal_free(call);
}

void bitcoind_sendrawtx_(struct bitcoind *bitcoind,
			 const char *hextx,
			 void (*cb)(struct bitcoind *bitcoind,
				    bool success, const char *err_msg, void *),
			 void *cb_arg)
{
	struct jsonrpc_request *req;
	struct sendrawtx_call *call = tal(bitcoind, struct sendrawtx_call);

	call->bitcoind = bitcoind;
	call->cb = cb;
	call->cb_arg = cb_arg;
	log_debug(bitcoind->log, "sendrawtransaction: %s", hextx);

	req = jsonrpc_request_start(bitcoind, "sendrawtransaction",
				    bitcoind->log, sendrawtx_callback,
				    call);
	json_add_string(req->stream, "tx", hextx);
	jsonrpc_request_end(req);
	bitcoin_plugin_send(bitcoind, req);
}

/* `getrawblockbyheight`
 *
 * If no block were found at that height, will set each field to `null`.
 * Plugin response:
 * {
 *	"blockhash": "<blkid>",
 *	"block": "rawblock"
 * }
 */

struct getrawblockbyheight_call {
	struct bitcoind *bitcoind;
	void (*cb)(struct bitcoind *bitcoind,
		   struct bitcoin_blkid *blkid,
		   struct bitcoin_block *block,
		   void *);
	void *cb_arg;
};

static void
getrawblockbyheight_callback(const char *buf, const jsmntok_t *toks,
			     const jsmntok_t *idtok,
			     struct getrawblockbyheight_call *call)
{
	const jsmntok_t *resulttok, *blockhashtok, *blocktok;
	const char *block_str, *blockhash_str;
	struct bitcoin_blkid blkid;
	struct bitcoin_block *blk;

	resulttok = json_get_member(buf, toks, "result");
	if (!resulttok)
		bitcoin_plugin_error(call->bitcoind, buf, toks,
				     "getrawblockbyheight",
				     "bad 'result' field");

	blockhashtok = json_get_member(buf, resulttok, "blockhash");
	if (!blockhashtok)
		bitcoin_plugin_error(call->bitcoind, buf, toks,
				     "getrawblockbyheight",
				     "bad 'blockhash' field");
	/* If block hash is `null`, this means not found! Call the callback
	 * with NULL values. */
	if (json_tok_is_null(buf, blockhashtok)) {
		db_begin_transaction(call->bitcoind->ld->wallet->db);
		call->cb(call->bitcoind, NULL, NULL, call->cb_arg);
		db_commit_transaction(call->bitcoind->ld->wallet->db);
		goto clean;
	}
	blockhash_str = json_strdup(tmpctx, buf, blockhashtok);
	if (!bitcoin_blkid_from_hex(blockhash_str, strlen(blockhash_str), &blkid))
		bitcoin_plugin_error(call->bitcoind, buf, toks,
				     "getrawblockbyheight",
				     "bad block hash");

	blocktok = json_get_member(buf, resulttok, "block");
	if (!blocktok)
		bitcoin_plugin_error(call->bitcoind, buf, toks,
				     "getrawblockbyheight",
				     "bad 'block' field");
	block_str = json_strdup(tmpctx, buf, blocktok);
	blk = bitcoin_block_from_hex(tmpctx, chainparams, block_str,
				     strlen(block_str));
	if (!blk)
		bitcoin_plugin_error(call->bitcoind, buf, toks,
				     "getrawblockbyheight",
				     "bad block");

	db_begin_transaction(call->bitcoind->ld->wallet->db);
	call->cb(call->bitcoind, &blkid, blk, call->cb_arg);
	db_commit_transaction(call->bitcoind->ld->wallet->db);

clean:
	tal_free(call);
}

void bitcoind_getrawblockbyheight_(struct bitcoind *bitcoind,
				   u32 height,
				   void (*cb)(struct bitcoind *bitcoind,
					      struct bitcoin_blkid *blkid,
					      struct bitcoin_block *blk,
					      void *arg),
				   void *cb_arg)
{
	struct jsonrpc_request *req;
	struct getrawblockbyheight_call *call = tal(NULL,
						    struct getrawblockbyheight_call);

	call->bitcoind = bitcoind;
	call->cb = cb;
	call->cb_arg = cb_arg;

	req = jsonrpc_request_start(bitcoind, "getrawblockbyheight",
				    bitcoind->log, getrawblockbyheight_callback,
				    /* Freed in cb. */
				    notleak(call));
	json_add_num(req->stream, "height", height);
	jsonrpc_request_end(req);
	bitcoin_plugin_send(bitcoind, req);
}

/* `getchaininfo`
 *
 * Called at startup to check the network we are operating on, and to check
 * if the Bitcoin backend is synced to the network tip. This also allows to
 * get the current block count.
 * {
 *	"chain": "<bip70_chainid>",
 *	"headercount": <number of fetched headers>,
 *	"blockcount": <number of fetched block>,
 *	"ibd": <synced?>
 * }
 */

struct getchaininfo_call {
	struct bitcoind *bitcoind;
	/* Should we log verbosely? */
	bool first_call;
	void (*cb)(struct bitcoind *bitcoind,
		   const char *chain,
		   u32 headercount,
		   u32 blockcount,
		   const bool ibd,
		   const bool first_call,
		   void *);
	void *cb_arg;
};

static void getchaininfo_callback(const char *buf, const jsmntok_t *toks,
				  const jsmntok_t *idtok,
				  struct getchaininfo_call *call)
{
	const jsmntok_t *resulttok, *chaintok, *headerstok, *blktok, *ibdtok;
	u32 headers = 0;
	u32 blocks = 0;
	bool ibd = false;

	resulttok = json_get_member(buf, toks, "result");
	if (!resulttok)
		bitcoin_plugin_error(call->bitcoind, buf, toks, "getchaininfo",
				     "bad 'result' field");

	chaintok = json_get_member(buf, resulttok, "chain");
	if (!chaintok)
		bitcoin_plugin_error(call->bitcoind, buf, toks, "getchaininfo",
				     "bad 'chain' field");

	headerstok = json_get_member(buf, resulttok, "headercount");
	if (!headerstok || !json_to_number(buf, headerstok, &headers))
		bitcoin_plugin_error(call->bitcoind, buf, toks, "getchaininfo",
				     "bad 'headercount' field");

	blktok = json_get_member(buf, resulttok, "blockcount");
	if (!blktok || !json_to_number(buf, blktok, &blocks))
		bitcoin_plugin_error(call->bitcoind, buf, toks, "getchaininfo",
				     "bad 'blockcount' field");

	ibdtok = json_get_member(buf, resulttok, "ibd");
	if (!ibdtok || !json_to_bool(buf, ibdtok, &ibd))
		bitcoin_plugin_error(call->bitcoind, buf, toks, "getchaininfo",
				     "bad 'ibd' field");

	db_begin_transaction(call->bitcoind->ld->wallet->db);
	call->cb(call->bitcoind, json_strdup(tmpctx, buf, chaintok), headers,
		 blocks, ibd, call->first_call, call->cb_arg);
	db_commit_transaction(call->bitcoind->ld->wallet->db);

	tal_free(call);
}

void bitcoind_getchaininfo_(struct bitcoind *bitcoind,
			    const bool first_call,
			    void (*cb)(struct bitcoind *bitcoind,
				       const char *chain,
				       u32 headercount,
				       u32 blockcount,
				       const bool ibd,
				       const bool first_call,
				       void *),
			    void *cb_arg)
{
	struct jsonrpc_request *req;
	struct getchaininfo_call *call = tal(bitcoind, struct getchaininfo_call);

	call->bitcoind = bitcoind;
	call->cb = cb;
	call->cb_arg = cb_arg;
	call->first_call = first_call;

	req = jsonrpc_request_start(bitcoind, "getchaininfo", bitcoind->log,
				    getchaininfo_callback, call);
	jsonrpc_request_end(req);
	bitcoin_plugin_send(bitcoind, req);
}

/* `getutxout`
 *
 * Get informations about an UTXO. If the TXO is spent, the plugin will set
 * all fields to `null`.
 * {
 *	"amount": <The output's amount in *sats*>,
 *	"script": "The output's scriptPubKey",
 * }
 */

struct getutxout_call {
	struct bitcoind *bitcoind;
	unsigned int blocknum, txnum, outnum;

	/* The real callback */
	void (*cb)(struct bitcoind *bitcoind,
		   const struct bitcoin_tx_output *txout, void *arg);
	/* The real callback arg */
	void *cb_arg;
};

static void getutxout_callback(const char *buf, const jsmntok_t *toks,
			      const jsmntok_t *idtok,
			      struct getutxout_call *call)
{
	const jsmntok_t *resulttok, *amounttok, *scripttok;
	struct bitcoin_tx_output txout;

	resulttok = json_get_member(buf, toks, "result");
	if (!resulttok)
		bitcoin_plugin_error(call->bitcoind, buf, toks, "getutxout",
				     "bad 'result' field");

	scripttok = json_get_member(buf, resulttok, "script");
	if (!scripttok)
		bitcoin_plugin_error(call->bitcoind, buf, toks, "getutxout",
				     "bad 'script' field");
	if (json_tok_is_null(buf, scripttok)) {
		db_begin_transaction(call->bitcoind->ld->wallet->db);
		call->cb(call->bitcoind, NULL, call->cb_arg);
		db_commit_transaction(call->bitcoind->ld->wallet->db);
		goto clean;
	}
	txout.script = json_tok_bin_from_hex(tmpctx, buf, scripttok);

	amounttok = json_get_member(buf, resulttok, "amount");
	if (!amounttok)
		bitcoin_plugin_error(call->bitcoind, buf, toks, "getutxout",
				     "bad 'amount' field");
	if (!json_to_sat(buf, amounttok, &txout.amount))
		bitcoin_plugin_error(call->bitcoind, buf, toks, "getutxout",
				     "bad sats amount");

	db_begin_transaction(call->bitcoind->ld->wallet->db);
	call->cb(call->bitcoind, &txout, call->cb_arg);
	db_commit_transaction(call->bitcoind->ld->wallet->db);

clean:
	tal_free(call);
}

void bitcoind_getutxout_(struct bitcoind *bitcoind,
			 const struct bitcoin_txid *txid, const u32 outnum,
			 void (*cb)(struct bitcoind *bitcoind,
				    const struct bitcoin_tx_output *txout,
				    void *arg),
			 void *cb_arg)
{
	struct jsonrpc_request *req;
	struct getutxout_call *call = tal(bitcoind, struct getutxout_call);

	call->bitcoind = bitcoind;
	call->cb = cb;
	call->cb_arg = cb_arg;

	req = jsonrpc_request_start(bitcoind, "getutxout", bitcoind->log,
				    getutxout_callback, call);
	json_add_txid(req->stream, "txid", txid);
	json_add_num(req->stream, "vout", outnum);
	jsonrpc_request_end(req);
	bitcoin_plugin_send(bitcoind, req);
}

/* Context for the getfilteredblock call. Wraps the actual arguments while we
 * process the various steps. */
struct filteredblock_call {
	struct list_node list;
	void (*cb)(struct bitcoind *bitcoind, const struct filteredblock *fb,
		   void *arg);
	void *arg;

	struct filteredblock *result;
	struct filteredblock_outpoint **outpoints;
	size_t current_outpoint;
	struct timeabs start_time;
	u32 height;
};

/* Declaration for recursion in process_getfilteredblock_step1 */
static void
process_getfiltered_block_final(struct bitcoind *bitcoind,
				const struct filteredblock_call *call);

static void
process_getfilteredblock_step2(struct bitcoind *bitcoind,
			       const struct bitcoin_tx_output *output,
			       void *arg)
{
	struct filteredblock_call *call = (struct filteredblock_call *)arg;
	struct filteredblock_outpoint *o = call->outpoints[call->current_outpoint];

	/* If this output is unspent, add it to the filteredblock result. */
	if (output)
		tal_arr_expand(&call->result->outpoints, tal_steal(call->result, o));

	call->current_outpoint++;
	if (call->current_outpoint < tal_count(call->outpoints)) {
		o = call->outpoints[call->current_outpoint];
		bitcoind_getutxout(bitcoind, &o->txid, o->outnum,
				  process_getfilteredblock_step2, call);
	} else {
		/* If there were no more outpoints to check, we call the callback. */
		process_getfiltered_block_final(bitcoind, call);
	}
}

static void process_getfilteredblock_step1(struct bitcoind *bitcoind,
					   struct bitcoin_blkid *blkid,
					   struct bitcoin_block *block,
					   struct filteredblock_call *call)
{
	struct filteredblock_outpoint *o;
	struct bitcoin_tx *tx;

	/* If we were unable to fetch the block hash (bitcoind doesn't know
	 * about a block at that height), we can short-circuit and just call
	 * the callback. */
	if (!blkid)
		return process_getfiltered_block_final(bitcoind, call);

	/* So we have the first piece of the puzzle, the block hash */
	call->result = tal(call, struct filteredblock);
	call->result->height = call->height;
	call->result->outpoints = tal_arr(call->result, struct filteredblock_outpoint *, 0);
	call->result->id = *blkid;

	/* If the plugin gave us a block id, they MUST send us a block. */
	assert(block != NULL);

	call->result->prev_hash = block->hdr.prev_hash;

	/* Allocate an array containing all the potentially interesting
	 * outpoints. We will later copy the ones we're interested in into the
	 * call->result if they are unspent. */

	call->outpoints = tal_arr(call, struct filteredblock_outpoint *, 0);
	for (size_t i = 0; i < tal_count(block->tx); i++) {
		tx = block->tx[i];
		for (size_t j = 0; j < tx->wtx->num_outputs; j++) {
			const u8 *script = bitcoin_tx_output_get_script(NULL, tx, j);
			struct amount_asset amount = bitcoin_tx_output_get_amount(tx, j);
			if (amount_asset_is_main(&amount) && is_p2wsh(script, NULL)) {
				/* This is an interesting output, remember it. */
				o = tal(call->outpoints, struct filteredblock_outpoint);
				bitcoin_txid(tx, &o->txid);
				o->amount = amount_asset_to_sat(&amount);
				o->txindex = i;
				o->outnum = j;
				o->scriptPubKey = tal_steal(o, script);
				tal_arr_expand(&call->outpoints, o);
			} else {
				tal_free(script);
			}
		}
	}

	if (tal_count(call->outpoints) == 0) {
		/* If there were no outpoints to check, we can short-circuit
		 * and just call the callback. */
		process_getfiltered_block_final(bitcoind, call);
	} else {

		/* Otherwise we start iterating through call->outpoints and
		 * store the one's that are unspent in
		 * call->result->outpoints. */
		o = call->outpoints[call->current_outpoint];
		bitcoind_getutxout(bitcoind, &o->txid, o->outnum,
				  process_getfilteredblock_step2, call);
	}
}

/* Takes a call, dispatches it to all queued requests that match the same
 * height, and then kicks off the next call. */
static void
process_getfiltered_block_final(struct bitcoind *bitcoind,
				const struct filteredblock_call *call)
{
	struct filteredblock_call *c, *next;
	u32 height = call->height;

	if (call->result == NULL)
		goto next;

	/* Need to steal so we don't accidentally free it while iterating through the list below. */
	struct filteredblock *fb = tal_steal(NULL, call->result);
	list_for_each_safe(&bitcoind->pending_getfilteredblock, c, next, list) {
		if (c->height == height) {
			c->cb(bitcoind, fb, c->arg);
			list_del(&c->list);
			tal_free(c);
		}
	}
	tal_free(fb);

next:
	/* Nothing to free here, since `*call` was already deleted during the
	 * iteration above. It was also removed from the list, so no need to
	 * pop here. */
	if (!list_empty(&bitcoind->pending_getfilteredblock)) {
		c = list_top(&bitcoind->pending_getfilteredblock, struct filteredblock_call, list);
		bitcoind_getrawblockbyheight(bitcoind, c->height,
					     process_getfilteredblock_step1, c);
	}
}

void bitcoind_getfilteredblock_(struct bitcoind *bitcoind, u32 height,
				void (*cb)(struct bitcoind *bitcoind,
					   const struct filteredblock *fb,
					   void *arg),
				void *arg)
{
	/* Stash the call context for when we need to call the callback after
	 * all the bitcoind calls we need to perform. */
	struct filteredblock_call *call = tal(bitcoind, struct filteredblock_call);
	/* If this is the first request, we should start processing it. */
	bool start = list_empty(&bitcoind->pending_getfilteredblock);
	call->cb = cb;
	call->arg = arg;
	call->height = height;
	assert(call->cb != NULL);
	call->start_time = time_now();
	call->result = NULL;
	call->current_outpoint = 0;

	list_add_tail(&bitcoind->pending_getfilteredblock, &call->list);
	if (start)
		bitcoind_getrawblockbyheight(bitcoind, height,
					     process_getfilteredblock_step1, call);
}

static void destroy_bitcoind(struct bitcoind *bitcoind)
{
	strmap_clear(&bitcoind->pluginsmap);
}

struct bitcoind *new_bitcoind(const tal_t *ctx,
			      struct lightningd *ld,
			      struct log *log)
{
	struct bitcoind *bitcoind = tal(ctx, struct bitcoind);

	strmap_init(&bitcoind->pluginsmap);
	bitcoind->ld = ld;
	bitcoind->log = log;
	list_head_init(&bitcoind->pending_getfilteredblock);
	tal_add_destructor(bitcoind, destroy_bitcoind);
	bitcoind->synced = false;

	return bitcoind;
}
