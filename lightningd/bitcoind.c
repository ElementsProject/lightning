/* Code for talking to bitcoind.  We use a plugin as the Bitcoin backend.
 * The default one shipped with C-lightning is a plugin which talks to bitcoind
 * by using bitcoin-cli, but the interface we use to gather Bitcoin data is
 * standardized and you can use another plugin as the Bitcoin backend, or
 * even make your own! */
#include "config.h"
#include <bitcoin/base58.h>
#include <bitcoin/block.h>
#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <bitcoin/shadouble.h>
#include <ccan/array_size/array_size.h>
#include <ccan/io/io.h>
#include <ccan/tal/str/str.h>
#include <common/configdir.h>
#include <common/json_parse.h>
#include <common/memleak.h>
#include <common/trace.h>
#include <db/exec.h>
#include <lightningd/bitcoind.h>
#include <lightningd/chaintopology.h>
#include <lightningd/io_loop_with_timers.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/plugin.h>

/* The names of the requests we can make to our Bitcoin backend. */
static const char *methods[] = {"getchaininfo", "getrawblockbyheight",
                                "sendrawtransaction", "getutxout",
                                "estimatefees"};

static void bitcoin_destructor(struct plugin *p)
{
	if (p->plugins->ld->state == LD_STATE_SHUTDOWN)
		return;
	fatal("The Bitcoin backend died.");
}

static void plugin_config_cb(const char *buffer,
			     const jsmntok_t *toks,
			     const jsmntok_t *idtok,
			     struct plugin *plugin)
{
	plugin->plugin_state = INIT_COMPLETE;
	log_debug(plugin->plugins->ld->log, "io_break: %s", __func__);
	io_break(plugin);
}

static void config_plugin(struct plugin *plugin)
{
	struct jsonrpc_request *req;
	void *ret;

	req = jsonrpc_request_start(plugin, "init", NULL,
				    plugin->non_numeric_ids, plugin->log,
	                            NULL, plugin_config_cb, plugin);
	plugin_populate_init_request(plugin, req);
	jsonrpc_request_end(req);
	plugin_request_send(plugin, req);

	tal_add_destructor(plugin, bitcoin_destructor);

	ret = io_loop_with_timers(plugin->plugins->ld);
	log_debug(plugin->plugins->ld->log, "io_loop_with_timers: %s", __func__);
	assert(ret == plugin);
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

	p = strmap_getn(&bitcoind->pluginsmap, method, strcspn(method, "."));
	fatal("%s error: bad response to %s (%s), response was %.*s",
	      p ? p->cmd : "UNKNOWN CALL", method, reason,
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
 * Plugin response (deprecated):
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
 *
 * Plugin response (modern):
 * {
 *	"feerate_floor": <sat per kVB>,
 *	"feerates": {
 *		{ "blocks": 2, "feerate": <sat per kVB> },
 *		{ "blocks": 6, "feerate": <sat per kVB> },
 *		{ "blocks": 12, "feerate": <sat per kVB> }
 *		{ "blocks": 100, "feerate": <sat per kVB> }
 *	}
 * }
 *
 * If rates are missing, we linearly interpolate (we don't extrapolate tho!).
 */
struct estimatefee_call {
	struct bitcoind *bitcoind;
	void (*cb)(struct lightningd *ld, u32 feerate_floor,
		   const struct feerate_est *rates, void *);
	void *cb_arg;
};

/* Note: returns estimates in perkb, caller converts! */
static struct feerate_est *parse_feerate_ranges(const tal_t *ctx,
						struct bitcoind *bitcoind,
						const char *buf,
						const jsmntok_t *floortok,
						const jsmntok_t *feerates,
						u32 *floor)
{
	size_t i;
	const jsmntok_t *t;
	struct feerate_est *rates = tal_arr(ctx, struct feerate_est, 0);

	if (!json_to_u32(buf, floortok, floor))
		bitcoin_plugin_error(bitcoind, buf, floortok,
				     "estimatefees.feerate_floor", "Not a u32?");

	json_for_each_arr(i, t, feerates) {
		struct feerate_est rate;
		const char *err;

		err = json_scan(tmpctx, buf, t, "{blocks:%,feerate:%}",
				JSON_SCAN(json_to_u32, &rate.blockcount),
				JSON_SCAN(json_to_u32, &rate.rate));
		if (err)
			bitcoin_plugin_error(bitcoind, buf, t,
					     "estimatefees.feerates", err);

		/* Block count must be in order.  If rates go up somehow, we
		 * reduce to prev. */
		if (tal_count(rates) != 0) {
			const struct feerate_est *prev = &rates[tal_count(rates)-1];
			if (rate.blockcount <= prev->blockcount)
				bitcoin_plugin_error(bitcoind, buf, feerates,
						     "estimatefees.feerates",
						     "Blocks must be ascending"
						     " order: %u <= %u!",
						     rate.blockcount,
						     prev->blockcount);
			if (rate.rate > prev->rate) {
				log_unusual(bitcoind->log,
					    "Feerate for %u blocks (%u) is > rate"
					    " for %u blocks (%u)!",
					    rate.blockcount, rate.rate,
					    prev->blockcount, prev->rate);
				rate.rate = prev->rate;
			}
		}

		tal_arr_expand(&rates, rate);
	}

	if (tal_count(rates) == 0) {
		if (chainparams->testnet)
			log_debug(bitcoind->log, "Unable to estimate any fees");
		else
			log_unusual(bitcoind->log, "Unable to estimate any fees");
	}

	return rates;
}

static struct feerate_est *parse_deprecated_feerates(const tal_t *ctx,
						     struct bitcoind *bitcoind,
						     const char *buf,
						     const jsmntok_t *toks)
{
	struct feerate_est *rates = tal_arr(ctx, struct feerate_est, 0);
	struct oldstyle {
		const char *name;
		size_t blockcount;
		size_t multiplier;
	} oldstyles[] = { { "max_acceptable", 2, 10 },
			  { "unilateral_close", 6, 1 },
			  { "opening", 12, 1 },
			  { "mutual_close", 100, 1 } };

	for (size_t i = 0; i < ARRAY_SIZE(oldstyles); i++) {
		const jsmntok_t *feeratetok;
		struct feerate_est rate;

		feeratetok = json_get_member(buf, toks, oldstyles[i].name);
		if (!feeratetok) {
 			bitcoin_plugin_error(bitcoind, buf, toks,
 					     "estimatefees",
					     "missing '%s' field",
					     oldstyles[i].name);
		}
		if (!json_to_u32(buf, feeratetok, &rate.rate)) {
			if (chainparams->testnet)
				log_debug(bitcoind->log,
					  "Unable to estimate %s fees",
					  oldstyles[i].name);
			else
				log_unusual(bitcoind->log,
					    "Unable to estimate %s fees",
					    oldstyles[i].name);
			continue;
		}

		if (rate.rate == 0)
			continue;

		/* Cancel out the 10x multiplier on max_acceptable */
		rate.rate /= oldstyles[i].multiplier;
		rate.blockcount = oldstyles[i].blockcount;
		tal_arr_expand(&rates, rate);
	}
	return rates;
}

static void estimatefees_callback(const char *buf, const jsmntok_t *toks,
				  const jsmntok_t *idtok,
				  struct estimatefee_call *call)
{
	const jsmntok_t *resulttok, *floortok;
	struct feerate_est *feerates;
	u32 floor;

	resulttok = json_get_member(buf, toks, "result");
	if (!resulttok)
		bitcoin_plugin_error(call->bitcoind, buf, toks,
				     "estimatefees",
				     "bad 'result' field");

	/* Modern style has floor. */
	floortok = json_get_member(buf, resulttok, "feerate_floor");
	if (floortok) {
		feerates = parse_feerate_ranges(call, call->bitcoind,
						buf, floortok,
						json_get_member(buf, resulttok,
								"feerates"),
						&floor);
	} else {
		if (!lightningd_deprecated_in_ok(call->bitcoind->ld,
						 call->bitcoind->ld->log,
						 call->bitcoind->ld->deprecated_ok,
						 "estimatefeesv1", NULL,
						 "v23.05", "v24.05",
						 NULL)) {
			bitcoin_plugin_error(call->bitcoind, buf, resulttok,
					     "estimatefees",
					     "missing feerate_floor field");
		}

		feerates = parse_deprecated_feerates(call, call->bitcoind,
						     buf, resulttok);
		floor = feerate_from_style(FEERATE_FLOOR, FEERATE_PER_KSIPA);
	}

	/* Convert to perkw */
	floor = feerate_from_style(floor, FEERATE_PER_KBYTE);
	if (floor < FEERATE_FLOOR)
		floor = FEERATE_FLOOR;

	/* FIXME: We could let this go below the dynamic floor, but we'd
	 * need to know if the floor is because of their node's policy
	 * (minrelaytxfee) or mempool conditions (mempoolminfee). */
	for (size_t i = 0; i < tal_count(feerates); i++) {
		feerates[i].rate = feerate_from_style(feerates[i].rate,
						      FEERATE_PER_KBYTE);
		if (feerates[i].rate < floor)
			feerates[i].rate = floor;
	}

	call->cb(call->bitcoind->ld, floor, feerates, call->cb_arg);
	tal_free(call);
}

void bitcoind_estimate_fees_(const tal_t *ctx,
			     struct bitcoind *bitcoind,
			     void (*cb)(struct lightningd *ld,
					u32 feerate_floor,
					const struct feerate_est *feerates,
					void *arg),
			     void *cb_arg)
{
	struct jsonrpc_request *req;
	struct estimatefee_call *call = tal(ctx, struct estimatefee_call);

	call->bitcoind = bitcoind;
	call->cb = cb;
	call->cb_arg = cb_arg;

	req = jsonrpc_request_start(call, "estimatefees", NULL, true,
				    bitcoind->log,
				    NULL, estimatefees_callback, call);
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
	const char *err;
	const char *errmsg = NULL;
	bool success = false;

	err = json_scan(tmpctx, buf, toks, "{result:{success:%}}",
			JSON_SCAN(json_to_bool, &success));
	if (err) {
		bitcoin_plugin_error(call->bitcoind, buf, toks,
				     "sendrawtransaction",
				     "bad 'result' field: %s", err);
	} else if (!success) {
		err = json_scan(tmpctx, buf, toks, "{result:{errmsg:%}}",
				JSON_SCAN_TAL(tmpctx, json_strdup, &errmsg));
		if (err)
			bitcoin_plugin_error(call->bitcoind, buf, toks,
					     "sendrawtransaction",
					     "bad 'errmsg' field: %s",
					     err);
	}

	/* In case they don't free it, we will. */
	tal_steal(tmpctx, call);
	call->cb(call->bitcoind, success, errmsg, call->cb_arg);
}

void bitcoind_sendrawtx_(const tal_t *ctx,
			 struct bitcoind *bitcoind,
			 const char *id_prefix,
			 const char *hextx,
			 bool allowhighfees,
			 void (*cb)(struct bitcoind *bitcoind,
				    bool success, const char *msg, void *),
			 void *cb_arg)
{
	struct jsonrpc_request *req;
	struct sendrawtx_call *call = tal(ctx, struct sendrawtx_call);

	call->bitcoind = bitcoind;
	call->cb = cb;
	call->cb_arg = cb_arg;
	log_debug(bitcoind->log, "sendrawtransaction: %s", hextx);

	req = jsonrpc_request_start(call, "sendrawtransaction",
				    id_prefix, true,
				    bitcoind->log,
				    NULL, sendrawtx_callback,
				    call);
	json_add_string(req->stream, "tx", hextx);
	json_add_bool(req->stream, "allowhighfees", allowhighfees);
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
	u32 height;
	void (*cb)(struct bitcoind *bitcoind,
		   u32 height,
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
	const char *block_str, *err;
	struct bitcoin_blkid blkid;
	struct bitcoin_block *blk;
	trace_span_resume(call);
	trace_span_end(call);

	/* If block hash is `null`, this means not found! Call the callback
	 * with NULL values. */
	err = json_scan(tmpctx, buf, toks, "{result:{blockhash:null}}");
	if (!err) {
		call->cb(call->bitcoind, call->height, NULL, NULL, call->cb_arg);
		goto clean;
	}

	err = json_scan(tmpctx, buf, toks, "{result:{blockhash:%,block:%}}",
			JSON_SCAN(json_to_sha256, &blkid.shad.sha),
			JSON_SCAN_TAL(tmpctx, json_strdup, &block_str));
	if (err)
		bitcoin_plugin_error(call->bitcoind, buf, toks,
				     "getrawblockbyheight",
				     "bad 'result' field: %s", err);

	blk = bitcoin_block_from_hex(tmpctx, chainparams, block_str,
				     strlen(block_str));
	if (!blk)
		bitcoin_plugin_error(call->bitcoind, buf, toks,
				     "getrawblockbyheight",
				     "bad block");

	call->cb(call->bitcoind, call->height, &blkid, blk, call->cb_arg);

clean:
	tal_free(call);
}

void bitcoind_getrawblockbyheight_(const tal_t *ctx,
				   struct bitcoind *bitcoind,
				   u32 height,
				   void (*cb)(struct bitcoind *bitcoind,
					      u32 blockheight,
					      struct bitcoin_blkid *blkid,
					      struct bitcoin_block *blk,
					      void *arg),
				   void *cb_arg)
{
	struct jsonrpc_request *req;
	struct getrawblockbyheight_call *call = tal(ctx,
						    struct getrawblockbyheight_call);

	call->bitcoind = bitcoind;
	call->cb = cb;
	call->cb_arg = cb_arg;
	call->height = height;

	trace_span_start("plugin/bitcoind", call);
	trace_span_tag(call, "method", "getrawblockbyheight");
	trace_span_suspend(call);
	req = jsonrpc_request_start(call, "getrawblockbyheight", NULL, true,
				    bitcoind->log,
				    NULL,  getrawblockbyheight_callback,
				    call);
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
	void (*cb)(struct bitcoind *bitcoind,
		   const char *chain,
		   u32 headercount,
		   u32 blockcount,
		   const bool ibd,
		   void *);
	void *cb_arg;
};

static void getchaininfo_callback(const char *buf, const jsmntok_t *toks,
				  const jsmntok_t *idtok,
				  struct getchaininfo_call *call)
{
	const char *err, *chain;
	u32 headers, blocks;
	bool ibd;

	err = json_scan(tmpctx, buf, toks,
			"{result:{chain:%,headercount:%,blockcount:%,ibd:%}}",
			JSON_SCAN_TAL(tmpctx, json_strdup, &chain),
			JSON_SCAN(json_to_number, &headers),
			JSON_SCAN(json_to_number, &blocks),
			JSON_SCAN(json_to_bool, &ibd));
	if (err)
		bitcoin_plugin_error(call->bitcoind, buf, toks, "getchaininfo",
				     "bad 'result' field: %s", err);

	call->cb(call->bitcoind, chain, headers, blocks, ibd,
		 call->cb_arg);

	tal_free(call);
}

void bitcoind_getchaininfo_(const tal_t *ctx,
			    struct bitcoind *bitcoind,
			    const u32 height,
			    void (*cb)(struct bitcoind *bitcoind,
				       const char *chain,
				       u32 headercount,
				       u32 blockcount,
				       const bool ibd,
				       void *),
			    void *cb_arg)
{
	struct jsonrpc_request *req;
	struct getchaininfo_call *call = tal(ctx, struct getchaininfo_call);

	call->bitcoind = bitcoind;
	call->cb = cb;
	call->cb_arg = cb_arg;

	req = jsonrpc_request_start(call, "getchaininfo", NULL, true,
				    bitcoind->log,
				    NULL, getchaininfo_callback, call);
	json_add_u32(req->stream, "last_height", height);
	jsonrpc_request_end(req);
	bitcoin_plugin_send(bitcoind, req);
}

/* `getutxout`
 *
 * Get information about an UTXO. If the TXO is spent, the plugin will set
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
	const char *err;
	struct bitcoin_tx_output txout;

	/* Whatever happens, we want to free this. */
	tal_steal(tmpctx, call);

	err = json_scan(tmpctx, buf, toks, "{result:{script:null}}");
	if (!err) {
		call->cb(call->bitcoind, NULL, call->cb_arg);
		return;
	}

	err = json_scan(tmpctx, buf, toks, "{result:{script:%,amount:%}}",
			JSON_SCAN_TAL(tmpctx, json_tok_bin_from_hex,
				      &txout.script),
			JSON_SCAN(json_to_sat, &txout.amount));
	if (err)
		bitcoin_plugin_error(call->bitcoind, buf, toks, "getutxout",
				     "bad 'result' field: %s", err);

	call->cb(call->bitcoind, &txout, call->cb_arg);
}

void bitcoind_getutxout_(const tal_t *ctx,
			 struct bitcoind *bitcoind,
			 const struct bitcoin_outpoint *outpoint,
			 void (*cb)(struct bitcoind *,
				    const struct bitcoin_tx_output *,
				    void *),
			 void *cb_arg)
{
	struct jsonrpc_request *req;
	struct getutxout_call *call = tal(ctx, struct getutxout_call);

	call->bitcoind = bitcoind;
	call->cb = cb;
	call->cb_arg = cb_arg;

	req = jsonrpc_request_start(call, "getutxout", NULL, true,
				    bitcoind->log,
				    NULL, getutxout_callback, call);
	json_add_txid(req->stream, "txid", &outpoint->txid);
	json_add_num(req->stream, "vout", outpoint->n);
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
		bitcoind_getutxout(call, bitcoind, &o->outpoint,
				   process_getfilteredblock_step2, call);
	} else {
		/* If there were no more outpoints to check, we call the callback. */
		process_getfiltered_block_final(bitcoind, call);
	}
}

static void process_getfilteredblock_step1(struct bitcoind *bitcoind,
					   u32 height,
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
			const struct wally_tx_output *output;
			output = &tx->wtx->outputs[j];

			if (!is_p2wsh(output->script, output->script_len, NULL))
				continue;

			struct amount_asset amount = wally_tx_output_get_amount(output);
			if (amount_asset_is_main(&amount)) {
				/* This is an interesting output, remember it. */
				o = tal(call->outpoints, struct filteredblock_outpoint);
				bitcoin_txid(tx, &o->outpoint.txid);
				o->outpoint.n = j;
				o->amount = amount_asset_to_sat(&amount);
				o->txindex = i;
				o->scriptPubKey = tal_dup_arr(o, u8, output->script, output->script_len, 0);
				tal_arr_expand(&call->outpoints, o);
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
		bitcoind_getutxout(call, bitcoind, &o->outpoint,
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
		bitcoind_getrawblockbyheight(bitcoind, bitcoind, c->height,
					     process_getfilteredblock_step1, c);
	}
}

static void destroy_filteredblock_call(struct filteredblock_call *call)
{
	list_del(&call->list);
}

void bitcoind_getfilteredblock_(const tal_t *ctx,
				struct bitcoind *bitcoind, u32 height,
				void (*cb)(struct bitcoind *bitcoind,
					   const struct filteredblock *fb,
					   void *arg),
				void *arg)
{
	/* Stash the call context for when we need to call the callback after
	 * all the bitcoind calls we need to perform. */
	struct filteredblock_call *call = tal(ctx, struct filteredblock_call);
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
	tal_add_destructor(call, destroy_filteredblock_call);
	if (start)
		bitcoind_getrawblockbyheight(call, bitcoind, height,
					     process_getfilteredblock_step1, call);
}

static void destroy_bitcoind(struct bitcoind *bitcoind)
{
	strmap_clear(&bitcoind->pluginsmap);
}

struct bitcoind *new_bitcoind(const tal_t *ctx,
			      struct lightningd *ld,
			      struct logger *log)
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
