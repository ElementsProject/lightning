/* Code for talking to bitcoind.  We use bitcoin-cli. */
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

/* Bitcoind's web server has a default of 4 threads, with queue depth 16.
 * It will *fail* rather than queue beyond that, so we must not stress it!
 *
 * This is how many request for each priority level we have.
 */
#define BITCOIND_MAX_PARALLEL 4

/* The names of the request we can make to our Bitcoin backend. */
static const char *methods[] = {"getchaininfo", "getrawblockbyheight",
                                "sendrawtransaction", "getutxout",
                                "getfeerate"};

static void plugin_config_cb(const char *buffer,
			     const jsmntok_t *toks,
			     const jsmntok_t *idtok,
			     struct plugin *plugin)
{
	plugin->plugin_state = CONFIGURED;
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
	if (p->plugin_state != CONFIGURED)
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
			fatal("Could not access the plugin for %s, is a "
			      "Bitcoin plugin (by default plugins/bcli) "
			      "registered ?", methods[i]);
		}
		wait_plugin(bitcoind, methods[i], p);
	}
}

/* Add the n'th arg to *args, incrementing n and keeping args of size n+1 */
static void add_arg(const char ***args, const char *arg)
{
	tal_arr_expand(args, arg);
}

static const char **gather_args(const struct bitcoind *bitcoind,
				const tal_t *ctx, const char *cmd, va_list ap)
{
	const char **args = tal_arr(ctx, const char *, 1);
	const char *arg;

	args[0] = bitcoind->cli ? bitcoind->cli : chainparams->cli;
	if (chainparams->cli_args)
		add_arg(&args, chainparams->cli_args);

	if (bitcoind->datadir)
		add_arg(&args, tal_fmt(args, "-datadir=%s", bitcoind->datadir));


	if (bitcoind->rpcconnect)
		add_arg(&args,
			tal_fmt(args, "-rpcconnect=%s", bitcoind->rpcconnect));

	if (bitcoind->rpcport)
		add_arg(&args,
			tal_fmt(args, "-rpcport=%s", bitcoind->rpcport));

	if (bitcoind->rpcuser)
		add_arg(&args, tal_fmt(args, "-rpcuser=%s", bitcoind->rpcuser));

	if (bitcoind->rpcpass)
		add_arg(&args,
			tal_fmt(args, "-rpcpassword=%s", bitcoind->rpcpass));

	add_arg(&args, cmd);

	while ((arg = va_arg(ap, const char *)) != NULL)
		add_arg(&args, tal_strdup(args, arg));

	add_arg(&args, NULL);
	return args;
}

struct bitcoin_cli {
	struct list_node list;
	struct bitcoind *bitcoind;
	int fd;
	int *exitstatus;
	pid_t pid;
	const char **args;
	struct timeabs start;
	enum bitcoind_prio prio;
	char *output;
	size_t output_bytes;
	size_t new_output;
	bool (*process)(struct bitcoin_cli *);
	void *cb;
	void *cb_arg;
	struct bitcoin_cli **stopper;
};

static struct io_plan *read_more(struct io_conn *conn, struct bitcoin_cli *bcli)
{
	bcli->output_bytes += bcli->new_output;
	if (bcli->output_bytes == tal_count(bcli->output))
		tal_resize(&bcli->output, bcli->output_bytes * 2);
	return io_read_partial(conn, bcli->output + bcli->output_bytes,
			       tal_count(bcli->output) - bcli->output_bytes,
			       &bcli->new_output, read_more, bcli);
}

static struct io_plan *output_init(struct io_conn *conn, struct bitcoin_cli *bcli)
{
	bcli->output_bytes = bcli->new_output = 0;
	bcli->output = tal_arr(bcli, char, 100);
	return read_more(conn, bcli);
}

static void next_bcli(struct bitcoind *bitcoind, enum bitcoind_prio prio);

/* For printing: simple string of args (no secrets!) */
static char *args_string(const tal_t *ctx, const char **args)
{
	size_t i;
	char *ret = tal_strdup(ctx, args[0]);

	for (i = 1; args[i]; i++) {
            ret = tal_strcat(ctx, take(ret), " ");
            if (strstarts(args[i], "-rpcpassword")) {
                    ret = tal_strcat(ctx, take(ret), "-rpcpassword=...");
            } else if (strstarts(args[i], "-rpcuser")) {
                    ret = tal_strcat(ctx, take(ret), "-rpcuser=...");
            } else {
                ret = tal_strcat(ctx, take(ret), args[i]);
            }
	}
	return ret;
}

static char *bcli_args(const tal_t *ctx, struct bitcoin_cli *bcli)
{
    return args_string(ctx, bcli->args);
}

static void retry_bcli(struct bitcoin_cli *bcli)
{
	list_add_tail(&bcli->bitcoind->pending[bcli->prio], &bcli->list);
	next_bcli(bcli->bitcoind, bcli->prio);
}

/* We allow 60 seconds of spurious errors, eg. reorg. */
static void bcli_failure(struct bitcoind *bitcoind,
			 struct bitcoin_cli *bcli,
			 int exitstatus)
{
	struct timerel t;

	if (!bitcoind->error_count)
		bitcoind->first_error_time = time_mono();

	t = timemono_between(time_mono(), bitcoind->first_error_time);
	if (time_greater(t, time_from_sec(bitcoind->retry_timeout)))
		fatal("%s exited %u (after %u other errors) '%.*s'; "
		      "we have been retrying command for "
		      "--bitcoin-retry-timeout=%"PRIu64" seconds; "
		      "bitcoind setup or our --bitcoin-* configs broken?",
		      bcli_args(tmpctx, bcli),
		      exitstatus,
		      bitcoind->error_count,
		      (int)bcli->output_bytes,
		      bcli->output,
		      bitcoind->retry_timeout);

	log_unusual(bitcoind->log,
		    "%s exited with status %u",
		    bcli_args(tmpctx, bcli), exitstatus);

	bitcoind->error_count++;

	/* Retry in 1 second (not a leak!) */
	notleak(new_reltimer(bitcoind->ld->timers, notleak(bcli),
			     time_from_sec(1),
			     retry_bcli, bcli));
}

static void bcli_finished(struct io_conn *conn UNUSED, struct bitcoin_cli *bcli)
{
	int ret, status;
	struct bitcoind *bitcoind = bcli->bitcoind;
	enum bitcoind_prio prio = bcli->prio;
	bool ok;
	u64 msec = time_to_msec(time_between(time_now(), bcli->start));

	/* If it took over 10 seconds, that's rather strange. */
	if (msec > 10000)
		log_unusual(bitcoind->log,
			    "bitcoin-cli: finished %s (%"PRIu64" ms)",
			    bcli_args(tmpctx, bcli), msec);

	assert(bitcoind->num_requests[prio] > 0);

	/* FIXME: If we waited for SIGCHILD, this could never hang! */
	while ((ret = waitpid(bcli->pid, &status, 0)) < 0 && errno == EINTR);
	if (ret != bcli->pid)
		fatal("%s %s", bcli_args(tmpctx, bcli),
		      ret == 0 ? "not exited?" : strerror(errno));

	if (!WIFEXITED(status))
		fatal("%s died with signal %i",
		      bcli_args(tmpctx, bcli),
		      WTERMSIG(status));

	if (!bcli->exitstatus) {
		if (WEXITSTATUS(status) != 0) {
			bcli_failure(bitcoind, bcli, WEXITSTATUS(status));
			bitcoind->num_requests[prio]--;
			goto done;
		}
	} else
		*bcli->exitstatus = WEXITSTATUS(status);

	if (WEXITSTATUS(status) == 0)
		bitcoind->error_count = 0;

	bitcoind->num_requests[bcli->prio]--;

	/* Don't continue if were only here because we were freed for shutdown */
	if (bitcoind->shutdown)
		return;

	db_begin_transaction(bitcoind->ld->wallet->db);
	ok = bcli->process(bcli);
	db_commit_transaction(bitcoind->ld->wallet->db);

	if (!ok)
		bcli_failure(bitcoind, bcli, WEXITSTATUS(status));
	else
		tal_free(bcli);

done:
	next_bcli(bitcoind, prio);
}

static void next_bcli(struct bitcoind *bitcoind, enum bitcoind_prio prio)
{
	struct bitcoin_cli *bcli;
	struct io_conn *conn;

	if (bitcoind->num_requests[prio] >= BITCOIND_MAX_PARALLEL)
		return;

	bcli = list_pop(&bitcoind->pending[prio], struct bitcoin_cli, list);
	if (!bcli)
		return;

	bcli->pid = pipecmdarr(NULL, &bcli->fd, &bcli->fd,
			       cast_const2(char **, bcli->args));
	if (bcli->pid < 0)
		fatal("%s exec failed: %s", bcli->args[0], strerror(errno));

	bcli->start = time_now();

	bitcoind->num_requests[prio]++;

	/* This lifetime is attached to bitcoind command fd */
	conn = notleak(io_new_conn(bitcoind, bcli->fd, output_init, bcli));
	io_set_finish(conn, bcli_finished, bcli);
}

static bool process_donothing(struct bitcoin_cli *bcli UNUSED)
{
	return true;
}

/* If stopper gets freed first, set process() to a noop. */
static void stop_process_bcli(struct bitcoin_cli **stopper)
{
	(*stopper)->process = process_donothing;
	(*stopper)->stopper = NULL;
}

/* It command finishes first, free stopper. */
static void remove_stopper(struct bitcoin_cli *bcli)
{
	/* Calls stop_process_bcli, but we don't care. */
	tal_free(bcli->stopper);
}

/* If ctx is non-NULL, and is freed before we return, we don't call process().
 * process returns false() if it's a spurious error, and we should retry. */
static void
start_bitcoin_cli(struct bitcoind *bitcoind,
		  const tal_t *ctx,
		  bool (*process)(struct bitcoin_cli *),
		  bool nonzero_exit_ok,
		  enum bitcoind_prio prio,
		  void *cb, void *cb_arg,
		  char *cmd, ...)
{
	va_list ap;
	struct bitcoin_cli *bcli = tal(bitcoind, struct bitcoin_cli);

	bcli->bitcoind = bitcoind;
	bcli->process = process;
	bcli->prio = prio;
	bcli->cb = cb;
	bcli->cb_arg = cb_arg;
	if (ctx) {
		/* Create child whose destructor will stop us calling */
		bcli->stopper = tal(ctx, struct bitcoin_cli *);
		*bcli->stopper = bcli;
		tal_add_destructor(bcli->stopper, stop_process_bcli);
		tal_add_destructor(bcli, remove_stopper);
	} else
		bcli->stopper = NULL;

	if (nonzero_exit_ok)
		bcli->exitstatus = tal(bcli, int);
	else
		bcli->exitstatus = NULL;
	va_start(ap, cmd);
	bcli->args = gather_args(bitcoind, bcli, cmd, ap);
	va_end(ap);

	list_add_tail(&bitcoind->pending[bcli->prio], &bcli->list);
	next_bcli(bitcoind, bcli->prio);
}

static bool extract_feerate(struct bitcoin_cli *bcli,
			    const char *output, size_t output_bytes,
			    u64 *feerate)
{
	const jsmntok_t *tokens, *feeratetok;
	bool valid;

	tokens = json_parse_input(output, output, output_bytes, &valid);
	if (!tokens)
		fatal("%s: %s response",
		      bcli_args(tmpctx, bcli),
		      valid ? "partial" : "invalid");

	if (tokens[0].type != JSMN_OBJECT) {
		log_unusual(bcli->bitcoind->log,
			    "%s: gave non-object (%.*s)?",
			    bcli_args(tmpctx, bcli),
			    (int)output_bytes, output);
		return false;
	}

	feeratetok = json_get_member(output, tokens, "feerate");
	if (!feeratetok)
		return false;

	return json_to_bitcoin_amount(output, feeratetok, feerate);
}

struct estimatefee {
	size_t i;
	const u32 *blocks;
	const char **estmode;

	void (*cb)(struct bitcoind *bitcoind, const u32 satoshi_per_kw[],
		   void *);
	void *arg;
	u32 *satoshi_per_kw;
};

static void do_one_estimatefee(struct bitcoind *bitcoind,
			       struct estimatefee *efee);

static bool process_estimatefee(struct bitcoin_cli *bcli)
{
	u64 feerate;
	struct estimatefee *efee = bcli->cb_arg;

	/* FIXME: We could trawl recent blocks for median fee... */
	if (!extract_feerate(bcli, bcli->output, bcli->output_bytes, &feerate)) {
		log_unusual(bcli->bitcoind->log, "Unable to estimate %s/%u fee",
			    efee->estmode[efee->i], efee->blocks[efee->i]);

#if DEVELOPER
		/* This is needed to test for failed feerate estimates
		 * in DEVELOPER mode */
		efee->satoshi_per_kw[efee->i] = 0;
#else
		/* If we are in testnet mode we want to allow payments
		 * with the minimal fee even if the estimate didn't
		 * work out. This is less disruptive than erring out
		 * all the time. */
		if (chainparams->testnet)
			efee->satoshi_per_kw[efee->i] = FEERATE_FLOOR;
		else
			efee->satoshi_per_kw[efee->i] = 0;
#endif
	} else
		/* Rate in satoshi per kw. */
		efee->satoshi_per_kw[efee->i]
			= feerate_from_style(feerate, FEERATE_PER_KBYTE);

	efee->i++;
	if (efee->i == tal_count(efee->satoshi_per_kw)) {
		efee->cb(bcli->bitcoind, efee->satoshi_per_kw, efee->arg);
		tal_free(efee);
	} else {
		/* Next */
		do_one_estimatefee(bcli->bitcoind, efee);
	}
	return true;
}

static void do_one_estimatefee(struct bitcoind *bitcoind,
			       struct estimatefee *efee)
{
	char blockstr[STR_MAX_CHARS(u32)];

	snprintf(blockstr, sizeof(blockstr), "%u", efee->blocks[efee->i]);
	start_bitcoin_cli(bitcoind, NULL, process_estimatefee, false,
			  BITCOIND_LOW_PRIO,
			  NULL, efee,
			  "estimatesmartfee", blockstr, efee->estmode[efee->i],
			  NULL);
}

void bitcoind_estimate_fees_(struct bitcoind *bitcoind,
			     const u32 blocks[], const char *estmode[],
			     size_t num_estimates,
			     void (*cb)(struct bitcoind *bitcoind,
					const u32 satoshi_per_kw[], void *),
			     void *arg)
{
	struct estimatefee *efee = tal(bitcoind, struct estimatefee);

	efee->i = 0;
	efee->blocks = tal_dup_arr(efee, u32, blocks, num_estimates, 0);
	efee->estmode = tal_dup_arr(efee, const char *, estmode, num_estimates,
				    0);
	efee->cb = cb;
	efee->arg = arg;
	efee->satoshi_per_kw = tal_arr(efee, u32, num_estimates);

	do_one_estimatefee(bitcoind, efee);
}

/* Our Bitcoin backend plugin gave us a bad response. We can't recover. */
static void bitcoin_plugin_error(struct bitcoind *bitcoind, const char *buf,
				 const jsmntok_t *toks, const char *method,
				 const char *reason)
{
	struct plugin *p = strmap_get(&bitcoind->pluginsmap, method);
	fatal("%s error: bad response to %s (%s), response was %.*s",
	      p->cmd, method, reason,
	      toks->end - toks->start, buf + toks->start);
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
	plugin_request_send(strmap_get(&bitcoind->pluginsmap,
				       "sendrawtransaction"), req);
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
	plugin_request_send(strmap_get(&bitcoind->pluginsmap,
				       "getrawblockbyheight"), req);
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
	plugin_request_send(strmap_get(&bitcoind->pluginsmap, "getchaininfo"),
			    req);
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
	plugin_request_send(strmap_get(&bitcoind->pluginsmap, "getutxout"),
			    req);
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
	/* Suppresses the callbacks from bcli_finished as we free conns. */
	bitcoind->shutdown = true;
}

struct bitcoind *new_bitcoind(const tal_t *ctx,
			      struct lightningd *ld,
			      struct log *log)
{
	struct bitcoind *bitcoind = tal(ctx, struct bitcoind);

	strmap_init(&bitcoind->pluginsmap);
	bitcoind->cli = NULL;
	bitcoind->datadir = NULL;
	bitcoind->ld = ld;
	bitcoind->log = log;
	for (size_t i = 0; i < BITCOIND_NUM_PRIO; i++) {
		bitcoind->num_requests[i] = 0;
		list_head_init(&bitcoind->pending[i]);
	}
	list_head_init(&bitcoind->pending_getfilteredblock);
	bitcoind->shutdown = false;
	bitcoind->error_count = 0;
	bitcoind->retry_timeout = 60;
	bitcoind->rpcuser = NULL;
	bitcoind->rpcpass = NULL;
	bitcoind->rpcconnect = NULL;
	bitcoind->rpcport = NULL;
	tal_add_destructor(bitcoind, destroy_bitcoind);
	bitcoind->synced = false;

	return bitcoind;
}
