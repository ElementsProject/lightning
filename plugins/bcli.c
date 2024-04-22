#include "config.h"
#include <bitcoin/base58.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/io/io.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <errno.h>
#include <plugins/libplugin.h>

/* Bitcoind's web server has a default of 4 threads, with queue depth 16.
 * It will *fail* rather than queue beyond that, so we must not stress it!
 *
 * This is how many request for each priority level we have.
 */
#define BITCOIND_MAX_PARALLEL 4
#define RPC_TRANSACTION_ALREADY_IN_CHAIN -27

enum bitcoind_prio {
	BITCOIND_LOW_PRIO,
	BITCOIND_HIGH_PRIO
};
#define BITCOIND_NUM_PRIO (BITCOIND_HIGH_PRIO+1)

struct bitcoind {
	/* eg. "bitcoin-cli" */
	char *cli;

	/* -datadir arg for bitcoin-cli. */
	char *datadir;

	/* bitcoind's version, used for compatibility checks. */
	u32 version;

	/* Is bitcoind synced?  If not, we retry. */
	bool synced;

	/* How many high/low prio requests are we running (it's ratelimited) */
	size_t num_requests[BITCOIND_NUM_PRIO];

	/* Pending requests (high and low prio). */
	struct list_head pending[BITCOIND_NUM_PRIO];

	/* In flight requests (in a list for memleak detection) */
	struct list_head current;

	/* If non-zero, time we first hit a bitcoind error. */
	unsigned int error_count;
	struct timemono first_error_time;

	/* How long to keep trying to contact bitcoind
	 * before fatally exiting. */
	u64 retry_timeout;

	/* Passthrough parameters for bitcoin-cli */
	char *rpcuser, *rpcpass, *rpcconnect, *rpcport;

	/* Whether we fake fees (regtest) */
	bool fake_fees;

	/* Override in case we're developer mode for testing*/
	bool dev_no_fake_fees;
};

static struct bitcoind *bitcoind;

struct bitcoin_cli {
	struct list_node list;
	int fd;
	int *exitstatus;
	pid_t pid;
	const char **args;
	struct timeabs start;
	enum bitcoind_prio prio;
	char *output;
	size_t output_bytes;
	size_t new_output;
	struct command_result *(*process)(struct bitcoin_cli *);
	struct command *cmd;
	/* Used to stash content between multiple calls */
	void *stash;
};

/* Add the n'th arg to *args, incrementing n and keeping args of size n+1 */
static void add_arg(const char ***args, const char *arg TAKES)
{
	if (taken(arg))
		tal_steal(*args, arg);
	tal_arr_expand(args, arg);
}

static const char **gather_argsv(const tal_t *ctx, const char *cmd, va_list ap)
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
		// Always pipe the rpcpassword via stdin. Do not pass it using an
		// `-rpcpassword` argument - secrets in arguments can leak when listing
		// system processes.
		add_arg(&args, "-stdinrpcpass");

	add_arg(&args, cmd);
	while ((arg = va_arg(ap, char *)) != NULL)
		add_arg(&args, arg);
	add_arg(&args, NULL);

	return args;
}

static LAST_ARG_NULL const char **
gather_args(const tal_t *ctx, const char *cmd, ...)
{
	va_list ap;
	const char **ret;

	va_start(ap, cmd);
	ret = gather_argsv(ctx, cmd, ap);
	va_end(ap);

	return ret;
}

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

static void next_bcli(enum bitcoind_prio prio);

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

/* Only set as destructor once bcli is in current. */
static void destroy_bcli(struct bitcoin_cli *bcli)
{
	list_del_from(&bitcoind->current, &bcli->list);
}

static void retry_bcli(void *cb_arg)
{
	struct bitcoin_cli *bcli = cb_arg;
	list_del_from(&bitcoind->current, &bcli->list);
	tal_del_destructor(bcli, destroy_bcli);

	list_add_tail(&bitcoind->pending[bcli->prio], &bcli->list);
	tal_free(bcli->output);
	next_bcli(bcli->prio);
}

/* We allow 60 seconds of spurious errors, eg. reorg. */
static void bcli_failure(struct bitcoin_cli *bcli,
                         int exitstatus)
{
	struct timerel t;

	if (!bitcoind->error_count)
		bitcoind->first_error_time = time_mono();

	t = timemono_between(time_mono(), bitcoind->first_error_time);
	if (time_greater(t, time_from_sec(bitcoind->retry_timeout)))
		plugin_err(bcli->cmd->plugin,
		           "%s exited %u (after %u other errors) '%.*s'; "
		           "we have been retrying command for "
		           "--bitcoin-retry-timeout=%"PRIu64" seconds; "
		           "bitcoind setup or our --bitcoin-* configs broken?",
		           bcli_args(tmpctx, bcli),
		           exitstatus,
		           bitcoind->error_count,
		           (int)bcli->output_bytes,
		           bcli->output,
		           bitcoind->retry_timeout);

	plugin_log(bcli->cmd->plugin, LOG_UNUSUAL, "%s exited with status %u",
		   bcli_args(tmpctx, bcli), exitstatus);
	bitcoind->error_count++;

	/* Retry in 1 second */
	plugin_timer(bcli->cmd->plugin, time_from_sec(1), retry_bcli, bcli);
}

static void bcli_finished(struct io_conn *conn UNUSED, struct bitcoin_cli *bcli)
{
	int ret, status;
	struct command_result *res;
	enum bitcoind_prio prio = bcli->prio;
	u64 msec = time_to_msec(time_between(time_now(), bcli->start));

	/* If it took over 10 seconds, that's rather strange. */
	if (msec > 10000)
		plugin_log(bcli->cmd->plugin, LOG_UNUSUAL,
		           "bitcoin-cli: finished %s (%"PRIu64" ms)",
		           bcli_args(tmpctx, bcli), msec);

	assert(bitcoind->num_requests[prio] > 0);

	/* FIXME: If we waited for SIGCHILD, this could never hang! */
	while ((ret = waitpid(bcli->pid, &status, 0)) < 0 && errno == EINTR);
	if (ret != bcli->pid)
		plugin_err(bcli->cmd->plugin, "%s %s", bcli_args(tmpctx, bcli),
		           ret == 0 ? "not exited?" : strerror(errno));

	if (!WIFEXITED(status))
		plugin_err(bcli->cmd->plugin, "%s died with signal %i",
		           bcli_args(tmpctx, bcli),
		           WTERMSIG(status));

	/* Implicit nonzero_exit_ok == false */
	if (!bcli->exitstatus) {
		if (WEXITSTATUS(status) != 0) {
			bcli_failure(bcli, WEXITSTATUS(status));
			bitcoind->num_requests[prio]--;
			goto done;
		}
	} else
		*bcli->exitstatus = WEXITSTATUS(status);

	if (WEXITSTATUS(status) == 0)
		bitcoind->error_count = 0;

	bitcoind->num_requests[bcli->prio]--;

	res = bcli->process(bcli);
	if (!res)
		bcli_failure(bcli, WEXITSTATUS(status));
	else
		tal_free(bcli);

done:
	next_bcli(prio);
}

static void next_bcli(enum bitcoind_prio prio)
{
	struct bitcoin_cli *bcli;
	struct io_conn *conn;
	int in;

	if (bitcoind->num_requests[prio] >= BITCOIND_MAX_PARALLEL)
		return;

	bcli = list_pop(&bitcoind->pending[prio], struct bitcoin_cli, list);
	if (!bcli)
		return;

	bcli->pid = pipecmdarr(&in, &bcli->fd, &bcli->fd,
			       cast_const2(char **, bcli->args));
	if (bcli->pid < 0)
		plugin_err(bcli->cmd->plugin, "%s exec failed: %s",
			   bcli->args[0], strerror(errno));


	if (bitcoind->rpcpass)
		write_all(in, bitcoind->rpcpass, strlen(bitcoind->rpcpass));

	close(in);

	bcli->start = time_now();

	bitcoind->num_requests[prio]++;

	/* We don't keep a pointer to this, but it's not a leak */
	conn = notleak(io_new_conn(bcli, bcli->fd, output_init, bcli));
	io_set_finish(conn, bcli_finished, bcli);

	list_add_tail(&bitcoind->current, &bcli->list);
	tal_add_destructor(bcli, destroy_bcli);
}

static void
start_bitcoin_cliv(const tal_t *ctx,
		   struct command *cmd,
		   struct command_result *(*process)(struct bitcoin_cli *),
		   bool nonzero_exit_ok,
		   enum bitcoind_prio prio,
		   void *stash,
		   const char *method,
		   va_list ap)
{
	struct bitcoin_cli *bcli = tal(bitcoind, struct bitcoin_cli);

	bcli->process = process;
	bcli->cmd = cmd;
	bcli->prio = prio;

	if (nonzero_exit_ok)
		bcli->exitstatus = tal(bcli, int);
	else
		bcli->exitstatus = NULL;

	bcli->args = gather_argsv(bcli, method, ap);
	bcli->stash = stash;

	list_add_tail(&bitcoind->pending[bcli->prio], &bcli->list);
	next_bcli(bcli->prio);
}

/* If ctx is non-NULL, and is freed before we return, we don't call process().
 * process returns false() if it's a spurious error, and we should retry. */
static void LAST_ARG_NULL
start_bitcoin_cli(const tal_t *ctx,
		  struct command *cmd,
		  struct command_result *(*process)(struct bitcoin_cli *),
		  bool nonzero_exit_ok,
		  enum bitcoind_prio prio,
		  void *stash,
		  const char *method,
		  ...)
{
	va_list ap;

	va_start(ap, method);
	start_bitcoin_cliv(ctx, cmd, process, nonzero_exit_ok, prio, stash, method,
			   ap);
	va_end(ap);
}

static void strip_trailing_whitespace(char *str, size_t len)
{
	size_t stripped_len = len;
	while (stripped_len > 0 && cisspace(str[stripped_len-1]))
		stripped_len--;

	str[stripped_len] = 0x00;
}

static struct command_result *command_err_bcli_badjson(struct bitcoin_cli *bcli,
						       const char *errmsg)
{
	char *err = tal_fmt(bcli, "%s: bad JSON: %s (%.*s)",
			    bcli_args(tmpctx, bcli), errmsg,
			    (int)bcli->output_bytes, bcli->output);
	return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
}

static struct command_result *process_getutxout(struct bitcoin_cli *bcli)
{
	const jsmntok_t *tokens;
	struct json_stream *response;
	struct bitcoin_tx_output output;
	const char *err;

	/* As of at least v0.15.1.0, bitcoind returns "success" but an empty
	   string on a spent txout. */
	if (*bcli->exitstatus != 0 || bcli->output_bytes == 0) {
		response = jsonrpc_stream_success(bcli->cmd);
		json_add_null(response, "amount");
		json_add_null(response, "script");

		return command_finished(bcli->cmd, response);
	}

	tokens = json_parse_simple(bcli->output, bcli->output,
				   bcli->output_bytes);
	if (!tokens) {
		return command_err_bcli_badjson(bcli, "cannot parse");
	}

	err = json_scan(tmpctx, bcli->output, tokens,
		       "{value:%,scriptPubKey:{hex:%}}",
		       JSON_SCAN(json_to_bitcoin_amount,
				 &output.amount.satoshis), /* Raw: bitcoind */
		       JSON_SCAN_TAL(bcli, json_tok_bin_from_hex,
				     &output.script));
	if (err)
		return command_err_bcli_badjson(bcli, err);

	response = jsonrpc_stream_success(bcli->cmd);
	json_add_sats(response, "amount", output.amount);
	json_add_string(response, "script", tal_hex(response, output.script));

	return command_finished(bcli->cmd, response);
}

static struct command_result *process_getblockchaininfo(struct bitcoin_cli *bcli)
{
	const jsmntok_t *tokens;
	struct json_stream *response;
	bool ibd;
	u32 headers, blocks;
	const char *chain, *err;

	tokens = json_parse_simple(bcli->output,
				   bcli->output, bcli->output_bytes);
	if (!tokens) {
		return command_err_bcli_badjson(bcli, "cannot parse");
	}

	err = json_scan(tmpctx, bcli->output, tokens,
			"{chain:%,headers:%,blocks:%,initialblockdownload:%}",
			JSON_SCAN_TAL(tmpctx, json_strdup, &chain),
			JSON_SCAN(json_to_number, &headers),
			JSON_SCAN(json_to_number, &blocks),
			JSON_SCAN(json_to_bool, &ibd));
	if (err)
		return command_err_bcli_badjson(bcli, err);

	response = jsonrpc_stream_success(bcli->cmd);
	json_add_string(response, "chain", chain);
	json_add_u32(response, "headercount", headers);
	json_add_u32(response, "blockcount", blocks);
	json_add_bool(response, "ibd", ibd);

	return command_finished(bcli->cmd, response);
}

struct estimatefee_params {
	u32 blocks;
	const char *style;
};

static const struct estimatefee_params estimatefee_params[] = {
	{ 2, "CONSERVATIVE" },
	{ 6, "ECONOMICAL" },
	{ 12, "ECONOMICAL" },
	{ 100, "ECONOMICAL" },
};

struct estimatefees_stash {
	/* This is max(mempoolminfee,minrelaytxfee) */
	u64 perkb_floor;
	u32 cursor;
	/* FIXME: We use u64 but lightningd will store them as u32. */
	u64 perkb[ARRAY_SIZE(estimatefee_params)];
};

static struct command_result *
estimatefees_null_response(struct bitcoin_cli *bcli)
{
	struct json_stream *response = jsonrpc_stream_success(bcli->cmd);

	/* We give a floor, which is the standard minimum */
	json_array_start(response, "feerates");
	json_array_end(response);
	json_add_u32(response, "feerate_floor", 1000);

	if (command_deprecated_out_ok(bcli->cmd, "dummy_null",
				      "v23.05", "v24.05")) {
		json_add_null(response, "opening");
		json_add_null(response, "mutual_close");
		json_add_null(response, "unilateral_close");
		json_add_null(response, "delayed_to_us");
		json_add_null(response, "htlc_resolution");
		json_add_null(response, "penalty");
		json_add_null(response, "min_acceptable");
		json_add_null(response, "max_acceptable");
	}

	return command_finished(bcli->cmd, response);
}

static struct command_result *
estimatefees_parse_feerate(struct bitcoin_cli *bcli, u64 *feerate)
{
	const jsmntok_t *tokens;

	tokens = json_parse_simple(bcli->output,
				   bcli->output, bcli->output_bytes);
	if (!tokens) {
		return command_err_bcli_badjson(bcli, "cannot parse");
	}

	if (json_scan(tmpctx, bcli->output, tokens, "{feerate:%}",
		      JSON_SCAN(json_to_bitcoin_amount, feerate)) != NULL) {
		/* Paranoia: if it had a feerate, but was malformed: */
		if (json_get_member(bcli->output, tokens, "feerate"))
			return command_err_bcli_badjson(bcli, "cannot scan");
		/* Regtest fee estimation is generally awful: Fake it at min. */
		if (bitcoind->fake_fees) {
			*feerate = 1000;
			return NULL;
		}
		/* We return null if estimation failed, and bitcoin-cli will
		 * exit with 0 but no feerate field on failure. */
		return estimatefees_null_response(bcli);
	}

	return NULL;
}

static struct command_result *process_sendrawtransaction(struct bitcoin_cli *bcli)
{
	struct json_stream *response;

	/* This is useful for functional tests. */
	if (bcli->exitstatus)
		plugin_log(bcli->cmd->plugin, LOG_DBG,
			   "sendrawtx exit %i (%s) %.*s",
			   *bcli->exitstatus, bcli_args(tmpctx, bcli),
			   *bcli->exitstatus ?
				(u32)bcli->output_bytes-1 : 0,
				bcli->output);

	response = jsonrpc_stream_success(bcli->cmd);
	json_add_bool(response, "success",
		      *bcli->exitstatus == 0 ||
			  *bcli->exitstatus ==
			      RPC_TRANSACTION_ALREADY_IN_CHAIN);
	json_add_string(response, "errmsg",
			*bcli->exitstatus ?
			tal_strndup(bcli->cmd,
				    bcli->output, bcli->output_bytes-1)
			: "");

	return command_finished(bcli->cmd, response);
}

struct getrawblock_stash {
	const char *block_hash;
	u32 block_height;
	const char *block_hex;
	int *peers;
};

/* Mutual recursion. */
static struct command_result *getrawblock(struct bitcoin_cli *bcli);

static struct command_result *process_rawblock(struct bitcoin_cli *bcli)
{
	struct json_stream *response;
	struct getrawblock_stash *stash = bcli->stash;

	strip_trailing_whitespace(bcli->output, bcli->output_bytes);
	stash->block_hex = tal_steal(stash, bcli->output);

	response = jsonrpc_stream_success(bcli->cmd);
	json_add_string(response, "blockhash", stash->block_hash);
	json_add_string(response, "block", stash->block_hex);

	return command_finished(bcli->cmd, response);
}

static struct command_result *process_getblockfrompeer(struct bitcoin_cli *bcli)
{
	/* Remove the peer that we tried to get the block from and move along,
	 * we may also check on errors here */
	struct getrawblock_stash *stash = bcli->stash;

	if (bcli->exitstatus && *bcli->exitstatus != 0) {
		/* We still continue with the execution if we can not fetch the
		 * block from peer */
		plugin_log(bcli->cmd->plugin, LOG_DBG,
			   "failed to fetch block %s from peer %i, skip.",
			   stash->block_hash, stash->peers[0]);
	} else {
		plugin_log(bcli->cmd->plugin, LOG_DBG,
			   "try to fetch block %s from peer %i.",
			   stash->block_hash, stash->peers[0]);
	}

	stash->peers[0] = stash->peers[tal_count(stash->peers) - 1];
	tal_resize(&stash->peers, tal_count(stash->peers) - 1);

	/* `getblockfrompeer` is an async call. sleep for a second to allow the
	 * block to be delivered by the peer. fixme: We could also sleep for
	 * double the last ping here (with sanity limit)*/
	sleep(1);

	return getrawblock(bcli);
}

static struct command_result *process_getpeerinfo(struct bitcoin_cli *bcli)
{
	const jsmntok_t *t, *toks;
	struct getrawblock_stash *stash = bcli->stash;
	size_t i;

	toks =
	    json_parse_simple(bcli->output, bcli->output, bcli->output_bytes);

	if (!toks) {
		return command_err_bcli_badjson(bcli, "cannot parse");
	}

	stash->peers = tal_arr(bcli->stash, int, 0);

	json_for_each_arr(i, t, toks)
	{
		int id;
		if (json_scan(tmpctx, bcli->output, t, "{id:%}",
			      JSON_SCAN(json_to_int, &id)) == NULL) {
			// fixme: future optimization: a) filter for full nodes,
			// b) sort by last ping
			tal_arr_expand(&stash->peers, id);
		}
	}

	if (tal_count(stash->peers) <= 0) {
		/* We don't have peers yet, retry from `getrawblock` */
		plugin_log(bcli->cmd->plugin, LOG_DBG,
			   "got an empty peer list.");
		return getrawblock(bcli);
	}

	start_bitcoin_cli(NULL, bcli->cmd, process_getblockfrompeer, true,
			  BITCOIND_HIGH_PRIO, stash, "getblockfrompeer",
			  stash->block_hash,
			  take(tal_fmt(NULL, "%i", stash->peers[0])), NULL);

	return command_still_pending(bcli->cmd);
}

static struct command_result *process_getrawblock(struct bitcoin_cli *bcli)
{
	/* We failed to get the raw block. */
	if (bcli->exitstatus && *bcli->exitstatus != 0) {
		struct getrawblock_stash *stash = bcli->stash;

		plugin_log(bcli->cmd->plugin, LOG_DBG,
			   "failed to fetch block %s from the bitcoin backend (maybe pruned).",
			   stash->block_hash);

		if (bitcoind->version >= 230000) {
			/* `getblockformpeer` was introduced in v23.0.0 */

			if (!stash->peers) {
				/* We don't have peers to fetch blocks from, get
				 * some! */
				start_bitcoin_cli(NULL, bcli->cmd,
						  process_getpeerinfo, true,
						  BITCOIND_HIGH_PRIO, stash,
						  "getpeerinfo", NULL);

				return command_still_pending(bcli->cmd);
			}

			if (tal_count(stash->peers) > 0) {
				/* We have peers left that we can ask for the
				 * block */
				start_bitcoin_cli(
				    NULL, bcli->cmd, process_getblockfrompeer,
				    true, BITCOIND_HIGH_PRIO, stash,
				    "getblockfrompeer", stash->block_hash,
				    take(tal_fmt(NULL, "%i", stash->peers[0])),
				    NULL);

				return command_still_pending(bcli->cmd);
			}

			/* We failed to fetch the block from from any peer we
			 * got. */
			plugin_log(
			    bcli->cmd->plugin, LOG_DBG,
			    "asked all known peers about block %s, retry",
			    stash->block_hash);
			stash->peers = tal_free(stash->peers);
		}

		return NULL;
	}

	return process_rawblock(bcli);
}

static struct command_result *
getrawblockbyheight_notfound(struct bitcoin_cli *bcli)
{
	struct json_stream *response;

	response = jsonrpc_stream_success(bcli->cmd);
	json_add_null(response, "blockhash");
	json_add_null(response, "block");

	return command_finished(bcli->cmd, response);
}

static struct command_result *getrawblock(struct bitcoin_cli *bcli)
{
	struct getrawblock_stash *stash = bcli->stash;

	start_bitcoin_cli(NULL, bcli->cmd, process_getrawblock, true,
			  BITCOIND_HIGH_PRIO, stash, "getblock",
			  stash->block_hash,
			  /* Non-verbose: raw block. */
			  "0", NULL);

	return command_still_pending(bcli->cmd);
}

static struct command_result *process_getblockhash(struct bitcoin_cli *bcli)
{
	struct getrawblock_stash *stash = bcli->stash;

	/* If it failed with error 8, give an empty response. */
	if (bcli->exitstatus && *bcli->exitstatus != 0) {
		/* Other error means we have to retry. */
		if (*bcli->exitstatus != 8)
			return NULL;
		return getrawblockbyheight_notfound(bcli);
	}

	strip_trailing_whitespace(bcli->output, bcli->output_bytes);
	stash->block_hash = tal_strdup(stash, bcli->output);
	if (!stash->block_hash || strlen(stash->block_hash) != 64) {
		return command_err_bcli_badjson(bcli, "bad blockhash");
	}

	return getrawblock(bcli);
}

/* Get a raw block given its height.
 * Calls `getblockhash` then `getblock` to retrieve it from bitcoin_cli.
 * Will return early with null fields if block isn't known (yet).
 */
static struct command_result *getrawblockbyheight(struct command *cmd,
                                                  const char *buf,
                                                  const jsmntok_t *toks)
{
	struct getrawblock_stash *stash;
	u32 *height;

	/* bitcoin-cli wants a string. */
	if (!param(cmd, buf, toks,
	           p_req("height", param_number, &height),
	           NULL))
		return command_param_failed();

	stash = tal(cmd, struct getrawblock_stash);
	stash->block_height = *height;
	stash->peers = NULL;
	tal_free(height);

	start_bitcoin_cli(NULL, cmd, process_getblockhash, true,
			  BITCOIND_LOW_PRIO, stash,
			  "getblockhash",
			  take(tal_fmt(NULL, "%u", stash->block_height)),
			  NULL);

	return command_still_pending(cmd);
}

/* Get infos about the block chain.
 * Calls `getblockchaininfo` and returns headers count, blocks count,
 * the chain id, and whether this is initialblockdownload.
 */
static struct command_result *getchaininfo(struct command *cmd,
                                           const char *buf UNUSED,
                                           const jsmntok_t *toks UNUSED)
{
	/* FIXME(vincenzopalazzo): Inside the JSON request,
         * we have the current height known from Core Lightning. Therefore,
         * we can attempt to prevent a crash if the 'getchaininfo' function returns
         * a lower height than the one we already know, by waiting for a short period.
         * However, I currently don't have a better idea on how to handle this situation. */
	u32 *height UNUSED;
	if (!param(cmd, buf, toks,
		   p_req("last_height", param_number, &height),
		   NULL))
		return command_param_failed();

	start_bitcoin_cli(NULL, cmd, process_getblockchaininfo, false,
			  BITCOIND_HIGH_PRIO, NULL,
			  "getblockchaininfo", NULL);

	return command_still_pending(cmd);
}

/* Mutual recursion. */
static struct command_result *estimatefees_done(struct bitcoin_cli *bcli);

/* Add a feerate, but don't publish one that bitcoind won't accept. */
static void json_add_feerate(struct json_stream *result, const char *fieldname,
			     struct command *cmd,
			     const struct estimatefees_stash *stash,
			     uint64_t value)
{
	/* Anthony Towns reported signet had a 900kbtc fee block, and then
	 * CLN got upset scanning feerate.  It expects a u32. */
	if (value > 0xFFFFFFFF) {
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "Feerate %"PRIu64" is ridiculous: trimming to 32 bites",
			   value);
		value = 0xFFFFFFFF;
	}
	/* 0 is special, it means "unknown" */
	if (value && value < stash->perkb_floor) {
		plugin_log(cmd->plugin, LOG_DBG,
			   "Feerate %s raised from %"PRIu64
			   " perkb to floor of %"PRIu64,
			   fieldname, value, stash->perkb_floor);
		json_add_u64(result, fieldname, stash->perkb_floor);
	} else {
		json_add_u64(result, fieldname, value);
	}
}

static u32 feerate_for_block(const struct estimatefees_stash *stash, u32 blocks)
{
	for (size_t i = 0; i < ARRAY_SIZE(stash->perkb); i++) {
		if (estimatefee_params[i].blocks != blocks)
			continue;
		return stash->perkb[i];
	}
	abort();
}

static struct command_result *estimatefees_next(struct command *cmd,
						struct estimatefees_stash *stash)
{
	struct json_stream *response;

	if (stash->cursor < ARRAY_SIZE(stash->perkb)) {
		start_bitcoin_cli(NULL, cmd, estimatefees_done, true,
				  BITCOIND_LOW_PRIO, stash,
				  "estimatesmartfee",
				  take(tal_fmt(NULL, "%u",
					       estimatefee_params[stash->cursor].blocks)),
				  estimatefee_params[stash->cursor].style,
				  NULL);

		return command_still_pending(cmd);
	}

	response = jsonrpc_stream_success(cmd);
	if (command_deprecated_out_ok(cmd, "opening",
				      "v23.05", "v24.05"))
		json_add_feerate(response, "opening", cmd, stash,
				 feerate_for_block(stash, 12));
	if (command_deprecated_out_ok(cmd, "mutual_close",
				      "v23.05", "v24.05"))
		json_add_feerate(response, "mutual_close", cmd, stash,
				 feerate_for_block(stash, 100));
	if (command_deprecated_out_ok(cmd, "unilateral_close",
				      "v23.05", "v24.05"))
		json_add_feerate(response, "unilateral_close", cmd, stash,
				 feerate_for_block(stash, 6));
	if (command_deprecated_out_ok(cmd, "delayed_to_us",
				      "v23.05", "v24.05"))
		json_add_feerate(response, "delayed_to_us", cmd, stash,
				 feerate_for_block(stash, 12));
	if (command_deprecated_out_ok(cmd, "htlc_resolution",
				      "v23.05", "v24.05"))
		json_add_feerate(response, "htlc_resolution", cmd, stash,
				 feerate_for_block(stash, 6));
	if (command_deprecated_out_ok(cmd, "penalty",
				      "v23.05", "v24.05"))
		json_add_feerate(response, "penalty", cmd, stash,
				 feerate_for_block(stash, 12));
		/* We divide the slow feerate for the minimum acceptable, lightningd
		 * will use floor if it's hit, though. */
	if (command_deprecated_out_ok(cmd, "min_acceptable",
				      "v23.05", "v24.05"))
		json_add_feerate(response, "min_acceptable", cmd, stash,
				 feerate_for_block(stash, 100) / 2);
		/* BOLT #2:
		 *
		 * Given the variance in fees, and the fact that the transaction may be
		 * spent in the future, it's a good idea for the fee payer to keep a good
		 * margin (say 5x the expected fee requirement)
		 */
	if (command_deprecated_out_ok(cmd, "max_acceptable",
				      "v23.05", "v24.05"))
		json_add_feerate(response, "max_acceptable", cmd, stash,
				 feerate_for_block(stash, 2) * 10);

	/* Modern style: present an ordered array of block deadlines, and a floor. */
	json_array_start(response, "feerates");
	for (size_t i = 0; i < ARRAY_SIZE(stash->perkb); i++) {
		if (!stash->perkb[i])
			continue;
		json_object_start(response, NULL);
		json_add_u32(response, "blocks", estimatefee_params[i].blocks);
		json_add_feerate(response, "feerate", cmd, stash, stash->perkb[i]);
		json_object_end(response);
	}
	json_array_end(response);
	json_add_u64(response, "feerate_floor", stash->perkb_floor);
	return command_finished(cmd, response);
}

static struct command_result *getminfees_done(struct bitcoin_cli *bcli)
{
	const jsmntok_t *tokens;
	const char *err;
	u64 mempoolfee, relayfee;
	struct estimatefees_stash *stash = bcli->stash;

	if (*bcli->exitstatus != 0)
		return estimatefees_null_response(bcli);

	tokens = json_parse_simple(bcli->output,
				   bcli->output, bcli->output_bytes);
	if (!tokens)
		return command_err_bcli_badjson(bcli,
						"cannot parse getmempoolinfo");

	/* Look at minrelaytxfee they configured, and current min fee to get
	 * into mempool. */
	err = json_scan(tmpctx, bcli->output, tokens,
			"{mempoolminfee:%,minrelaytxfee:%}",
			JSON_SCAN(json_to_bitcoin_amount, &mempoolfee),
			JSON_SCAN(json_to_bitcoin_amount, &relayfee));
	if (err)
		return command_err_bcli_badjson(bcli, err);

	stash->perkb_floor = max_u64(mempoolfee, relayfee);
	stash->cursor = 0;
	return estimatefees_next(bcli->cmd, stash);
}

/* Get the current feerates. We use an urgent feerate for unilateral_close and max,
 * a slightly less urgent feerate for htlc_resolution and penalty transactions,
 * a slow feerate for min, and a normal one for all others.
 */
static struct command_result *estimatefees(struct command *cmd,
					   const char *buf UNUSED,
					   const jsmntok_t *toks UNUSED)
{
	struct estimatefees_stash *stash = tal(cmd, struct estimatefees_stash);

	if (!param(cmd, buf, toks, NULL))
		return command_param_failed();

	start_bitcoin_cli(NULL, cmd, getminfees_done, true,
			  BITCOIND_LOW_PRIO, stash,
			  "getmempoolinfo",
			  NULL);
	return command_still_pending(cmd);
}

static struct command_result *estimatefees_done(struct bitcoin_cli *bcli)
{
	struct command_result *err;
	struct estimatefees_stash *stash = bcli->stash;

	/* If we cannot estimate fees, no need to continue bothering bitcoind. */
	if (*bcli->exitstatus != 0)
		return estimatefees_null_response(bcli);

	err = estimatefees_parse_feerate(bcli, &stash->perkb[stash->cursor]);
	if (err)
		return err;

	stash->cursor++;
	return estimatefees_next(bcli->cmd, stash);
}

/* Send a transaction to the Bitcoin network.
 * Calls `sendrawtransaction` using the first parameter as the raw tx.
 */
static struct command_result *sendrawtransaction(struct command *cmd,
                                                 const char *buf,
                                                 const jsmntok_t *toks)
{
	const char *tx, *highfeesarg;
	bool *allowhighfees;

	/* bitcoin-cli wants strings. */
	if (!param(cmd, buf, toks,
	           p_req("tx", param_string, &tx),
		   p_req("allowhighfees", param_bool, &allowhighfees),
	           NULL))
		return command_param_failed();

	if (*allowhighfees) {
			highfeesarg = "0";
	} else
		highfeesarg = NULL;

	start_bitcoin_cli(NULL, cmd, process_sendrawtransaction, true,
			  BITCOIND_HIGH_PRIO, NULL,
			  "sendrawtransaction",
			  tx, highfeesarg, NULL);

	return command_still_pending(cmd);
}

static struct command_result *getutxout(struct command *cmd,
                                       const char *buf,
                                       const jsmntok_t *toks)
{
	const char *txid, *vout;

	/* bitcoin-cli wants strings. */
	if (!param(cmd, buf, toks,
	           p_req("txid", param_string, &txid),
	           p_req("vout", param_string, &vout),
	           NULL))
		return command_param_failed();

	start_bitcoin_cli(NULL, cmd, process_getutxout, true,
			  BITCOIND_HIGH_PRIO, NULL,
			  "gettxout", txid, vout, NULL);

	return command_still_pending(cmd);
}

static void bitcoind_failure(struct plugin *p, const char *error_message)
{
	const char **cmd = gather_args(bitcoind, "echo", NULL);
	plugin_err(p, "\n%s\n\n"
		      "Make sure you have bitcoind running and that bitcoin-cli"
		      " is able to connect to bitcoind.\n\n"
		      "You can verify that your Bitcoin Core installation is"
		      " ready for use by running:\n\n"
		      "    $ %s 'hello world'\n", error_message,
		      args_string(cmd, cmd));
}

/* Do some sanity checks on bitcoind based on the output of `getnetworkinfo`. */
static void parse_getnetworkinfo_result(struct plugin *p, const char *buf)
{
	const jsmntok_t *result;
	bool tx_relay;
	u32 min_version = 220000;
	const char *err;

	result = json_parse_simple(NULL, buf, strlen(buf));
	if (!result)
		plugin_err(p, "Invalid response to '%s': '%s'. Can not "
			      "continue without proceeding to sanity checks.",
			      gather_args(bitcoind, "getnetworkinfo", NULL), buf);

	/* Check that we have a fully-featured `estimatesmartfee`. */
	err = json_scan(tmpctx, buf, result, "{version:%,localrelay:%}",
			JSON_SCAN(json_to_u32, &bitcoind->version),
			JSON_SCAN(json_to_bool, &tx_relay));
	if (err)
		plugin_err(p, "%s.  Got '%s'. Can not"
			   " continue without proceeding to sanity checks.",
			   err,
			   gather_args(bitcoind, "getnetworkinfo", NULL), buf);

	if (bitcoind->version < min_version)
		plugin_err(p, "Unsupported bitcoind version %"PRIu32", at least"
			      " %"PRIu32" required.", bitcoind->version, min_version);

	/* We don't support 'blocksonly', as we rely on transaction relay for fee
	 * estimates. */
	if (!tx_relay)
		plugin_err(p, "The 'blocksonly' mode of bitcoind, or any option "
			      "deactivating transaction relay is not supported.");

	tal_free(result);
}

static void wait_and_check_bitcoind(struct plugin *p)
{
	int in, from, status, ret;
	pid_t child;
	const char **cmd = gather_args(bitcoind, "getnetworkinfo", NULL);
	bool printed = false;
	char *output = NULL;

	for (;;) {
		tal_free(output);

		child = pipecmdarr(&in, &from, &from, cast_const2(char **, cmd));

		if (bitcoind->rpcpass)
			write_all(in, bitcoind->rpcpass, strlen(bitcoind->rpcpass));

		close(in);

		if (child < 0) {
			if (errno == ENOENT)
				bitcoind_failure(p, "bitcoin-cli not found. Is bitcoin-cli "
						    "(part of Bitcoin Core) available in your PATH?");
			plugin_err(p, "%s exec failed: %s", cmd[0], strerror(errno));
		}

		output = grab_fd(cmd, from);

		while ((ret = waitpid(child, &status, 0)) < 0 && errno == EINTR);
		if (ret != child)
			bitcoind_failure(p, tal_fmt(bitcoind, "Waiting for %s: %s",
						    cmd[0], strerror(errno)));
		if (!WIFEXITED(status))
			bitcoind_failure(p, tal_fmt(bitcoind, "Death of %s: signal %i",
						   cmd[0], WTERMSIG(status)));

		if (WEXITSTATUS(status) == 0)
			break;

		/* bitcoin/src/rpc/protocol.h:
		 *	RPC_IN_WARMUP = -28, //!< Client still warming up
		 */
		if (WEXITSTATUS(status) != 28) {
			if (WEXITSTATUS(status) == 1)
				bitcoind_failure(p, "Could not connect to bitcoind using"
						    " bitcoin-cli. Is bitcoind running?");
			bitcoind_failure(p, tal_fmt(bitcoind, "%s exited with code %i: %s",
						    cmd[0], WEXITSTATUS(status), output));
		}

		if (!printed) {
			plugin_log(p, LOG_UNUSUAL,
				   "Waiting for bitcoind to warm up...");
			printed = true;
		}
		sleep(1);
	}

	parse_getnetworkinfo_result(p, output);

	tal_free(cmd);
}

static void memleak_mark_bitcoind(struct plugin *p, struct htable *memtable)
{
	memleak_scan_obj(memtable, bitcoind);
}

static const char *init(struct plugin *p, const char *buffer UNUSED,
			const jsmntok_t *config UNUSED)
{
	wait_and_check_bitcoind(p);

	/* Usually we fake up fees in regtest */
	if (streq(chainparams->network_name, "regtest"))
		bitcoind->fake_fees = !bitcoind->dev_no_fake_fees;
	else
		bitcoind->fake_fees = false;

	plugin_set_memleak_handler(p, memleak_mark_bitcoind);
	plugin_log(p, LOG_INFORM,
		   "bitcoin-cli initialized and connected to bitcoind.");

	return NULL;
}

static const struct plugin_command commands[] = {
	{
		"getrawblockbyheight",
		"bitcoin",
		"Get the bitcoin block at a given height",
		"",
		getrawblockbyheight
	},
	{
		"getchaininfo",
		"bitcoin",
		"Get the chain id, the header count, the block count,"
		" and whether this is IBD.",
		"",
		getchaininfo
	},
	{
		"estimatefees",
		"bitcoin",
		"Get the urgent, normal and slow Bitcoin feerates as"
		" sat/kVB.",
		"",
		estimatefees
	},
	{
		"sendrawtransaction",
		"bitcoin",
		"Send a raw transaction to the Bitcoin network.",
		"",
		sendrawtransaction
	},
	{
		"getutxout",
		"bitcoin",
		"Get information about an output, identified by a {txid} an a {vout}",
		"",
		getutxout
	},
};

static struct bitcoind *new_bitcoind(const tal_t *ctx)
{
	bitcoind = tal(ctx, struct bitcoind);

	bitcoind->cli = NULL;
	bitcoind->datadir = NULL;
	for (size_t i = 0; i < BITCOIND_NUM_PRIO; i++) {
		bitcoind->num_requests[i] = 0;
		list_head_init(&bitcoind->pending[i]);
	}
	list_head_init(&bitcoind->current);
	bitcoind->error_count = 0;
	bitcoind->retry_timeout = 60;
	bitcoind->rpcuser = NULL;
	bitcoind->rpcpass = NULL;
	bitcoind->rpcconnect = NULL;
	bitcoind->rpcport = NULL;
	bitcoind->dev_no_fake_fees = false;

	return bitcoind;
}

int main(int argc, char *argv[])
{
	setup_locale();

	/* Initialize our global context object here to handle startup options. */
	bitcoind = new_bitcoind(NULL);

	plugin_main(argv, init, PLUGIN_STATIC, false /* Do not init RPC on startup*/,
		    NULL, commands, ARRAY_SIZE(commands),
		    NULL, 0, NULL, 0, NULL, 0,
		    plugin_option("bitcoin-datadir",
				  "string",
				  "-datadir arg for bitcoin-cli",
				  charp_option, &bitcoind->datadir),
		    plugin_option("bitcoin-cli",
				  "string",
				  "bitcoin-cli pathname",
				  charp_option, &bitcoind->cli),
		    plugin_option("bitcoin-rpcuser",
				  "string",
				  "bitcoind RPC username",
				  charp_option, &bitcoind->rpcuser),
		    plugin_option("bitcoin-rpcpassword",
				  "string",
				  "bitcoind RPC password",
				  charp_option, &bitcoind->rpcpass),
		    plugin_option("bitcoin-rpcconnect",
				  "string",
				  "bitcoind RPC host to connect to",
				  charp_option, &bitcoind->rpcconnect),
		    plugin_option("bitcoin-rpcport",
				  "int",
				  "bitcoind RPC host's port",
				  charp_option, &bitcoind->rpcport),
		    plugin_option("bitcoin-retry-timeout",
				  "string",
				  "how long to keep retrying to contact bitcoind"
				  " before fatally exiting",
				  u64_option, &bitcoind->retry_timeout),
		    plugin_option_dev("dev-no-fake-fees",
				      "bool",
				      "Suppress fee faking for regtest",
				      bool_option, &bitcoind->dev_no_fake_fees),
		    NULL);
}
