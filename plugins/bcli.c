#include <bitcoin/base58.h>
#include <bitcoin/block.h>
#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <bitcoin/shadouble.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/io/io.h>
#include <ccan/json_out/json_out.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/str/hex/hex.h>
#include <ccan/take/take.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/json_helpers.h>
#include <common/memleak.h>
#include <common/utils.h>
#include <errno.h>
#include <inttypes.h>
#include <plugins/libplugin.h>

/* Bitcoind's web server has a default of 4 threads, with queue depth 16.
 * It will *fail* rather than queue beyond that, so we must not stress it!
 *
 * This is how many request for each priority level we have.
 */
#define BITCOIND_MAX_PARALLEL 4

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

	/* Is bitcoind synced?  If not, we retry. */
	bool synced;

	/* How many high/low prio requests are we running (it's ratelimited) */
	size_t num_requests[BITCOIND_NUM_PRIO];

	/* Pending requests (high and low prio). */
	struct list_head pending[BITCOIND_NUM_PRIO];

	/* If non-zero, time we first hit a bitcoind error. */
	unsigned int error_count;
	struct timemono first_error_time;

	/* How long to keep trying to contact bitcoind
	 * before fatally exiting. */
	u64 retry_timeout;

	/* Passthrough parameters for bitcoin-cli */
	char *rpcuser, *rpcpass, *rpcconnect, *rpcport;

	/* The factor to time the urgent feerate by to get the maximum
	 * acceptable feerate. */
	u32 max_fee_multiplier;

	/* Percent of CONSERVATIVE/2 feerate we'll use for commitment txs. */
	u64 commit_fee_percent;
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
static void add_arg(const char ***args, const char *arg)
{
	tal_arr_expand(args, arg);
}

static const char **gather_args(const tal_t *ctx, const char *cmd, const char **cmd_args)
{
	const char **args = tal_arr(ctx, const char *, 1);

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
	for (size_t i = 0; i < tal_count(cmd_args); i++)
		add_arg(&args, cmd_args[i]);
	add_arg(&args, NULL);

	return args;
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

static char *bcli_args(struct bitcoin_cli *bcli)
{
    return args_string(bcli, bcli->args);
}

static void retry_bcli(void *cb_arg)
{
	struct bitcoin_cli *bcli = cb_arg;
	list_add_tail(&bitcoind->pending[bcli->prio], &bcli->list);
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
		           bcli_args(bcli),
		           exitstatus,
		           bitcoind->error_count,
		           (int)bcli->output_bytes,
		           bcli->output,
		           bitcoind->retry_timeout);

	plugin_log(bcli->cmd->plugin, LOG_UNUSUAL, "%s exited with status %u",
		   bcli_args(bcli), exitstatus);
	bitcoind->error_count++;

	/* Retry in 1 second (not a leak!) */
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
		           bcli_args(bcli), msec);

	assert(bitcoind->num_requests[prio] > 0);

	/* FIXME: If we waited for SIGCHILD, this could never hang! */
	while ((ret = waitpid(bcli->pid, &status, 0)) < 0 && errno == EINTR);
	if (ret != bcli->pid)
		plugin_err(bcli->cmd->plugin, "%s %s", bcli_args(bcli),
		           ret == 0 ? "not exited?" : strerror(errno));

	if (!WIFEXITED(status))
		plugin_err(bcli->cmd->plugin, "%s died with signal %i",
		           bcli_args(bcli),
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

	if (bitcoind->num_requests[prio] >= BITCOIND_MAX_PARALLEL)
		return;

	bcli = list_pop(&bitcoind->pending[prio], struct bitcoin_cli, list);
	if (!bcli)
		return;

	bcli->pid = pipecmdarr(NULL, &bcli->fd, &bcli->fd,
			       cast_const2(char **, bcli->args));
	if (bcli->pid < 0)
		plugin_err(bcli->cmd->plugin, "%s exec failed: %s",
			   bcli->args[0], strerror(errno));

	bcli->start = time_now();

	bitcoind->num_requests[prio]++;

	conn = io_new_conn(bcli, bcli->fd, output_init, bcli);
	io_set_finish(conn, bcli_finished, bcli);
}

/* If ctx is non-NULL, and is freed before we return, we don't call process().
 * process returns false() if it's a spurious error, and we should retry. */
static void
start_bitcoin_cli(const tal_t *ctx,
		  struct command *cmd,
		  struct command_result *(*process)(struct bitcoin_cli *),
		  bool nonzero_exit_ok,
		  enum bitcoind_prio prio,
		  char *method, const char **method_args,
		  void *stash)
{
	struct bitcoin_cli *bcli = tal(bitcoind, struct bitcoin_cli);

	bcli->process = process;
	bcli->cmd = cmd;
	bcli->prio = prio;

	if (nonzero_exit_ok)
		bcli->exitstatus = tal(bcli, int);
	else
		bcli->exitstatus = NULL;

	bcli->args = gather_args(bcli, method, method_args);
	bcli->stash = stash;

	list_add_tail(&bitcoind->pending[bcli->prio], &bcli->list);
	next_bcli(bcli->prio);
}

static struct command_result *process_getutxout(struct bitcoin_cli *bcli)
{
	const jsmntok_t *tokens, *valuetok, *scriptpubkeytok, *hextok;
	struct json_stream *response;
	bool valid;
	struct bitcoin_tx_output output;
	char *err;

	/* As of at least v0.15.1.0, bitcoind returns "success" but an empty
	   string on a spent txout. */
	if (*bcli->exitstatus != 0 || bcli->output_bytes == 0) {
		response = jsonrpc_stream_success(bcli->cmd);
		json_add_null(response, "amount");
		json_add_null(response, "script");

		return command_finished(bcli->cmd, response);
	}

	tokens = json_parse_input(bcli->output, bcli->output,
				  bcli->output_bytes, &valid);
	if (!tokens) {
		err = tal_fmt(bcli, "%s: %s response", bcli_args(bcli),
			      valid ? "partial" : "invalid");
		return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
	}

	if (tokens[0].type != JSMN_OBJECT) {
		err = tal_fmt(bcli, "%s: gave non-object (%.*s)?",
			      bcli_args(bcli), (int)bcli->output_bytes,
			      bcli->output);
		return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
	}

	valuetok = json_get_member(bcli->output, tokens, "value");
	if (!valuetok) {
		err = tal_fmt(bcli,"%s: had no value member (%.*s)?",
			      bcli_args(bcli), (int)bcli->output_bytes,
			      bcli->output);
		return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
	}

	if (!json_to_bitcoin_amount(bcli->output, valuetok, &output.amount.satoshis)) {/* Raw: talking to bitcoind */
		err = tal_fmt(bcli, "%s: had bad value (%.*s)?",
			      bcli_args(bcli), (int)bcli->output_bytes,
			      bcli->output);
		return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
	}

	scriptpubkeytok = json_get_member(bcli->output, tokens, "scriptPubKey");
	if (!scriptpubkeytok) {
		err = tal_fmt(bcli, "%s: had no scriptPubKey member (%.*s)?",
			      bcli_args(bcli), (int)bcli->output_bytes,
			      bcli->output);
		return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
	}

	hextok = json_get_member(bcli->output, scriptpubkeytok, "hex");
	if (!hextok) {
		err = tal_fmt(bcli, "%s: had no scriptPubKey->hex member (%.*s)?",
			      bcli_args(bcli), (int)bcli->output_bytes,
			      bcli->output);
		return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
	}

	output.script = tal_hexdata(bcli, bcli->output + hextok->start,
	                            hextok->end - hextok->start);
	if (!output.script) {
		err = tal_fmt(bcli, "%s: scriptPubKey->hex invalid hex (%.*s)?",
			      bcli_args(bcli), (int)bcli->output_bytes,
			      bcli->output);
		return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
	}

	response = jsonrpc_stream_success(bcli->cmd);
	json_add_amount_sat_only(response, "amount", output.amount);
	json_add_string(response, "script", tal_hex(response, output.script));

	return command_finished(bcli->cmd, response);
}

static struct command_result *process_getblockchaininfo(struct bitcoin_cli *bcli)
{
	const jsmntok_t *tokens, *chaintok, *headerstok, *blockstok, *ibdtok;
	struct json_stream *response;
	bool valid, ibd;
	u32 headers, blocks;
	char *err;

	tokens = json_parse_input(bcli, bcli->output, bcli->output_bytes,
	                          &valid);
	if (!tokens) {
		err = tal_fmt(bcli->cmd, "%s: %s response (%.*s)",
			      bcli_args(bcli), valid ? "partial" : "invalid",
			      (int)bcli->output_bytes, bcli->output);
		return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
	}

	if (tokens[0].type != JSMN_OBJECT) {
		err = tal_fmt(bcli->cmd, "%s: gave non-object (%.*s)",
			      bcli_args(bcli), (int)bcli->output_bytes,
			      bcli->output);
		return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
	}

	chaintok = json_get_member(bcli->output, tokens, "chain");
	if (!chaintok) {
		err = tal_fmt(bcli->cmd, "%s: bad 'chain' field (%.*s)",
			      bcli_args(bcli), (int)bcli->output_bytes,
			      bcli->output);
		return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
	}

	headerstok = json_get_member(bcli->output, tokens, "headers");
	if (!headerstok || !json_to_number(bcli->output, headerstok, &headers)) {
		err = tal_fmt(bcli->cmd, "%s: bad 'headers' field (%.*s)",
			      bcli_args(bcli), (int)bcli->output_bytes,
			      bcli->output);
		return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
	}

	blockstok = json_get_member(bcli->output, tokens, "blocks");
	if (!blockstok || !json_to_number(bcli->output, blockstok, &blocks)) {
		err = tal_fmt(bcli->cmd, "%s: bad 'blocks' field (%.*s)",
			      bcli_args(bcli), (int)bcli->output_bytes,
			      bcli->output);
		return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
	}

	ibdtok = json_get_member(bcli->output, tokens, "initialblockdownload");
	if (!ibdtok || !json_to_bool(bcli->output, ibdtok, &ibd)) {
		err = tal_fmt(bcli->cmd, "%s: bad 'initialblockdownload' field (%.*s)",
			      bcli_args(bcli), (int)bcli->output_bytes,
			      bcli->output);
		return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
	}

	response = jsonrpc_stream_success(bcli->cmd);
	json_add_string(response, "chain",
			json_strdup(response, bcli->output, chaintok));
	json_add_u32(response, "headercount", headers);
	json_add_u32(response, "blockcount", blocks);
	json_add_bool(response, "ibd", ibd);

	return command_finished(bcli->cmd, response);
}


struct estimatefees_stash {
	/* FIXME: We use u64 but lightningd will store them as u32. */
	u64 very_urgent, urgent, normal, slow;
};

static struct command_result *
estimatefees_null_response(struct bitcoin_cli *bcli)
{
	struct json_stream *response = jsonrpc_stream_success(bcli->cmd);

	json_add_null(response, "opening");
	json_add_null(response, "mutual_close");
	json_add_null(response, "unilateral_close");
	json_add_null(response, "delayed_to_us");
	json_add_null(response, "htlc_resolution");
	json_add_null(response, "penalty");
	json_add_null(response, "min_acceptable");
	json_add_null(response, "max_acceptable");

	return command_finished(bcli->cmd, response);
}

static struct command_result *
estimatefees_parse_feerate(struct bitcoin_cli *bcli, u64 *feerate)
{
	const jsmntok_t *tokens, *feeratetok = NULL;
	bool valid;
	char *err;

	tokens = json_parse_input(bcli->output, bcli->output,
	                          (int)bcli->output_bytes, &valid);
	if (!tokens) {
		err = tal_fmt(bcli->cmd, "%s: %s response (%.*s)",
			      bcli_args(bcli), valid ? "partial" : "invalid",
			      (int)bcli->output_bytes, bcli->output);
		return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
	}

	if (tokens[0].type != JSMN_OBJECT) {
		err = tal_fmt(bcli->cmd, "%s: gave non-object (%.*s)",
			      bcli_args(bcli), (int)bcli->output_bytes,
			      bcli->output);
		return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
	}

	feeratetok = json_get_member(bcli->output, tokens, "feerate");
	if (feeratetok &&
	    !json_to_bitcoin_amount(bcli->output, feeratetok, feerate)) {
		err = tal_fmt(bcli->cmd, "%s: bad 'feerate' field (%.*s)",
			      bcli_args(bcli), (int)bcli->output_bytes,
			      bcli->output);
		return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
	} else if (!feeratetok)
		/* We return null if estimation failed, and bitcoin-cli will
		 * exit with 0 but no feerate field on failure. */
		return estimatefees_null_response(bcli);

	return NULL;
}

/* We got all the feerates, give them to lightningd. */
static struct command_result *estimatefees_final_step(struct bitcoin_cli *bcli)
{
	struct command_result *err;
	struct json_stream *response;
	struct estimatefees_stash *stash = bcli->stash;

	/* bitcoind could theoretically fail to estimate for a higher target. */
	if (*bcli->exitstatus != 0)
		return estimatefees_null_response(bcli);

	err = estimatefees_parse_feerate(bcli, &stash->slow);
	if (err)
		return err;

	response = jsonrpc_stream_success(bcli->cmd);
	json_add_u64(response, "opening", stash->normal);
	json_add_u64(response, "mutual_close", stash->normal);
	json_add_u64(response, "unilateral_close",
		     stash->very_urgent * bitcoind->commit_fee_percent / 100);
	json_add_u64(response, "delayed_to_us", stash->normal);
	json_add_u64(response, "htlc_resolution", stash->urgent);
	json_add_u64(response, "penalty", stash->urgent);
	/* We divide the slow feerate for the minimum acceptable, lightningd
	 * will use floor if it's hit, though. */
	json_add_u64(response, "min_acceptable", stash->slow / 2);
	/* BOLT #2:
	*
	* Given the variance in fees, and the fact that the transaction may be
	* spent in the future, it's a good idea for the fee payer to keep a good
	* margin (say 5x the expected fee requirement)
	*/
	json_add_u64(response, "max_acceptable",
		     stash->very_urgent * bitcoind->max_fee_multiplier);

	return command_finished(bcli->cmd, response);
}

/* We got the response for the normal feerate, now treat the slow one. */
static struct command_result *estimatefees_fourth_step(struct bitcoin_cli *bcli)
{
	struct command_result *err;
	struct estimatefees_stash *stash = bcli->stash;
	const char **params = tal_arr(bcli->cmd, const char *, 2);

	/* bitcoind could theoretically fail to estimate for a higher target. */
	if (*bcli->exitstatus != 0)
		return estimatefees_null_response(bcli);

	err = estimatefees_parse_feerate(bcli, &stash->normal);
	if (err)
		return err;

	params[0] = "100";
	params[1] = "ECONOMICAL";
	start_bitcoin_cli(NULL, bcli->cmd, estimatefees_final_step, true,
			  BITCOIND_LOW_PRIO, "estimatesmartfee", params, stash);

	return command_still_pending(bcli->cmd);
}

/* We got the response for the urgent feerate, now treat the normal one. */
static struct command_result *estimatefees_third_step(struct bitcoin_cli *bcli)
{
	struct command_result *err;
	struct estimatefees_stash *stash = bcli->stash;
	const char **params = tal_arr(bcli->cmd, const char *, 2);

	/* If we cannot estimate fees, no need to continue bothering bitcoind. */
	if (*bcli->exitstatus != 0)
		return estimatefees_null_response(bcli);

	err = estimatefees_parse_feerate(bcli, &stash->urgent);
	if (err)
		return err;

	params[0] = "4";
	params[1] = "ECONOMICAL";
	start_bitcoin_cli(NULL, bcli->cmd, estimatefees_fourth_step, true,
			  BITCOIND_LOW_PRIO, "estimatesmartfee", params, stash);

	return command_still_pending(bcli->cmd);
}

/* We got the response for the very urgent feerate, now treat the urgent one. */
static struct command_result *estimatefees_second_step(struct bitcoin_cli *bcli)
{
	struct command_result *err;
	struct estimatefees_stash *stash = bcli->stash;
	const char **params = tal_arr(bcli->cmd, const char *, 2);

	/* If we cannot estimate fees, no need to continue bothering bitcoind. */
	if (*bcli->exitstatus != 0)
		return estimatefees_null_response(bcli);

	err = estimatefees_parse_feerate(bcli, &stash->very_urgent);
	if (err)
		return err;

	params[0] = "3";
	params[1] = "CONSERVATIVE";
	start_bitcoin_cli(NULL, bcli->cmd, estimatefees_third_step, true,
			  BITCOIND_LOW_PRIO, "estimatesmartfee", params, stash);

	return command_still_pending(bcli->cmd);
}


static struct command_result *process_sendrawtransaction(struct bitcoin_cli *bcli)
{
	struct json_stream *response;

	/* This is useful for functional tests. */
	if (*bcli->exitstatus == 0)
		plugin_log(bcli->cmd->plugin, LOG_DBG, "sendrawtx exit %i (%s)",
			   *bcli->exitstatus, bcli_args(bcli));

	response = jsonrpc_stream_success(bcli->cmd);
	json_add_bool(response, "success", *bcli->exitstatus == 0);
	json_add_string(response, "errmsg",
			bcli->exitstatus ? tal_strndup(bcli, bcli->output,
						       bcli->output_bytes-1) : "");

	return command_finished(bcli->cmd, response);
}

struct getrawblock_stash {
	const char *block_hash;
	u32 block_height;
	const char *block_hex;
};

static struct command_result *process_getrawblock(struct bitcoin_cli *bcli)
{
	struct json_stream *response;
	struct getrawblock_stash *stash = bcli->stash;

	/* -1 to strip \n. */
	stash->block_hex = tal_fmt(stash, "%.*s",
	                           (int)bcli->output_bytes-1, bcli->output);

	response = jsonrpc_stream_success(bcli->cmd);
	json_add_string(response, "blockhash", stash->block_hash);
	json_add_string(response, "block", stash->block_hex);

	return command_finished(bcli->cmd, response);
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

static struct command_result *process_getblockhash(struct bitcoin_cli *bcli)
{
	const char *err, **params;
	struct getrawblock_stash *stash = bcli->stash;

	/* If it failed with error 8, give an empty response. */
	if (bcli->exitstatus && *bcli->exitstatus != 0) {
		/* Other error means we have to retry. */
		if (*bcli->exitstatus != 8)
			return NULL;
		return getrawblockbyheight_notfound(bcli);
	}

	/* `-1` to strip the newline character. */
	stash->block_hash = tal_strndup(stash, bcli->output,
					bcli->output_bytes-1);
	if (!stash->block_hash || strlen(stash->block_hash) != 64) {
		err = tal_fmt(bcli->cmd, "%s: bad blockhash '%s'",
			      bcli_args(bcli), stash->block_hash);
		return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
	}

	params = tal_arr(bcli->cmd, const char *, 2);
	params[0] = stash->block_hash;
	/* Non-verbose: raw block. */
	params[1] = "0";
	start_bitcoin_cli(NULL, bcli->cmd, process_getrawblock, false,
			  BITCOIND_HIGH_PRIO, "getblock", params, stash);

	return command_still_pending(bcli->cmd);
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
	const char **params;

	/* bitcoin-cli wants a string. */
	if (!param(cmd, buf, toks,
	           p_req("height", param_number, &height),
	           NULL))
		return command_param_failed();

	stash = tal(cmd, struct getrawblock_stash);
	stash->block_height = *height;

	params = tal_arr(cmd, const char *, 1);
	params[0] = tal_fmt(params, "%u", *height);
	start_bitcoin_cli(NULL, cmd, process_getblockhash, true,
			  BITCOIND_LOW_PRIO, "getblockhash", params, stash);

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
	if (!param(cmd, buf, toks, NULL))
	    return command_param_failed();

	start_bitcoin_cli(NULL, cmd, process_getblockchaininfo, false,
			  BITCOIND_HIGH_PRIO, "getblockchaininfo", NULL, NULL);

	return command_still_pending(cmd);
}

/* Get the current feerates. We use an urgent feerate for unilateral_close and max,
 * a slightly less urgent feerate for htlc_resolution and penalty transactions,
 * a slow feerate for min, and a normal one for all others.
 *
 * Calls `estimatesmartfee` with targets 2/CONSERVATIVE (very urgent),
 * 3/CONSERVATIVE (urgent), 4/ECONOMICAL (normal), and 100/ECONOMICAL (slow)
 * then returns the feerates as sat/kVB.
 */
static struct command_result *estimatefees(struct command *cmd,
					   const char *buf UNUSED,
					   const jsmntok_t *toks UNUSED)
{
	struct estimatefees_stash *stash = tal(cmd, struct estimatefees_stash);
	const char **params = tal_arr(cmd, const char *, 2);

	if (!param(cmd, buf, toks, NULL))
	    return command_param_failed();

	/* First call to estimatesmartfee, for very urgent estimation (unilateral
	 * and max_acceptable feerates). */
	params[0] = "2";
	params[1] = "CONSERVATIVE";
	start_bitcoin_cli(NULL, cmd, estimatefees_second_step, true,
			  BITCOIND_LOW_PRIO, "estimatesmartfee", params, stash);

	return command_still_pending(cmd);
}

/* Send a transaction to the Bitcoin network.
 * Calls `sendrawtransaction` using the first parameter as the raw tx.
 */
static struct command_result *sendrawtransaction(struct command *cmd,
                                                 const char *buf,
                                                 const jsmntok_t *toks)
{
	const char **params = tal_arr(cmd, const char *, 1);

	/* bitcoin-cli wants strings. */
	if (!param(cmd, buf, toks,
	           p_req("tx", param_string, &params[0]),
	           NULL))
		return command_param_failed();

	start_bitcoin_cli(NULL, cmd, process_sendrawtransaction, true,
			  BITCOIND_HIGH_PRIO, "sendrawtransaction", params, NULL);

	return command_still_pending(cmd);
}

static struct command_result *getutxout(struct command *cmd,
                                       const char *buf,
                                       const jsmntok_t *toks)
{
	const char **params = tal_arr(cmd, const char *, 2);

	/* bitcoin-cli wants strings. */
	if (!param(cmd, buf, toks,
	           p_req("txid", param_string, &params[0]),
	           p_req("vout", param_string, &params[1]),
	           NULL))
		return command_param_failed();

	start_bitcoin_cli(NULL, cmd, process_getutxout, true,
			  BITCOIND_HIGH_PRIO, "gettxout", params, NULL);

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

static void wait_for_bitcoind(struct plugin *p)
{
	int from, status, ret;
	pid_t child;
	const char **cmd = gather_args(bitcoind, "echo", NULL);
	bool printed = false;

	for (;;) {
		child = pipecmdarr(NULL, &from, &from, cast_const2(char **,cmd));
		if (child < 0) {
			if (errno == ENOENT)
				bitcoind_failure(p, "bitcoin-cli not found. Is bitcoin-cli "
						    "(part of Bitcoin Core) available in your PATH?");
			plugin_err(p, "%s exec failed: %s", cmd[0], strerror(errno));
		}

		char *output = grab_fd(cmd, from);

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
	tal_free(cmd);
}

static void init(struct plugin *p, const char *buffer UNUSED,
                 const jsmntok_t *config UNUSED)
{
	wait_for_bitcoind(p);
	plugin_log(p, LOG_INFORM,
		   "bitcoin-cli initialized and connected to bitcoind.");
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
		"Get informations about an output, identified by a {txid} an a {vout}",
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
	bitcoind->error_count = 0;
	bitcoind->retry_timeout = 60;
	bitcoind->rpcuser = NULL;
	bitcoind->rpcpass = NULL;
	bitcoind->rpcconnect = NULL;
	bitcoind->rpcport = NULL;
	bitcoind->max_fee_multiplier = 10;
	bitcoind->commit_fee_percent = 100;

	return bitcoind;
}

int main(int argc, char *argv[])
{
	setup_locale();

	/* Initialize our global context object here to handle startup options. */
	bitcoind = new_bitcoind(NULL);

	plugin_main(argv, init, PLUGIN_STATIC, false /* Do not init RPC on startup*/,
		    NULL, commands, ARRAY_SIZE(commands),
		    NULL, 0, NULL, 0,
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
				  "string",
				  "bitcoind RPC host's port",
				  charp_option, &bitcoind->rpcport),
		    plugin_option("bitcoin-retry-timeout",
				  "string",
				  "how long to keep retrying to contact bitcoind"
				  " before fatally exiting",
				  u64_option, &bitcoind->retry_timeout),
		    plugin_option("commit-fee",
				  "string",
				  "Percentage of fee to request for their commitment",
				  u64_option, &bitcoind->commit_fee_percent),
#if DEVELOPER
		    plugin_option("dev-max-fee-multiplier",
				  "string",
				  "Allow the fee proposed by the remote end to"
				  " be up to multiplier times higher than our "
				  "own. Small values will cause channels to be"
				  " closed more often due to fee fluctuations,"
				  " large values may result in large fees.",
				  u32_option, &bitcoind->max_fee_multiplier),
#endif /* DEVELOPER */
		    NULL);
}
