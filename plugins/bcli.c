#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <errno.h>
#include <inttypes.h>
#include <plugins/libplugin.h>
#include <unistd.h>

#define RPC_TRANSACTION_ALREADY_IN_CHAIN -27

struct bitcoind {
	/* eg. "bitcoin-cli" */
	char *cli;

	/* -datadir arg for bitcoin-cli. */
	char *datadir;

	/* bitcoind's version, used for compatibility checks. */
	u32 version;

	/* How long to keep trying to contact bitcoind
	 * before fatally exiting. */
	u64 retry_timeout;

	/* Passthrough parameters for bitcoin-cli */
	char *rpcuser, *rpcpass, *rpcconnect, *rpcport;
	u64 rpcclienttimeout;

	/* Whether we fake fees (regtest) */
	bool fake_fees;

	/* Override in case we're developer mode for testing*/
	bool dev_no_fake_fees;

	/* Override initialblockdownload (using canned blocks sets this) */
	bool dev_ignore_ibd;
};

static struct bitcoind *bitcoind;

/* Result of a synchronous bitcoin-cli call */
struct bcli_result {
	char *output;
	size_t output_len;
	int exitstatus;
	/* Command args string for error messages */
	const char *args;
};

/* Add the n'th arg to *args, incrementing n and keeping args of size n+1 */
static void add_arg(const char ***args, const char *arg TAKES)
{
	if (taken(arg))
		tal_steal(*args, arg);
	tal_arr_expand(args, arg);
}

/* If stdinargs is non-NULL, that is where we put additional args */
static const char **gather_argsv(const tal_t *ctx, const char ***stdinargs, const char *cmd, va_list ap)
{
	const char **args = tal_arr(ctx, const char *, 1);
	const char *arg;

	args[0] = bitcoind->cli ? bitcoind->cli : chainparams->cli;
	if (chainparams->cli_args)
		add_arg(&args, chainparams->cli_args);
	if (bitcoind->datadir)
		add_arg(&args, tal_fmt(args, "-datadir=%s", bitcoind->datadir));
	if (bitcoind->rpcclienttimeout) {
		/* Use the maximum value of rpcclienttimeout and retry_timeout to avoid
		   the bitcoind backend hanging for too long. */
		if (bitcoind->retry_timeout &&
		    bitcoind->retry_timeout > bitcoind->rpcclienttimeout)
			bitcoind->rpcclienttimeout = bitcoind->retry_timeout;

		add_arg(&args,
			tal_fmt(args, "-rpcclienttimeout=%"PRIu64, bitcoind->rpcclienttimeout));
	}
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
	/* To avoid giant command lines, we use -stdin (avail since bitcoin 0.13) */
	if (stdinargs)
		add_arg(&args, "-stdin");

	add_arg(&args, cmd);
	while ((arg = va_arg(ap, char *)) != NULL) {
		if (stdinargs)
			add_arg(stdinargs, arg);
		else
			add_arg(&args, arg);
	}
	add_arg(&args, NULL);

	return args;
}

static LAST_ARG_NULL const char **
gather_args(const tal_t *ctx, const char ***stdinargs, const char *cmd, ...)
{
	va_list ap;
	const char **ret;

	va_start(ap, cmd);
	ret = gather_argsv(ctx, stdinargs, cmd, ap);
	va_end(ap);

	return ret;
}

/* For printing: simple string of args (no secrets!) */
static char *args_string(const tal_t *ctx, const char **args, const char **stdinargs)
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
	for (i = 0; i < tal_count(stdinargs); i++) {
		ret = tal_strcat(ctx, take(ret), " ");
		ret = tal_strcat(ctx, take(ret), stdinargs[i]);
	}
	return ret;
}

/* Synchronous execution of bitcoin-cli.
 * Returns result with output and exit status. */
static struct bcli_result *
run_bitcoin_cliv(const tal_t *ctx,
		 struct plugin *plugin,
		 const char *method,
		 va_list ap)
{
	int in, from, status;
	pid_t child;
	const char **stdinargs;
	const char **cmd;
	struct bcli_result *res;

	stdinargs = tal_arr(ctx, const char *, 0);
	cmd = gather_argsv(ctx, &stdinargs, method, ap);

	child = pipecmdarr(&in, &from, &from, cast_const2(char **, cmd));
	if (child < 0)
		plugin_err(plugin, "%s exec failed: %s", cmd[0], strerror(errno));

	/* Send rpcpass via stdin if configured */
	if (bitcoind->rpcpass) {
		write_all(in, bitcoind->rpcpass, strlen(bitcoind->rpcpass));
		write_all(in, "\n", 1);
	}
	/* Send any additional stdin args */
	for (size_t i = 0; i < tal_count(stdinargs); i++) {
		write_all(in, stdinargs[i], strlen(stdinargs[i]));
		write_all(in, "\n", 1);
	}
	close(in);

	/* Read all output until EOF */
	res = tal(ctx, struct bcli_result);
	res->output = grab_fd_str(res, from);
	res->output_len = strlen(res->output);
	res->args = args_string(res, cmd, stdinargs);
	close(from);

	/* Wait for child to exit */
	while (waitpid(child, &status, 0) < 0) {
		if (errno == EINTR)
			continue;
		plugin_err(plugin, "waitpid(%s) failed: %s",
			   res->args, strerror(errno));
	}

	if (!WIFEXITED(status))
		plugin_err(plugin, "%s died with signal %i",
			   res->args, WTERMSIG(status));

	res->exitstatus = WEXITSTATUS(status);

	return res;
}

static LAST_ARG_NULL struct bcli_result *
run_bitcoin_cli(const tal_t *ctx,
		struct plugin *plugin,
		const char *method, ...)
{
	va_list ap;
	struct bcli_result *res;

	va_start(ap, method);
	res = run_bitcoin_cliv(ctx, plugin, method, ap);
	va_end(ap);

	return res;
}

static void strip_trailing_whitespace(char *str, size_t len)
{
	size_t stripped_len = len;
	while (stripped_len > 0 && cisspace(str[stripped_len-1]))
		stripped_len--;

	str[stripped_len] = 0x00;
}

static struct command_result *command_err(struct command *cmd,
					  struct bcli_result *res,
					  const char *errmsg)
{
	char *err = tal_fmt(cmd, "%s: %s (%.*s)",
			    res->args, errmsg, (int)res->output_len, res->output);
	return command_done_err(cmd, BCLI_ERROR, err, NULL);
}

/* Don't use this in general: it's better to omit fields. */
static void json_add_null(struct json_stream *stream, const char *fieldname)
{
	json_add_primitive(stream, fieldname, "null");
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

static struct command_result *
estimatefees_null_response(struct command *cmd)
{
	struct json_stream *response = jsonrpc_stream_success(cmd);

	/* We give a floor, which is the standard minimum */
	json_array_start(response, "feerates");
	json_array_end(response);
	json_add_u32(response, "feerate_floor", 1000);

	return command_finished(cmd, response);
}

static struct command_result *
getrawblockbyheight_notfound(struct command *cmd)
{
	struct json_stream *response;

	response = jsonrpc_stream_success(cmd);
	json_add_null(response, "blockhash");
	json_add_null(response, "block");

	return command_finished(cmd, response);
}

/* Get peers that support NODE_NETWORK (full nodes).
 * Returns array of peer ids, or empty array if none found. */
static int *get_fullnode_peers(const tal_t *ctx, struct command *cmd)
{
	struct bcli_result *res;
	const jsmntok_t *t, *toks;
	int *peers = tal_arr(ctx, int, 0);
	size_t i;

	res = run_bitcoin_cli(cmd, cmd->plugin, "getpeerinfo", NULL);
	if (res->exitstatus != 0)
		return peers;

	toks = json_parse_simple(res->output, res->output, res->output_len);
	if (!toks)
		return peers;

	json_for_each_arr(i, t, toks) {
		int id;
		u8 *services;

		if (json_scan(tmpctx, res->output, t, "{id:%,services:%}",
			      JSON_SCAN(json_to_int, &id),
			      JSON_SCAN_TAL(tmpctx, json_tok_bin_from_hex, &services)) == NULL) {
			/* From bitcoin source:
			 *  NODE_NETWORK means that the node is capable of serving the complete block chain.
			 *  It is currently set by all Bitcoin Core non pruned nodes, and is unset by SPV
			 *  clients or other light clients.
			 * NODE_NETWORK = (1 << 0)
			 */
			if (tal_count(services) > 0 && (services[tal_count(services)-1] & (1 << 0)))
				tal_arr_expand(&peers, id);
		}
	}

	return peers;
}

/* Get a raw block given its height.
 * Calls `getblockhash` then `getblock` to retrieve it from bitcoin_cli.
 * Will return early with null fields if block isn't known (yet).
 */
static struct command_result *getrawblockbyheight(struct command *cmd,
                                                  const char *buf,
                                                  const jsmntok_t *toks)
{
	struct bcli_result *res;
	struct json_stream *response;
	const char *block_hash;
	u32 *height;
	struct timemono first_error_time;
	bool first_error = true;
	int *peers = NULL;

	if (!param(cmd, buf, toks,
	           p_req("height", param_number, &height),
	           NULL))
		return command_param_failed();

	res = run_bitcoin_cli(cmd, cmd->plugin, "getblockhash",
			      tal_fmt(tmpctx, "%u", *height), NULL);

	if (res->exitstatus != 0) {
		/* Exit code 8 means block height doesn't exist (empty response) */
		if (res->exitstatus == 8)
			return getrawblockbyheight_notfound(cmd);
		return command_err(cmd, res, "command failed");
	}

	strip_trailing_whitespace(res->output, res->output_len);
	if (strlen(res->output) != 64)
		return command_err(cmd, res, "bad JSON: bad blockhash");

	block_hash = tal_strdup(cmd, res->output);

	for (;;) {
		res = run_bitcoin_cli(cmd, cmd->plugin, "getblock",
				      block_hash, "0", NULL);

		if (res->exitstatus == 0) {
			strip_trailing_whitespace(res->output, res->output_len);
			response = jsonrpc_stream_success(cmd);
			json_add_string(response, "blockhash", block_hash);
			json_add_string(response, "block", res->output);
			return command_finished(cmd, response);
		}

		plugin_log(cmd->plugin, LOG_DBG,
			"failed to fetch block %s from the bitcoin backend (maybe pruned).",
			block_hash);

		if (first_error) {
			first_error_time = time_mono();
			first_error = false;
		}

		struct timerel elapsed = timemono_between(time_mono(), first_error_time);
		if (time_greater(elapsed, time_from_sec(bitcoind->retry_timeout))) {
			return command_done_err(cmd, BCLI_ERROR,
				tal_fmt(cmd, "getblock %s timed out after %"PRIu64" seconds",
					block_hash, bitcoind->retry_timeout), NULL);
		}

		/* Try fetching from peers if bitcoind >= 23.0.0 */
		if (bitcoind->version >= 230000) {
			if (!peers)
				peers = get_fullnode_peers(cmd, cmd);

			if (tal_count(peers) > 0) {
				int peer = peers[tal_count(peers) - 1];
				tal_resize(&peers, tal_count(peers) - 1);

				res = run_bitcoin_cli(cmd, cmd->plugin,
						      "getblockfrompeer",
						      block_hash,
						      tal_fmt(tmpctx, "%i", peer),
						      NULL);

				if (res->exitstatus != 0) {
					/* We still continue with the execution if we cannot fetch the
					 * block from peer */
					plugin_log(cmd->plugin, LOG_DBG,
						   "failed to fetch block %s from peer %i, skip.",
						   block_hash, peer);
				} else {
					plugin_log(cmd->plugin, LOG_DBG,
						   "try to fetch block %s from peer %i.",
						   block_hash, peer);
				}
			}

			if (tal_count(peers) == 0) {
				plugin_log(cmd->plugin, LOG_DBG,
					   "asked all known peers about block %s, retry",
					   block_hash);
				peers = tal_free(peers);
			}
		}

		sleep(1);
	}
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
	struct bcli_result *res;
	const jsmntok_t *tokens;
	struct json_stream *response;
	bool ibd;
	u32 headers, blocks;
	const char *chain, *err;

	if (!param(cmd, buf, toks,
		   p_opt("last_height", param_number, &height),
		   NULL))
		return command_param_failed();

	res = run_bitcoin_cli(cmd, cmd->plugin, "getblockchaininfo", NULL);
	if (res->exitstatus != 0)
		return command_err(cmd, res, "command failed");

	tokens = json_parse_simple(res->output, res->output, res->output_len);
	if (!tokens)
		return command_err(cmd, res, "bad JSON: cannot parse");

	err = json_scan(tmpctx, res->output, tokens,
			"{chain:%,headers:%,blocks:%,initialblockdownload:%}",
			JSON_SCAN_TAL(tmpctx, json_strdup, &chain),
			JSON_SCAN(json_to_number, &headers),
			JSON_SCAN(json_to_number, &blocks),
			JSON_SCAN(json_to_bool, &ibd));
	if (err)
		return command_err(cmd, res, tal_fmt(tmpctx, "bad JSON: %s", err));

	if (bitcoind->dev_ignore_ibd)
		ibd = false;

	response = jsonrpc_stream_success(cmd);
	json_add_string(response, "chain", chain);
	json_add_u32(response, "headercount", headers);
	json_add_u32(response, "blockcount", blocks);
	json_add_bool(response, "ibd", ibd);

	return command_finished(cmd, response);
}

/* Add a feerate, but don't publish one that bitcoind won't accept. */
static void json_add_feerate(struct json_stream *result, const char *fieldname,
			     struct command *cmd,
			     u64 perkb_floor,
			     u64 value)
{
	/* Anthony Towns reported signet had a 900kbtc fee block, and then
	 * CLN got upset scanning feerate.  It expects a u32. */
	if (value > 0xFFFFFFFF) {
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "Feerate %"PRIu64" is ridiculous: trimming to 32 bits",
			   value);
		value = 0xFFFFFFFF;
	}
	/* 0 is special, it means "unknown" */
	if (value && value < perkb_floor) {
		plugin_log(cmd->plugin, LOG_DBG,
			   "Feerate %s raised from %"PRIu64
			   " perkb to floor of %"PRIu64,
			   fieldname, value, perkb_floor);
		json_add_u64(result, fieldname, perkb_floor);
	} else {
		json_add_u64(result, fieldname, value);
	}
}

/* Get the feerate floor from getmempoolinfo.
 * Returns NULL on success (floor stored in *perkb_floor), or error response. */
static struct command_result *get_feerate_floor(struct command *cmd,
						u64 *perkb_floor)
{
	struct bcli_result *res;
	const jsmntok_t *tokens;
	const char *err;
	u64 mempoolfee, relayfee;

	res = run_bitcoin_cli(cmd, cmd->plugin, "getmempoolinfo", NULL);
	if (res->exitstatus != 0)
		return estimatefees_null_response(cmd);

	tokens = json_parse_simple(res->output, res->output, res->output_len);
	if (!tokens)
		return command_err(cmd, res, "bad JSON: cannot parse");

	err = json_scan(tmpctx, res->output, tokens,
			"{mempoolminfee:%,minrelaytxfee:%}",
			JSON_SCAN(json_to_bitcoin_amount, &mempoolfee),
			JSON_SCAN(json_to_bitcoin_amount, &relayfee));
	if (err)
		return command_err(cmd, res, tal_fmt(tmpctx, "bad JSON: %s", err));

	*perkb_floor = max_u64(mempoolfee, relayfee);
	return NULL;
}

/* Get a single feerate from estimatesmartfee.
 * Returns NULL on success (feerate stored in *perkb), or error response. */
static struct command_result *get_feerate(struct command *cmd,
					  u32 blocks,
					  const char *style,
					  u64 *perkb)
{
	struct bcli_result *res;
	const jsmntok_t *tokens;

	res = run_bitcoin_cli(cmd, cmd->plugin, "estimatesmartfee",
			      tal_fmt(tmpctx, "%u", blocks), style, NULL);

	if (res->exitstatus != 0)
		return estimatefees_null_response(cmd);

	tokens = json_parse_simple(res->output, res->output, res->output_len);
	if (!tokens)
		return command_err(cmd, res, "bad JSON: cannot parse");

	if (json_scan(tmpctx, res->output, tokens, "{feerate:%}",
		      JSON_SCAN(json_to_bitcoin_amount, perkb)) != NULL) {
		/* Paranoia: if it had a feerate, but was malformed: */
		if (json_get_member(res->output, tokens, "feerate"))
			return command_err(cmd, res, "bad JSON: cannot scan");
		/* Regtest fee estimation is generally awful: Fake it at min. */
		if (bitcoind->fake_fees)
			*perkb = 1000;
		else
			/* We return null if estimation failed, and bitcoin-cli will
			 * exit with 0 but no feerate field on failure. */
			return estimatefees_null_response(cmd);
	}

	return NULL;
}

/* Get the current feerates. We use an urgent feerate for unilateral_close and max,
 * a slightly less urgent feerate for htlc_resolution and penalty transactions,
 * a slow feerate for min, and a normal one for all others.
 */
static struct command_result *estimatefees(struct command *cmd,
					   const char *buf UNUSED,
					   const jsmntok_t *toks UNUSED)
{
	struct command_result *err;
	u64 perkb_floor = 0;
	u64 perkb[ARRAY_SIZE(estimatefee_params)];
	struct json_stream *response;

	if (!param(cmd, buf, toks, NULL))
		return command_param_failed();

	err = get_feerate_floor(cmd, &perkb_floor);
	if (err)
		return err;

	for (size_t i = 0; i < ARRAY_SIZE(estimatefee_params); i++) {
		err = get_feerate(cmd, estimatefee_params[i].blocks,
				  estimatefee_params[i].style, &perkb[i]);
		if (err)
			return err;
	}

	response = jsonrpc_stream_success(cmd);
	json_array_start(response, "feerates");
	for (size_t i = 0; i < ARRAY_SIZE(perkb); i++) {
		if (!perkb[i])
			continue;
		json_object_start(response, NULL);
		json_add_u32(response, "blocks", estimatefee_params[i].blocks);
		json_add_feerate(response, "feerate", cmd, perkb_floor, perkb[i]);
		json_object_end(response);
	}
	json_array_end(response);
	json_add_u64(response, "feerate_floor", perkb_floor);
	return command_finished(cmd, response);
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
	struct bcli_result *res;
	struct json_stream *response;

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

	res = run_bitcoin_cli(cmd, cmd->plugin,
			      "sendrawtransaction", tx, highfeesarg, NULL);

	/* This is useful for functional tests. */
	plugin_log(cmd->plugin, LOG_DBG,
		   "sendrawtx exit %i (%s) %.*s",
		   res->exitstatus, res->args,
		   res->exitstatus ? (int)res->output_len : 0,
		   res->output);

	response = jsonrpc_stream_success(cmd);
	json_add_bool(response, "success",
		      res->exitstatus == 0 ||
			  res->exitstatus == RPC_TRANSACTION_ALREADY_IN_CHAIN);
	json_add_string(response, "errmsg",
			res->exitstatus ?
			tal_strndup(cmd, res->output, res->output_len)
			: "");

	return command_finished(cmd, response);
}

static struct command_result *getutxout(struct command *cmd,
                                       const char *buf,
                                       const jsmntok_t *toks)
{
	const char *txid, *vout;
	struct bcli_result *res;
	const jsmntok_t *tokens;
	struct json_stream *response;
	struct bitcoin_tx_output output;
	const char *err;

	/* bitcoin-cli wants strings. */
	if (!param(cmd, buf, toks,
	           p_req("txid", param_string, &txid),
	           p_req("vout", param_string, &vout),
	           NULL))
		return command_param_failed();

	res = run_bitcoin_cli(cmd, cmd->plugin, "gettxout", txid, vout, NULL);

	/* As of at least v0.15.1.0, bitcoind returns "success" but an empty
	   string on a spent txout. */
	if (res->exitstatus != 0 || res->output_len == 0) {
		response = jsonrpc_stream_success(cmd);
		json_add_null(response, "amount");
		json_add_null(response, "script");
		return command_finished(cmd, response);
	}

	tokens = json_parse_simple(res->output, res->output, res->output_len);
	if (!tokens)
		return command_err(cmd, res, "bad JSON: cannot parse");

	err = json_scan(tmpctx, res->output, tokens,
		       "{value:%,scriptPubKey:{hex:%}}",
		       JSON_SCAN(json_to_bitcoin_amount,
				 &output.amount.satoshis), /* Raw: bitcoind */
		       JSON_SCAN_TAL(cmd, json_tok_bin_from_hex,
				     &output.script));
	if (err)
		return command_err(cmd, res, tal_fmt(tmpctx, "bad JSON: %s", err));

	response = jsonrpc_stream_success(cmd);
	json_add_sats(response, "amount", output.amount);
	json_add_string(response, "script", tal_hex(response, output.script));

	return command_finished(cmd, response);
}

static void bitcoind_failure(struct plugin *p, const char *error_message)
{
	const char **cmd = gather_args(bitcoind, NULL, "echo", NULL);
	plugin_err(p, "\n%s\n\n"
		      "Make sure you have bitcoind running and that bitcoin-cli"
		      " is able to connect to bitcoind.\n\n"
		      "You can verify that your Bitcoin Core installation is"
		      " ready for use by running:\n\n"
		      "    $ %s 'hello world'\n", error_message,
		   args_string(cmd, cmd, NULL));
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
			   args_string(tmpctx, gather_args(bitcoind, NULL, "getnetworkinfo", NULL), NULL),
			   buf);

	/* Check that we have a fully-featured `estimatesmartfee`. */
	err = json_scan(tmpctx, buf, result, "{version:%,localrelay:%}",
			JSON_SCAN(json_to_u32, &bitcoind->version),
			JSON_SCAN(json_to_bool, &tx_relay));
	if (err)
		plugin_err(p, "%s.  Got '%.*s'. Can not"
			   " continue without proceeding to sanity checks.",
			   err,
			   json_tok_full_len(result), json_tok_full(buf, result));

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
	int in, from, status;
	pid_t child;
	const char **cmd = gather_args(
	    bitcoind, NULL, "-rpcwait", "-rpcwaittimeout=30", "getnetworkinfo", NULL);
	char *output = NULL;

	child = pipecmdarr(&in, &from, &from, cast_const2(char **, cmd));

	if (bitcoind->rpcpass)
		write_all(in, bitcoind->rpcpass, strlen(bitcoind->rpcpass));

	close(in);

	if (child < 0) {
		if (errno == ENOENT)
			bitcoind_failure(
			    p,
			    "bitcoin-cli not found. Is bitcoin-cli "
			    "(part of Bitcoin Core) available in your PATH?");
		plugin_err(p, "%s exec failed: %s", cmd[0], strerror(errno));
	}

	output = grab_fd_str(cmd, from);
	close(from);

	waitpid(child, &status, 0);

	if (!WIFEXITED(status))
		bitcoind_failure(p, tal_fmt(bitcoind, "Death of %s: signal %i",
					    cmd[0], WTERMSIG(status)));

	if (WEXITSTATUS(status) != 0) {
		if (WEXITSTATUS(status) == 1)
			bitcoind_failure(p,
					 "RPC connection timed out. Could "
					 "not connect to bitcoind using "
					 "bitcoin-cli. Is bitcoind running?");
		bitcoind_failure(p,
				 tal_fmt(bitcoind, "%s exited with code %i: %s",
					 cmd[0], WEXITSTATUS(status), output));
	}

	parse_getnetworkinfo_result(p, output);

	tal_free(cmd);
}

static void memleak_mark_bitcoind(struct plugin *p, struct htable *memtable)
{
	memleak_scan_obj(memtable, bitcoind);
}

static const char *init(struct command *init_cmd, const char *buffer UNUSED,
			const jsmntok_t *config UNUSED)
{
	wait_and_check_bitcoind(init_cmd->plugin);

	/* Usually we fake up fees in regtest */
	if (streq(chainparams->network_name, "regtest"))
		bitcoind->fake_fees = !bitcoind->dev_no_fake_fees;
	else
		bitcoind->fake_fees = false;

	plugin_set_memleak_handler(init_cmd->plugin, memleak_mark_bitcoind);
	plugin_log(init_cmd->plugin, LOG_INFORM,
		   "bitcoin-cli initialized and connected to bitcoind.");

	return NULL;
}

static const struct plugin_command commands[] = {
	{
		"getrawblockbyheight",
		getrawblockbyheight
	},
	{
		"getchaininfo",
		getchaininfo
	},
	{
		"estimatefees",
		estimatefees
	},
	{
		"sendrawtransaction",
		sendrawtransaction
	},
	{
		"getutxout",
		getutxout
	},
};

static struct bitcoind *new_bitcoind(const tal_t *ctx)
{
	bitcoind = tal(ctx, struct bitcoind);

	bitcoind->cli = NULL;
	bitcoind->datadir = NULL;
	bitcoind->retry_timeout = 60;
	bitcoind->rpcuser = NULL;
	bitcoind->rpcpass = NULL;
	bitcoind->rpcconnect = NULL;
	bitcoind->rpcport = NULL;
	/* Do not exceed retry_timeout value to avoid a bitcoind hang,
	   although normal rpcclienttimeout default value is 900. */
	bitcoind->rpcclienttimeout = 60;
	bitcoind->dev_no_fake_fees = false;
	bitcoind->dev_ignore_ibd = false;

	return bitcoind;
}

int main(int argc, char *argv[])
{
	setup_locale();

	/* Initialize our global context object here to handle startup options. */
	bitcoind = new_bitcoind(NULL);

	plugin_main(argv, init, NULL, PLUGIN_STATIC, false /* Do not init RPC on startup*/,
		    NULL, commands, ARRAY_SIZE(commands),
		    NULL, 0, NULL, 0, NULL, 0,
		    plugin_option("bitcoin-datadir",
				  "string",
				  "-datadir arg for bitcoin-cli",
				  charp_option, NULL, &bitcoind->datadir),
		    plugin_option("bitcoin-cli",
				  "string",
				  "bitcoin-cli pathname",
				  charp_option, NULL, &bitcoind->cli),
		    plugin_option("bitcoin-rpcuser",
				  "string",
				  "bitcoind RPC username",
				  charp_option, NULL, &bitcoind->rpcuser),
		    plugin_option("bitcoin-rpcpassword",
				  "string",
				  "bitcoind RPC password",
				  charp_option, NULL, &bitcoind->rpcpass),
		    plugin_option("bitcoin-rpcconnect",
				  "string",
				  "bitcoind RPC host to connect to",
				  charp_option, NULL, &bitcoind->rpcconnect),
		    plugin_option("bitcoin-rpcport",
				  "int",
				  "bitcoind RPC host's port",
				  charp_option, NULL, &bitcoind->rpcport),
		    plugin_option("bitcoin-rpcclienttimeout",
				  "int",
				  "bitcoind RPC timeout in seconds during HTTP requests",
				  u64_option, u64_jsonfmt, &bitcoind->rpcclienttimeout),
		    plugin_option("bitcoin-retry-timeout",
				  "int",
				  "how long to keep retrying to contact bitcoind"
				  " before fatally exiting",
				  u64_option, u64_jsonfmt, &bitcoind->retry_timeout),
		    plugin_option_dev("dev-no-fake-fees",
				      "bool",
				      "Suppress fee faking for regtest",
				      bool_option, NULL, &bitcoind->dev_no_fake_fees),
		    plugin_option_dev("dev-ignore-ibd",
				      "bool",
				      "Never tell lightningd we're doing initial block download",
				      bool_option, NULL, &bitcoind->dev_ignore_ibd),
		    NULL);
}
