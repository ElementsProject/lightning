/* Code for talking to bitcoind. */
#include "bitcoin/base58.h"
#include "bitcoin/block.h"
#include "bitcoin/feerate.h"
#include "bitcoin/shadouble.h"
#include "bitcoind.h"
#include "lightningd.h"
#include "log.h"
#include <ccan/cast/cast.h>
#include <ccan/io/backend.h>
#include <ccan/io/io.h>
#include <ccan/io/io_plan.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/str/hex/hex.h>
#include <ccan/take/take.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/json.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <common/utils.h>
#include <errno.h>
#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>
#include <inttypes.h>
#include <lightningd/bitcoin_rpc.h>
#include <lightningd/chaintopology.h>



/* Bitcoind's web server has a default of 4 threads, with queue depth 16.
 * It will *fail* rather than queue beyond that, so we must not stress it!
 *
 * This is how many request for each priority level we have.
 */
#define BITCOIND_MAX_PARALLEL 4

#define DEFAULT_RPCCONNECT "127.0.0.1"

static void next_brpc(struct bitcoind *bitcoind, enum bitcoind_prio prio);

/* For printing: simple string of args. */

static void retry_brpc(struct bitcoin_rpc *brpc)
{
	list_add_tail(&brpc->bitcoind->pending[brpc->prio], &brpc->list);
	next_brpc(brpc->bitcoind, brpc->prio);
}

/* We allow 60 seconds of spurious errors, eg. reorg. */
static void brpc_failure(struct bitcoind *bitcoind, struct bitcoin_rpc *brpc,
			 int exitstatus)
{
	struct timerel t;

	if (!bitcoind->error_count)
		bitcoind->first_error_time = time_mono();

	t = timemono_between(time_mono(), bitcoind->first_error_time);
	if (time_greater(t, time_from_sec(60)))
		fatal("%s exited %u (after %u other errors)\n", brpc->cmd,
		      exitstatus, bitcoind->error_count);

	log_unusual(bitcoind->log, "%s exited with status %u", brpc->cmd,
		    exitstatus);

	bitcoind->error_count++;

	/* reset rpc status */
	brpc->finished = false;
	brpc->exitstatus = RPC_FAIL;
	brpc->errorcode = 0;

	/* Retry in 1 second (not a leak!) */
	notleak(new_reltimer(&bitcoind->ld->timers, brpc, time_from_sec(1),
			     retry_brpc, brpc));
}

static void brpc_finished(struct bitcoin_rpc *brpc)
{
	struct bitcoind *bitcoind = brpc->bitcoind;
	enum bitcoind_prio prio = brpc->prio;
	bool ok;
	u64 msec = time_to_msec(time_between(time_now(), brpc->start));

	/* If it took over 10 seconds, that's rather strange. */
	if (msec > 10000)
		log_unusual(bitcoind->log,
			    "bitcoin-rpc: finished %s (%" PRIu64 " ms)",
			    brpc->cmd, msec);

	assert(bitcoind->num_requests[prio] > 0);

	evhttp_connection_free(brpc->evcon);
	event_base_free(brpc->base);

	if ((brpc->exitstatus == RPC_FAIL) ||
	    ((!brpc->rpc_error_ok) && (brpc->exitstatus == RPC_ERROR))) {
		log_unusual(bitcoind->log, "RPC: exit fail %d",
			    brpc->exitstatus);
		brpc_failure(bitcoind, brpc, brpc->exitstatus);
		bitcoind->num_requests[prio]--;
		goto done;
	}

	if (brpc->exitstatus == RPC_SUCCESS)
		bitcoind->error_count = 0;

	bitcoind->num_requests[brpc->prio]--;
	/* Don't continue if were only here because we were freed for shutdown */
	if (bitcoind->shutdown) {
		tal_free(brpc);
		return;
	}

	db_begin_transaction(bitcoind->ld->wallet->db);
	ok = brpc->process(brpc);
	db_commit_transaction(bitcoind->ld->wallet->db);

	if (!ok) {
		brpc_failure(bitcoind, brpc, brpc->exitstatus);
	} else {
		tal_free(brpc);
	}

done:
	next_brpc(bitcoind, prio);
}

static struct io_plan *always_init(struct io_conn *conn, void *arg)
{
	struct bitcoin_rpc *brpc = (struct bitcoin_rpc *)arg;

	if ((brpc->finished) || (brpc->bitcoind->shutdown)) {
		brpc_finished(brpc);
		return io_read(conn, NULL, 0, io_close_cb, NULL);
	} else {
		event_base_loop(brpc->base, EVLOOP_NONBLOCK);
		return io_read(conn, NULL, 0, always_init, arg);
	}
}

static void next_brpc(struct bitcoind *bitcoind, enum bitcoind_prio prio)
{
	struct bitcoin_rpc *brpc;
	bool ret;
	int fds[2];

	if (bitcoind->num_requests[prio] >= BITCOIND_MAX_PARALLEL)
		return;

	brpc = list_pop(&bitcoind->pending[prio], struct bitcoin_rpc, list);
	if (!brpc)
		return;

	ret = rpc_request(brpc);
	if (!ret) {
		return;
	}

	brpc->start = time_now();

	bitcoind->num_requests[prio]++;

	if (pipe(fds) != 0) {
		log_unusual(bitcoind->log, "next_brpc Failed: %s",
			    strerror(errno));
		abort();
	}

	close(fds[1]);
	io_new_conn(tmpctx, fds[0], always_init, brpc);
}

static bool is_literal(const char *arg)
{
	size_t arglen = strlen(arg);
	return strspn(arg, "0123456789") == arglen || streq(arg, "true") ||
	       streq(arg, "false") || streq(arg, "null") ||
	       (arg[0] == '{' && arg[arglen - 1] == '}') ||
	       (arg[0] == '[' && arg[arglen - 1] == ']') ||
	       (arg[0] == '"' && arg[arglen - 1] == '"');
}

static void add_input(char **cmd, const char *input, bool last)
{
	/* Numbers, bools, objects and arrays are left unquoted,
	 * and quoted things left alone. */
	if (is_literal(input))
		tal_append_fmt(cmd, "%s", input);
	else
		tal_append_fmt(cmd, "\"%s\"", input);
	if (!last)
		tal_append_fmt(cmd, ", ");
}

static bool process_donothing(struct bitcoin_rpc *bcrpc UNUSED)
{
	return true;
}

/* If stopper gets freed first, set process() to a noop. */
static void stop_process_brpc(struct bitcoin_rpc **stopper)
{
	(*stopper)->process = process_donothing;
	(*stopper)->stopper = NULL;
}

/* It rpc command finishes first, free stopper. */
static void remove_stopper(struct bitcoin_rpc *brpc)
{
	/* Calls stop_process_brpc, but we don't care. */
	tal_free(brpc->stopper);
}

static struct bitcoin_rpc *
	start_bitcoin_rpc(struct bitcoind *bitcoind, const tal_t *ctx,
			  bool (*process)(struct bitcoin_rpc *),
			  bool rpc_error_ok, enum bitcoind_prio prio, void *cb,
			  void *cb_arg, char *cmd, ...)
{
	va_list ap;
	struct bitcoin_rpc *brpc = tal(ctx, struct bitcoin_rpc);
	const char *arg, *next_arg;

	brpc->bitcoind = bitcoind;
	brpc->process = process;
	brpc->cb = cb;
	brpc->cb_arg = cb_arg;
	brpc->prio = prio;
	brpc->finished = false;
	brpc->exitstatus = RPC_FAIL;
	brpc->rpc_error_ok = rpc_error_ok;
	brpc->resulttok = NULL;
	brpc->errortok = NULL;
	brpc->errorcode = 0;
	if (ctx) {
		/* Create child whose destructor will stop us calling */
		brpc->stopper = tal(ctx, struct bitcoin_rpc *);
		*brpc->stopper = brpc;
		tal_add_destructor(brpc->stopper, stop_process_brpc);
		tal_add_destructor(brpc, remove_stopper);
	} else
		brpc->stopper = NULL;

	brpc->cmd = tal_fmt(brpc, "%s ", cmd);
	brpc->request = tal_fmt(
		brpc,
		"{\"jsonrpc\": \"1.0\", \"id\":\"lightningd\", \"method\": \"%s\", \"params\":",
		cmd);

	tal_append_fmt(&brpc->request, "[ ");

	va_start(ap, cmd);
	arg = va_arg(ap, const char *);
	if (arg != NULL) {
		do {
			next_arg = va_arg(ap, const char *);
			if (next_arg != NULL)
				add_input(&brpc->request, arg, false);
			else
				add_input(&brpc->request, arg, true);
			tal_append_fmt(&brpc->cmd, " ");
			brpc->cmd = tal_strcat(brpc, brpc->cmd, arg);
			arg = next_arg;
		} while (arg != NULL);
	}
	tal_append_fmt(&brpc->request, "]}");
	va_end(ap);

	list_add_tail(&bitcoind->pending[brpc->prio], &brpc->list);
	next_brpc(bitcoind, brpc->prio);
	return brpc;
}

static bool extract_feerate(struct bitcoin_rpc *brpc, const char *output,
			    size_t output_bytes, u64 *feerate)
{
	const jsmntok_t *feeratetok;

	if (brpc->exitstatus != RPC_SUCCESS) {
		log_debug(brpc->bitcoind->log, "%s", brpc->cmd);
		return false;
	}

	feeratetok = json_get_member(brpc->output, brpc->resulttok, "feerate");
	if (!feeratetok)
		return false;

	return json_tok_bitcoin_amount(output, feeratetok, feerate);
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

static bool process_estimatefee(struct bitcoin_rpc *brpc)
{
	u64 feerate;
	struct estimatefee *efee = brpc->cb_arg;

	/* FIXME: We could trawl recent blocks for median fee... */
	if (!extract_feerate(brpc, brpc->output, brpc->output_bytes,
			     &feerate)) {
		log_unusual(brpc->bitcoind->log, "Unable to estimate %s/%u fee",
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
		if (get_chainparams(brpc->bitcoind->ld)->testnet)
			efee->satoshi_per_kw[efee->i] = FEERATE_FLOOR;
		else
			efee->satoshi_per_kw[efee->i] = 0;
#endif
	} else
		/* Rate in satoshi per kw. */
		efee->satoshi_per_kw[efee->i] =
			feerate_from_style(feerate, FEERATE_PER_KBYTE);

	efee->i++;
	if (efee->i == tal_count(efee->satoshi_per_kw)) {
		efee->cb(brpc->bitcoind, efee->satoshi_per_kw, efee->arg);
		tal_free(efee);
	} else {
		/* Next */
		do_one_estimatefee(brpc->bitcoind, efee);
	}
	return true;
}

static void do_one_estimatefee(struct bitcoind *bitcoind,
			       struct estimatefee *efee)
{
	char blockstr[STR_MAX_CHARS(u32)];

	snprintf(blockstr, sizeof(blockstr), "%u", efee->blocks[efee->i]);
	start_bitcoin_rpc(bitcoind, NULL, process_estimatefee, false,
			  BITCOIND_LOW_PRIO, NULL, efee, "estimatesmartfee",
			  blockstr, efee->estmode[efee->i], NULL);
}

void bitcoind_estimate_fees_(struct bitcoind *bitcoind, const u32 blocks[],
			     const char *estmode[], size_t num_estimates,
			     void (*cb)(struct bitcoind *bitcoind,
					const u32 satoshi_per_kw[], void *),
			     void *arg)
{
	struct estimatefee *efee = tal(bitcoind, struct estimatefee);

	efee->i = 0;
	efee->blocks = tal_dup_arr(efee, u32, blocks, num_estimates, 0);
	efee->estmode =
		tal_dup_arr(efee, const char *, estmode, num_estimates, 0);
	efee->cb = cb;
	efee->arg = arg;
	efee->satoshi_per_kw = tal_arr(efee, u32, num_estimates);

	do_one_estimatefee(bitcoind, efee);
}

static bool process_sendrawtx(struct bitcoin_rpc *brpc)
{
	const jsmntok_t *msgtok;
	const char *msg;
	void (*cb)(struct bitcoind * bitcoind, int, const char *msg, void *) =
		brpc->cb;

	if (brpc->exitstatus == RPC_ERROR) {
		msgtok = json_get_member(brpc->output, brpc->errortok,
					 "message");
		if (msgtok)
			msg = tal_strndup(brpc, brpc->output + msgtok->start,
					  msgtok->end - msgtok->start);
		else
			msg = tal_strndup(
				brpc, brpc->output + brpc->errortok->start,
				brpc->errortok->end - brpc->errortok->start);
	} else
		msg = tal_strndup(brpc, brpc->output + brpc->resulttok->start,
				  brpc->resulttok->end -
					  brpc->resulttok->start);

	log_debug(brpc->bitcoind->log, "sendrawtx exit %u, gave %s",
		  brpc->exitstatus, msg);

	cb(brpc->bitcoind, brpc->exitstatus, msg, brpc->cb_arg);
	return true;
}

void bitcoind_sendrawtx_(struct bitcoind *bitcoind, const char *hextx,
			 void (*cb)(struct bitcoind *bitcoind, int exitstatus,
				    const char *msg, void *),
			 void *arg)
{
	log_debug(bitcoind->log, "sendrawtransaction: %s", hextx);
	start_bitcoin_rpc(bitcoind, NULL, process_sendrawtx, true,
			  BITCOIND_HIGH_PRIO, cb, arg, "sendrawtransaction",
			  hextx, NULL);
}

static bool process_rawblock(struct bitcoin_rpc *brpc)
{
	struct bitcoin_block *blk;
	void (*cb)(struct bitcoind * bitcoind, struct bitcoin_block * blk,
		   void *arg) = brpc->cb;

	int blklen = json_tok_len(brpc->resulttok) - 2;
	const char *blkhex = tal_strndup(
		brpc, brpc->output + brpc->resulttok->start, blklen);

	blk = bitcoin_block_from_hex(brpc, (const char *)blkhex, blklen);
	if (!blk)
		fatal("%s: bad block '%.*s'?", brpc->cmd,
		      (int)brpc->output_bytes, brpc->output);

	cb(brpc->bitcoind, blk, brpc->cb_arg);
	return true;
}

void bitcoind_getrawblock_(struct bitcoind *bitcoind,
			   const struct bitcoin_blkid *blockid,
			   void (*cb)(struct bitcoind *bitcoind,
				      struct bitcoin_block *blk, void *arg),
			   void *arg)
{
	char hex[hex_str_size(sizeof(*blockid))];

	bitcoin_blkid_to_hex(blockid, hex, sizeof(hex));
	start_bitcoin_rpc(bitcoind, NULL, process_rawblock, false,
			  BITCOIND_HIGH_PRIO, cb, arg, "getblock", hex, "false",
			  NULL);
}

static bool process_getblockcount(struct bitcoin_rpc *brpc)
{
	u32 blockcount;
	void (*cb)(struct bitcoind * bitcoind, u32 blockcount, void *arg) =
		brpc->cb;

	if (!json_to_number(brpc->output, brpc->resulttok, &blockcount))
		fatal("%s: gave non-numeric blockcount %s", brpc->cmd,
		      brpc->output);

	cb(brpc->bitcoind, blockcount, brpc->cb_arg);
	return true;
}

void bitcoind_getblockcount_(struct bitcoind *bitcoind,
			     void (*cb)(struct bitcoind *bitcoind,
					u32 blockcount, void *arg),
			     void *arg)
{
	start_bitcoin_rpc(bitcoind, NULL, process_getblockcount, false,
			  BITCOIND_HIGH_PRIO, cb, arg, "getblockcount", NULL);
}

struct get_output {
	unsigned int blocknum, txnum, outnum;

	/* The real callback */
	void (*cb)(struct bitcoind *bitcoind,
		   const struct bitcoin_tx_output *txout, void *arg);

	/* The real callback arg */
	void *cbarg;
};

static void process_get_output(struct bitcoind *bitcoind,
			       const struct bitcoin_tx_output *txout, void *arg)
{
	struct get_output *go = arg;
	go->cb(bitcoind, txout, go->cbarg);
}

static bool process_gettxout(struct bitcoin_rpc *brpc)
{
	void (*cb)(struct bitcoind * bitcoind,
		   const struct bitcoin_tx_output *output, void *arg) =
		brpc->cb;
	const jsmntok_t *tokens, *valuetok, *scriptpubkeytok, *hextok;
	struct bitcoin_tx_output out;

	if (brpc->exitstatus != RPC_SUCCESS) {
		log_debug(brpc->bitcoind->log, "%s: not unspent output?",
			  brpc->cmd);
		cb(brpc->bitcoind, NULL, brpc->cb_arg);
		return true;
	}

	tokens = brpc->resulttok;

	valuetok = json_get_member(brpc->output, tokens, "value");
	if (!valuetok)
		fatal("%s: had no value member (%.*s)?", brpc->cmd,
		      (int)brpc->output_bytes, brpc->output);

	if (!json_tok_bitcoin_amount(brpc->output, valuetok, &out.amount))
		fatal("%s: had bad value (%.*s)?", brpc->cmd,
		      (int)brpc->output_bytes, brpc->output);

	scriptpubkeytok = json_get_member(brpc->output, tokens, "scriptPubKey");
	if (!scriptpubkeytok)
		fatal("%s: had no scriptPubKey member (%.*s)?", brpc->cmd,
		      (int)brpc->output_bytes, brpc->output);
	hextok = json_get_member(brpc->output, scriptpubkeytok, "hex");
	if (!hextok)
		fatal("%s: had no scriptPubKey->hex member (%.*s)?", brpc->cmd,
		      (int)brpc->output_bytes, brpc->output);

	out.script = tal_hexdata(brpc, brpc->output + hextok->start,
				 hextok->end - hextok->start);
	if (!out.script)
		fatal("%s: scriptPubKey->hex invalid hex (%.*s)?", brpc->cmd,
		      (int)brpc->output_bytes, brpc->output);

	cb(brpc->bitcoind, &out, brpc->cb_arg);
	return true;
}

/**
 * process_getblock -- Retrieve a block from bitcoind
 *
 * Used to resolve a `txoutput` after identifying the blockhash, and
 * before extracting the outpoint from the UTXO.
 */
static bool process_getblock(struct bitcoin_rpc *brpc)
{
	void (*cb)(struct bitcoind * bitcoind,
		   const struct bitcoin_tx_output *output, void *arg) =
		brpc->cb;
	struct get_output *go = brpc->cb_arg;
	void *cbarg = go->cbarg;
	const jsmntok_t *txstok, *txidtok;
	struct bitcoin_txid txid;

	if (brpc->exitstatus != RPC_SUCCESS) {
		log_debug(brpc->bitcoind->log, "%s: error", brpc->cmd);
		cb(brpc->bitcoind, NULL, brpc->cb_arg);
		tal_free(go);
		return true;
	}

	/*  "tx": [
	    "1a7bb0f58a5d235d232deb61d9e2208dabe69848883677abe78e9291a00638e8",
	    "56a7e3468c16a4e21a4722370b41f522ad9dd8006c0e4e73c7d1c47f80eced94",
	    ...
	*/
	txstok = json_get_member(brpc->output, brpc->resulttok, "tx");
	if (!txstok)
		fatal("%s: had no tx member (%.*s)?", brpc->cmd,
		      (int)brpc->output_bytes, brpc->output);

	/* Now, this can certainly happen, if txnum too large. */
	txidtok = json_get_arr(txstok, go->txnum);
	if (!txidtok) {
		log_debug(brpc->bitcoind->log, "%s: no txnum %u", brpc->cmd,
			  go->txnum);
		cb(brpc->bitcoind, NULL, cbarg);
		tal_free(go);
		return true;
	}

	if (!bitcoin_txid_from_hex(brpc->output + txidtok->start,
				   txidtok->end - txidtok->start, &txid))
		fatal("%s: had bad txid (%.*s)?", brpc->cmd,
		      txidtok->end - txidtok->start,
		      brpc->output + txidtok->start);

	go->cb = cb;

	/* Now get the raw tx output. */
	bitcoind_gettxout(brpc->bitcoind, &txid, go->outnum, process_get_output,
			  go);
	return true;
}

static bool process_getblockhash_for_txout(struct bitcoin_rpc *brpc)
{
	void (*cb)(struct bitcoind * bitcoind,
		   const struct bitcoin_tx_output *output, void *arg) =
		brpc->cb;
	struct get_output *go = brpc->cb_arg;
	const char *blockhash;

	if (brpc->exitstatus != RPC_SUCCESS) {
		void *cbarg = go->cbarg;
		log_debug(brpc->bitcoind->log, "%s: invalid blocknum?",
			  brpc->cmd);
		tal_free(go);
		cb(brpc->bitcoind, NULL, cbarg);
		return true;
	}

	blockhash = tal_strndup(brpc, brpc->output + brpc->resulttok->start,
				brpc->resulttok->end - brpc->resulttok->start);

	start_bitcoin_rpc(brpc->bitcoind, NULL, process_getblock, false,
			  BITCOIND_LOW_PRIO, cb, go, "getblock",
			  take(blockhash), NULL);
	return true;
}

void bitcoind_getoutput_(struct bitcoind *bitcoind, unsigned int blocknum,
			 unsigned int txnum, unsigned int outnum,
			 void (*cb)(struct bitcoind *bitcoind,
				    const struct bitcoin_tx_output *output,
				    void *arg),
			 void *arg)
{
	struct get_output *go = tal(bitcoind, struct get_output);
	go->blocknum = blocknum;
	go->txnum = txnum;
	go->outnum = outnum;
	go->cbarg = arg;

	/* We may not have topology ourselves that far back, so ask bitcoind */
	start_bitcoin_rpc(bitcoind, NULL, process_getblockhash_for_txout, true,
			  BITCOIND_LOW_PRIO, cb, go, "getblockhash",
			  take(tal_fmt(NULL, "%u", blocknum)), NULL);

	notleak(go);
}

static bool process_getblockhash(struct bitcoin_rpc *brpc)
{
	struct bitcoin_blkid blkid;
	void (*cb)(struct bitcoind * bitcoind,
		   const struct bitcoin_blkid *blkid, void *arg) = brpc->cb;

	/* If it failed with error RPC_INVALID_PARAMETER, call with NULL block. */
	if (brpc->exitstatus == RPC_ERROR) {
		/* Other error means we have to retry. */
		if (brpc->errorcode != RPC_INVALID_PARAMETER)
			return false;
		cb(brpc->bitcoind, NULL, brpc->cb_arg);
		return true;
	} else if (brpc->exitstatus == RPC_FAIL)
		return true;

	int len = json_tok_len(brpc->resulttok);

	if (!bitcoin_blkid_from_hex(brpc->output + brpc->resulttok->start,
				    len - 2, &blkid)) {
		fatal("%s: bad blockid '%.*s'", brpc->cmd,
		      (int)brpc->output_bytes, brpc->output);
	}

	cb(brpc->bitcoind, &blkid, brpc->cb_arg);
	return true;
}

void bitcoind_getblockhash_(struct bitcoind *bitcoind, u32 height,
			    void (*cb)(struct bitcoind *bitcoind,
				       const struct bitcoin_blkid *blkid,
				       void *arg),
			    void *arg)
{
	char str[STR_MAX_CHARS(height)];
	snprintf(str, sizeof(str), "%u", height);

	start_bitcoin_rpc(bitcoind, NULL, process_getblockhash, true,
			  BITCOIND_HIGH_PRIO, cb, arg, "getblockhash", str,
			  NULL);
}

void bitcoind_gettxout(struct bitcoind *bitcoind,
		       const struct bitcoin_txid *txid, const u32 outnum,
		       void (*cb)(struct bitcoind *bitcoind,
				  const struct bitcoin_tx_output *txout,
				  void *arg),
		       void *arg)
{
	start_bitcoin_rpc(bitcoind, NULL, process_gettxout, true,
			  BITCOIND_LOW_PRIO, cb, arg, "gettxout",
			  take(type_to_string(NULL, struct bitcoin_txid, txid)),
			  take(tal_fmt(NULL, "%u", outnum)), NULL);
}

static void destroy_bitcoind(struct bitcoind *bitcoind)
{
	/* Suppresses the callbacks from brpc_finished as we free conns. */
	bitcoind->shutdown = true;
}

static void fatal_bitcoind_failure(struct bitcoind *bitcoind,
				   const char *error_message)
{
	fprintf(stderr, "%s\n\n", error_message);
	fprintf(stderr,
		"Make sure you have bitcoind running and that bitcoin rpc is able to connect to bitcoind.\n\n");
	fprintf(stderr,
		"You can verify that your Bitcoin Core installation is ready for use by running:\n\n");
	fprintf(stderr,
		"curl --user %s --data-binary '{\"jsonrpc\": \"1.0\","
		"\"id\":\"lightning\", \"method\": \"getblockchaininfo\","
		"\"params\": [] }' -H 'content-type: text/plain;' "
		"http://%s:%d/\n",
		bitcoind->rpcuser, bitcoind->rpcconnect, bitcoind->rpcport);
	exit(1);
}

void wait_for_bitcoind(struct bitcoind *bitcoind)
{
	struct bitcoin_rpc *brpc = tal(NULL, struct bitcoin_rpc);

	if ((bitcoind->rpccookiefile == NULL) &&
	    ((bitcoind->rpcuser == NULL) || (bitcoind->rpcpass == NULL) ||
	     (bitcoind->rpcconnect == NULL) || (bitcoind->rpcport == 0)))
		fatal("RPC server is not config,  See:\n"
		      " --bitcoin-rpcuser\n"
		      " --bitcoin-rpcpassword\n"
		      " --bitcoin-rpcconnect\n"
		      " --bitcoin-rpcport\n"
		      " --bitcoin-rpccookiefile\n");

	brpc->bitcoind = bitcoind;

	for (;;) {
		brpc->finished = false;
		brpc->exitstatus = RPC_FAIL;
		brpc->errorcode = 0;

		brpc->request =
			"{\"jsonrpc\": \"1.0\", \"id\":\"lightningd\", \"method\": \"getblockchaininfo\", \"params\":[] }";

		if (!rpc_request(brpc))
			fatal_bitcoind_failure(bitcoind, "RPC call fail\n");

		event_base_dispatch(brpc->base);
		evhttp_connection_free(brpc->evcon);
		event_base_free(brpc->base);

		if (brpc->exitstatus == RPC_SUCCESS)
			break;

		else if (brpc->exitstatus == RPC_FAIL)
			fatal_bitcoind_failure(bitcoind, brpc->output);

		/* Client still warming up */
		else if (brpc->errorcode == RPC_IN_WARMUP) {
			log_unusual(bitcoind->log,
				    "Waiting for bitcoind to warm up...");
		} else if (brpc->errorcode == RPC_CLIENT_IN_INITIAL_DOWNLOAD) {
			log_unusual(
				bitcoind->log,
				"Waiting for bitcoind downloading initial blocks...");
		} else if (brpc->output)
			fatal_bitcoind_failure(bitcoind, brpc->output);

		sleep(1);
	}

	tal_free(brpc);
}

struct bitcoind *new_bitcoind(const tal_t *ctx, struct lightningd *ld,
			      struct log *log)
{
	struct bitcoind *bitcoind = tal(ctx, struct bitcoind);

	/* Use testnet by default, change later if we want another network */
	bitcoind->chainparams = chainparams_for_network("testnet");
	bitcoind->datadir = NULL;
	bitcoind->ld = ld;
	bitcoind->log = log;
	for (size_t i = 0; i < BITCOIND_NUM_PRIO; i++) {
		bitcoind->num_requests[i] = 0;
		list_head_init(&bitcoind->pending[i]);
	}
	bitcoind->shutdown = false;
	bitcoind->error_count = 0;
	bitcoind->rpccookiefile = NULL;
	bitcoind->rpcuser = NULL;
	bitcoind->rpcpass = NULL;
	bitcoind->rpcconnect = tal_fmt(bitcoind, DEFAULT_RPCCONNECT);
	bitcoind->rpcport = bitcoind->chainparams->rpc_port;

	tal_add_destructor(bitcoind, destroy_bitcoind);

	return bitcoind;
}
