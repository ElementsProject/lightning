/* Code for talking to bitcoind.  We use bitcoin-cli. */
#include "bitcoin/base58.h"
#include "bitcoin/block.h"
#include "bitcoin/feerate.h"
#include "bitcoin/script.h"
#include "bitcoin/shadouble.h"
#include "bitcoind.h"
#include "lightningd.h"
#include "log.h"
#include <ccan/cast/cast.h>
#include <ccan/io/io.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/str/hex/hex.h>
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

/* Bitcoind's web server has a default of 4 threads, with queue depth 16.
 * It will *fail* rather than queue beyond that, so we must not stress it!
 *
 * This is how many request for each priority level we have.
 */
#define BITCOIND_MAX_PARALLEL 4

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

static bool process_sendrawtx(struct bitcoin_cli *bcli)
{
	void (*cb)(struct bitcoind *bitcoind,
		   int, const char *msg, void *) = bcli->cb;
	const char *msg = tal_strndup(bcli, bcli->output,
				      bcli->output_bytes);

	log_debug(bcli->bitcoind->log, "sendrawtx exit %u, gave %s",
		  *bcli->exitstatus, msg);

	cb(bcli->bitcoind, *bcli->exitstatus, msg, bcli->cb_arg);
	return true;
}

void bitcoind_sendrawtx_(struct bitcoind *bitcoind,
			 const char *hextx,
			 void (*cb)(struct bitcoind *bitcoind,
				    int exitstatus, const char *msg, void *),
			 void *arg)
{
	log_debug(bitcoind->log, "sendrawtransaction: %s", hextx);
	start_bitcoin_cli(bitcoind, NULL, process_sendrawtx, true,
			  BITCOIND_HIGH_PRIO,
			  cb, arg,
			  "sendrawtransaction", hextx, NULL);
}

static bool process_rawblock(struct bitcoin_cli *bcli)
{
	struct bitcoin_block *blk;
	void (*cb)(struct bitcoind *bitcoind,
		   struct bitcoin_block *blk,
		   void *arg) = bcli->cb;

	blk = bitcoin_block_from_hex(bcli, chainparams,
				     bcli->output, bcli->output_bytes);
	if (!blk)
		fatal("%s: bad block '%.*s'?",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);

	cb(bcli->bitcoind, blk, bcli->cb_arg);
	return true;
}

void bitcoind_getrawblock_(struct bitcoind *bitcoind,
			   const struct bitcoin_blkid *blockid,
			   void (*cb)(struct bitcoind *bitcoind,
				      struct bitcoin_block *blk,
				      void *arg),
			   void *arg)
{
	char hex[hex_str_size(sizeof(*blockid))];

	bitcoin_blkid_to_hex(blockid, hex, sizeof(hex));
	start_bitcoin_cli(bitcoind, NULL, process_rawblock, false,
			  BITCOIND_HIGH_PRIO,
			  cb, arg,
			  "getblock", hex, "false", NULL);
}

static bool process_getblockcount(struct bitcoin_cli *bcli)
{
	u32 blockcount;
	char *p, *end;
	void (*cb)(struct bitcoind *bitcoind,
		   u32 blockcount,
		   void *arg) = bcli->cb;

	p = tal_strndup(bcli, bcli->output, bcli->output_bytes);
	blockcount = strtol(p, &end, 10);
	if (end == p || *end != '\n')
		fatal("%s: gave non-numeric blockcount %s",
		      bcli_args(tmpctx, bcli), p);

	cb(bcli->bitcoind, blockcount, bcli->cb_arg);
	return true;
}

void bitcoind_getblockcount_(struct bitcoind *bitcoind,
			      void (*cb)(struct bitcoind *bitcoind,
					 u32 blockcount,
					 void *arg),
			      void *arg)
{
	start_bitcoin_cli(bitcoind, NULL, process_getblockcount, false,
			  BITCOIND_HIGH_PRIO,
			  cb, arg,
			  "getblockcount", NULL);
}

struct get_output {
	unsigned int blocknum, txnum, outnum;

	/* The real callback */
	void (*cb)(struct bitcoind *bitcoind, const struct bitcoin_tx_output *txout, void *arg);

	/* The real callback arg */
	void *cbarg;
};

static bool process_gettxout(struct bitcoin_cli *bcli)
{
	void (*cb)(struct bitcoind *bitcoind,
		   const struct bitcoin_tx_output *output,
		   void *arg) = bcli->cb;
	const jsmntok_t *tokens, *valuetok, *scriptpubkeytok, *hextok;
	struct bitcoin_tx_output out;
	bool valid;

	/* As of at least v0.15.1.0, bitcoind returns "success" but an empty
	   string on a spent gettxout */
	if (*bcli->exitstatus != 0 || bcli->output_bytes == 0) {
		cb(bcli->bitcoind, NULL, bcli->cb_arg);
		return true;
	}

	tokens = json_parse_input(bcli->output, bcli->output, bcli->output_bytes,
				  &valid);
	if (!tokens)
		fatal("%s: %s response",
		      bcli_args(tmpctx, bcli), valid ? "partial" : "invalid");

	if (tokens[0].type != JSMN_OBJECT)
		fatal("%s: gave non-object (%.*s)?",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);

	valuetok = json_get_member(bcli->output, tokens, "value");
	if (!valuetok)
		fatal("%s: had no value member (%.*s)?",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);

	if (!json_to_bitcoin_amount(bcli->output, valuetok, &out.amount.satoshis)) /* Raw: talking to bitcoind */
		fatal("%s: had bad value (%.*s)?",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);

	scriptpubkeytok = json_get_member(bcli->output, tokens, "scriptPubKey");
	if (!scriptpubkeytok)
		fatal("%s: had no scriptPubKey member (%.*s)?",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);
	hextok = json_get_member(bcli->output, scriptpubkeytok, "hex");
	if (!hextok)
		fatal("%s: had no scriptPubKey->hex member (%.*s)?",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);

	out.script = tal_hexdata(bcli, bcli->output + hextok->start,
				 hextok->end - hextok->start);
	if (!out.script)
		fatal("%s: scriptPubKey->hex invalid hex (%.*s)?",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);

	cb(bcli->bitcoind, &out, bcli->cb_arg);
	return true;
}

static bool process_getblockhash(struct bitcoin_cli *bcli)
{
	struct bitcoin_blkid blkid;
	void (*cb)(struct bitcoind *bitcoind,
		   const struct bitcoin_blkid *blkid,
		   void *arg) = bcli->cb;

	/* If it failed with error 8, call with NULL block. */
	if (*bcli->exitstatus != 0) {
		/* Other error means we have to retry. */
		if (*bcli->exitstatus != 8)
			return false;
		cb(bcli->bitcoind, NULL, bcli->cb_arg);
		return true;
	}

	if (bcli->output_bytes == 0
	    || !bitcoin_blkid_from_hex(bcli->output, bcli->output_bytes-1,
				       &blkid)) {
		fatal("%s: bad blockid '%.*s'",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);
	}

	cb(bcli->bitcoind, &blkid, bcli->cb_arg);
	return true;
}

void bitcoind_getblockhash_(struct bitcoind *bitcoind,
			    u32 height,
			    void (*cb)(struct bitcoind *bitcoind,
				       const struct bitcoin_blkid *blkid,
				       void *arg),
			    void *arg)
{
	char str[STR_MAX_CHARS(height)];
	snprintf(str, sizeof(str), "%u", height);

	start_bitcoin_cli(bitcoind, NULL, process_getblockhash, true,
			  BITCOIND_HIGH_PRIO,
			  cb, arg,
			  "getblockhash", str, NULL);
}

void bitcoind_gettxout(struct bitcoind *bitcoind,
		       const struct bitcoin_txid *txid, const u32 outnum,
		       void (*cb)(struct bitcoind *bitcoind,
				  const struct bitcoin_tx_output *txout,
				  void *arg),
		       void *arg)
{
	start_bitcoin_cli(bitcoind, NULL,
			  process_gettxout, true, BITCOIND_LOW_PRIO, cb, arg,
			  "gettxout",
			  take(type_to_string(NULL, struct bitcoin_txid, txid)),
			  take(tal_fmt(NULL, "%u", outnum)),
			  NULL);
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
process_getfilteredblock_step3(struct bitcoind *bitcoind,
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
		bitcoind_gettxout(bitcoind, &o->txid, o->outnum,
				  process_getfilteredblock_step3, call);
	} else {
		/* If there were no more outpoints to check, we call the callback. */
		process_getfiltered_block_final(bitcoind, call);
	}
}

static void process_getfilteredblock_step2(struct bitcoind *bitcoind,
					   struct bitcoin_block *block,
					   struct filteredblock_call *call)
{
	struct filteredblock_outpoint *o;
	struct bitcoin_tx *tx;

	/* If for some reason we couldn't get the block, just report a
	 * failure. */
	if (block == NULL)
		return process_getfiltered_block_final(bitcoind, call);

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
		bitcoind_gettxout(bitcoind, &o->txid, o->outnum,
				  process_getfilteredblock_step3, call);
	}
}

static void process_getfilteredblock_step1(struct bitcoind *bitcoind,
					   const struct bitcoin_blkid *blkid,
					   struct filteredblock_call *call)
{
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

	/* Now get the raw block to get all outpoints that were created in
	 * this block. */
	bitcoind_getrawblock(bitcoind, blkid, process_getfilteredblock_step2, call);
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
		bitcoind_getblockhash(bitcoind, c->height, process_getfilteredblock_step1, c);
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
		bitcoind_getblockhash(bitcoind, height, process_getfilteredblock_step1, call);
}

static bool extract_numeric_version(struct bitcoin_cli *bcli,
			    const char *output, size_t output_bytes,
			    u64 *version)
{
	const jsmntok_t *tokens, *versiontok;
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

	versiontok = json_get_member(output, tokens, "version");
	if (!versiontok)
		return false;

	return json_to_u64(output, versiontok, version);
}

static bool process_getclientversion(struct bitcoin_cli *bcli)
{
	u64 version;
	u64 min_version = chainparams->cli_min_supported_version;

	if (!extract_numeric_version(bcli, bcli->output,
				     bcli->output_bytes,
				     &version)) {
		fatal("%s: Unable to getclientversion (%.*s)",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes,
		      bcli->output);
	}

	if (version < min_version)
		fatal("Unsupported bitcoind version? bitcoind version: %"PRIu64","
		      " supported minimum version: %"PRIu64"",
		      version, min_version);

	return true;
}

void bitcoind_getclientversion(struct bitcoind *bitcoind)
{
	/* `getnetworkinfo` was added in v0.14.0. The older version would
	 * return non-zero exitstatus. */
	start_bitcoin_cli(bitcoind, NULL, process_getclientversion, false,
			  BITCOIND_HIGH_PRIO,
			  NULL, NULL,
			  "getnetworkinfo", NULL);
}

/* Mutual recursion */
static bool process_getblockchaininfo(struct bitcoin_cli *bcli);

static void retry_getblockchaininfo(struct bitcoind *bitcoind)
{
	assert(!bitcoind->synced);
	start_bitcoin_cli(bitcoind, NULL,
			  process_getblockchaininfo,
			  false, BITCOIND_LOW_PRIO, NULL, NULL,
			  "getblockchaininfo", NULL);
}

/* Given JSON object from getblockchaininfo, are we synced?  Poll if not. */
static void is_bitcoind_synced_yet(struct bitcoind *bitcoind,
				   const char *output, size_t output_len,
				   const jsmntok_t *obj,
				   bool initial)
{
	const jsmntok_t *t;
	unsigned int headers, blocks;
	bool ibd;

	t = json_get_member(output, obj, "headers");
	if (!t || !json_to_number(output, t, &headers))
		fatal("Invalid 'headers' field in getblockchaininfo '%.*s'",
		      (int)output_len, output);

	t = json_get_member(output, obj, "blocks");
	if (!t || !json_to_number(output, t, &blocks))
		fatal("Invalid 'blocks' field in getblockchaininfo '%.*s'",
		      (int)output_len, output);

	t = json_get_member(output, obj, "initialblockdownload");
	if (!t || !json_to_bool(output, t, &ibd))
		fatal("Invalid 'initialblockdownload' field in getblockchaininfo '%.*s'",
		      (int)output_len, output);

	if (ibd) {
		if (initial)
			log_unusual(bitcoind->log,
				    "Waiting for initial block download"
				    " (this can take a while!)");
		else
			log_debug(bitcoind->log,
				  "Still waiting for initial block download");
	} else if (headers != blocks) {
		if (initial)
			log_unusual(bitcoind->log,
				    "Waiting for bitcoind to catch up"
				    " (%u blocks of %u)",
				    blocks, headers);
		else
			log_debug(bitcoind->log,
				  "Waiting for bitcoind to catch up"
				  " (%u blocks of %u)",
				  blocks, headers);
	} else {
		if (!initial)
			log_info(bitcoind->log, "Bitcoind now synced.");
		bitcoind->synced = true;
		return;
	}

	bitcoind->synced = false;
	notleak(new_reltimer(bitcoind->ld->timers, bitcoind,
			     /* Be 4x more aggressive in this case. */
			     time_divide(time_from_sec(bitcoind->ld->topology
						       ->poll_seconds), 4),
			     retry_getblockchaininfo, bitcoind));
}

static bool process_getblockchaininfo(struct bitcoin_cli *bcli)
{
	const jsmntok_t *tokens;
	bool valid;

	tokens = json_parse_input(bcli, bcli->output, bcli->output_bytes,
				  &valid);
	if (!tokens)
		fatal("%s: %s response (%.*s)",
		      bcli_args(tmpctx, bcli),
		      valid ? "partial" : "invalid",
		      (int)bcli->output_bytes, bcli->output);

	if (tokens[0].type != JSMN_OBJECT) {
		log_unusual(bcli->bitcoind->log,
			    "%s: gave non-object (%.*s)?",
			    bcli_args(tmpctx, bcli),
			    (int)bcli->output_bytes, bcli->output);
		return false;
	}

	is_bitcoind_synced_yet(bcli->bitcoind, bcli->output, bcli->output_bytes,
			       tokens, false);
	return true;
}

static void destroy_bitcoind(struct bitcoind *bitcoind)
{
	/* Suppresses the callbacks from bcli_finished as we free conns. */
	bitcoind->shutdown = true;
}

static const char **cmdarr(const tal_t *ctx, const struct bitcoind *bitcoind,
			   const char *cmd, ...)
{
	va_list ap;
	const char **args;

	va_start(ap, cmd);
	args = gather_args(bitcoind, ctx, cmd, ap);
	va_end(ap);
	return args;
}

static void fatal_bitcoind_failure(struct bitcoind *bitcoind, const char *error_message)
{
	const char **cmd = cmdarr(bitcoind, bitcoind, "echo", NULL);

	fprintf(stderr, "%s\n\n", error_message);
	fprintf(stderr, "Make sure you have bitcoind running and that bitcoin-cli is able to connect to bitcoind.\n\n");
	fprintf(stderr, "You can verify that your Bitcoin Core installation is ready for use by running:\n\n");
	fprintf(stderr, "    $ %s 'hello world'\n", args_string(cmd, cmd));
	tal_free(cmd);
	exit(1);
}

/* This function is used to check "chain" field from
 * bitcoin-cli "getblockchaininfo" API */
static char* check_blockchain_from_bitcoincli(const tal_t *ctx,
				struct bitcoind *bitcoind,
				char* output, const char **cmd)
{
	size_t output_bytes;
	const jsmntok_t *tokens, *valuetok;
	bool valid;

	if (!output)
		return tal_fmt(ctx, "Reading from %s failed: %s",
			       args_string(tmpctx, cmd), strerror(errno));

	output_bytes = tal_count(output);

	tokens = json_parse_input(cmd, output, output_bytes,
			          &valid);

	if (!tokens)
		return tal_fmt(ctx, "%s: %s response",
			       args_string(tmpctx, cmd),
			       valid ? "partial" : "invalid");

	if (tokens[0].type != JSMN_OBJECT)
		return tal_fmt(ctx, "%s: gave non-object (%.*s)?",
			       args_string(tmpctx, cmd),
			       (int)output_bytes, output);

	valuetok = json_get_member(output, tokens, "chain");
	if (!valuetok)
		return tal_fmt(ctx, "%s: had no chain member (%.*s)?",
			       args_string(tmpctx, cmd),
			       (int)output_bytes, output);

	if(!json_tok_streq(output, valuetok,
			   chainparams->bip70_name))
		return tal_fmt(ctx, "Error blockchain for bitcoin-cli?"
			       " Should be: %s",
			       chainparams->bip70_name);

	is_bitcoind_synced_yet(bitcoind, output, output_bytes, tokens, true);
	return NULL;
}

void wait_for_bitcoind(struct bitcoind *bitcoind)
{
	int from, status, ret;
	pid_t child;
	const char **cmd = cmdarr(bitcoind, bitcoind, "getblockchaininfo", NULL);
	bool printed = false;
	char *errstr;

	for (;;) {
		child = pipecmdarr(NULL, &from, &from, cast_const2(char **,cmd));
		if (child < 0) {
			if (errno == ENOENT) {
				fatal_bitcoind_failure(bitcoind, "bitcoin-cli not found. Is bitcoin-cli (part of Bitcoin Core) available in your PATH?");
			}
			fatal("%s exec failed: %s", cmd[0], strerror(errno));
		}

		char *output = grab_fd(cmd, from);

		while ((ret = waitpid(child, &status, 0)) < 0 && errno == EINTR);
		if (ret != child)
			fatal("Waiting for %s: %s", cmd[0], strerror(errno));
		if (!WIFEXITED(status))
			fatal("Death of %s: signal %i",
			      cmd[0], WTERMSIG(status));

		if (WEXITSTATUS(status) == 0) {
			/* If succeeded, so check answer it gave. */
			errstr = check_blockchain_from_bitcoincli(tmpctx, bitcoind, output, cmd);
			if (errstr)
				fatal("%s", errstr);

			break;
		}

		/* bitcoin/src/rpc/protocol.h:
		 *	RPC_IN_WARMUP = -28, //!< Client still warming up
		 */
		if (WEXITSTATUS(status) != 28) {
			if (WEXITSTATUS(status) == 1) {
				fatal_bitcoind_failure(bitcoind, "Could not connect to bitcoind using bitcoin-cli. Is bitcoind running?");
			}
			fatal("%s exited with code %i: %s",
			      cmd[0], WEXITSTATUS(status), output);
		}

		if (!printed) {
			log_unusual(bitcoind->log,
				    "Waiting for bitcoind to warm up...");
			printed = true;
		}
		sleep(1);
	}
	tal_free(cmd);
}

struct bitcoind *new_bitcoind(const tal_t *ctx,
			      struct lightningd *ld,
			      struct log *log)
{
	struct bitcoind *bitcoind = tal(ctx, struct bitcoind);

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

	return bitcoind;
}
