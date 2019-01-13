/* Code for talking to bitcoind.  We use bitcoin-cli. */
#include "bitcoin/base58.h"
#include "bitcoin/block.h"
#include "bitcoin/feerate.h"
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
#include <common/json.h>
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
	*tal_arr_expand(args) = arg;
}

static const char **gather_args(const struct bitcoind *bitcoind,
				const tal_t *ctx, const char *cmd, va_list ap)
{
	const char **args = tal_arr(ctx, const char *, 1);
	const char *arg;

	args[0] = bitcoind->cli ? bitcoind->cli : bitcoind->chainparams->cli;
	if (bitcoind->chainparams->cli_args)
		add_arg(&args, bitcoind->chainparams->cli_args);

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

/* For printing: simple string of args. */
static char *bcli_args(const tal_t *ctx, struct bitcoin_cli *bcli)
{
	size_t i;
	char *ret = tal_strdup(ctx, bcli->args[0]);

	for (i = 1; bcli->args[i]; i++) {
		ret = tal_strcat(ctx, take(ret), " ");
		ret = tal_strcat(ctx, take(ret), bcli->args[i]);
	}
	return ret;
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
	if (time_greater(t, time_from_sec(60)))
		fatal("%s exited %u (after %u other errors) '%.*s'",
		      bcli_args(tmpctx, bcli),
		      exitstatus,
		      bitcoind->error_count,
		      (int)bcli->output_bytes,
		      bcli->output);

	log_unusual(bitcoind->log,
		    "%s exited with status %u",
		    bcli_args(tmpctx, bcli), exitstatus);

	bitcoind->error_count++;

	/* Retry in 1 second (not a leak!) */
	new_reltimer(&bitcoind->ld->timers, notleak(bcli), time_from_sec(1),
		     retry_bcli, bcli);
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
		if (get_chainparams(bcli->bitcoind->ld)->testnet)
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

	blk = bitcoin_block_from_hex(bcli, bcli->output, bcli->output_bytes);
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

static void process_get_output(struct bitcoind *bitcoind, const struct bitcoin_tx_output *txout, void *arg)
{
	struct get_output *go = arg;
	go->cb(bitcoind, txout, go->cbarg);
}

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
		log_debug(bcli->bitcoind->log, "%s: not unspent output?",
			  bcli_args(tmpctx, bcli));
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

	if (!json_to_bitcoin_amount(bcli->output, valuetok, &out.amount))
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

/**
 * process_getblock -- Retrieve a block from bitcoind
 *
 * Used to resolve a `txoutput` after identifying the blockhash, and
 * before extracting the outpoint from the UTXO.
 */
static bool process_getblock(struct bitcoin_cli *bcli)
{
	void (*cb)(struct bitcoind *bitcoind,
		   const struct bitcoin_tx_output *output,
		   void *arg) = bcli->cb;
	struct get_output *go = bcli->cb_arg;
	void *cbarg = go->cbarg;
	const jsmntok_t *tokens, *txstok, *txidtok;
	struct bitcoin_txid txid;
	bool valid;

	tokens = json_parse_input(bcli->output, bcli->output, bcli->output_bytes,
				  &valid);
	if (!tokens) {
		/* Most likely we are running on a pruned node, call
		 * the callback with NULL to indicate failure */
		log_debug(bcli->bitcoind->log,
			  "%s: returned invalid block, is this a pruned node?",
			  bcli_args(tmpctx, bcli));
		cb(bcli->bitcoind, NULL, cbarg);
		tal_free(go);
		return true;
	}

	if (tokens[0].type != JSMN_OBJECT)
		fatal("%s: gave non-object (%.*s)?",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);

	/*  "tx": [
	    "1a7bb0f58a5d235d232deb61d9e2208dabe69848883677abe78e9291a00638e8",
	    "56a7e3468c16a4e21a4722370b41f522ad9dd8006c0e4e73c7d1c47f80eced94",
	    ...
	*/
	txstok = json_get_member(bcli->output, tokens, "tx");
	if (!txstok)
		fatal("%s: had no tx member (%.*s)?",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes, bcli->output);

	/* Now, this can certainly happen, if txnum too large. */
	txidtok = json_get_arr(txstok, go->txnum);
	if (!txidtok) {
		log_debug(bcli->bitcoind->log, "%s: no txnum %u",
			  bcli_args(tmpctx, bcli), go->txnum);
		cb(bcli->bitcoind, NULL, cbarg);
		tal_free(go);
		return true;
	}

	if (!bitcoin_txid_from_hex(bcli->output + txidtok->start,
				   txidtok->end - txidtok->start,
				   &txid))
		fatal("%s: had bad txid (%.*s)?",
		      bcli_args(tmpctx, bcli),
		      json_tok_full_len(txidtok),
		      json_tok_full(bcli->output, txidtok));

	go->cb = cb;
	/* Now get the raw tx output. */
	bitcoind_gettxout(bcli->bitcoind, &txid, go->outnum, process_get_output, go);
	return true;
}

static bool process_getblockhash_for_txout(struct bitcoin_cli *bcli)
{
	void (*cb)(struct bitcoind *bitcoind,
		   const struct bitcoin_tx_output *output,
		   void *arg) = bcli->cb;
	struct get_output *go = bcli->cb_arg;
	char *blockhash;

	if (*bcli->exitstatus != 0) {
		void *cbarg = go->cbarg;
		log_debug(bcli->bitcoind->log, "%s: invalid blocknum?",
			  bcli_args(tmpctx, bcli));
		tal_free(go);
		cb(bcli->bitcoind, NULL, cbarg);
		return true;
	}

	/* Strip the newline at the end of the previous output */
	blockhash = tal_strndup(NULL, bcli->output, bcli->output_bytes-1);

	start_bitcoin_cli(bcli->bitcoind, NULL, process_getblock, true,
			  BITCOIND_LOW_PRIO,
			  cb, go,
			  "getblock", take(blockhash), NULL);
	return true;
}

void bitcoind_getoutput_(struct bitcoind *bitcoind,
			 unsigned int blocknum, unsigned int txnum,
			 unsigned int outnum,
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
	start_bitcoin_cli(bitcoind, NULL, process_getblockhash_for_txout,
			  true, BITCOIND_LOW_PRIO, cb, go,
			  "getblockhash", take(tal_fmt(NULL, "%u", blocknum)),
			  NULL);

	/* Looks like a leak, but we free it in process_getblock */
	notleak(go);
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
	size_t i;
	const char **cmd = cmdarr(bitcoind, bitcoind, "echo", NULL);

	fprintf(stderr, "%s\n\n", error_message);
	fprintf(stderr, "Make sure you have bitcoind running and that bitcoin-cli is able to connect to bitcoind.\n\n");
	fprintf(stderr, "You can verify that your Bitcoin Core installation is ready for use by running:\n\n");
	fprintf(stderr, "    $ ");
	for (i = 0; cmd[i]; i++) {
		fprintf(stderr, "%s ", cmd[i]);
	}
	fprintf(stderr, "'hello world'\n");
	tal_free(cmd);
	exit(1);
}

void wait_for_bitcoind(struct bitcoind *bitcoind)
{
	int from, status, ret;
	pid_t child;
	const char **cmd = cmdarr(bitcoind, bitcoind, "echo", NULL);
	bool printed = false;

	for (;;) {
		child = pipecmdarr(NULL, &from, &from, cast_const2(char **,cmd));
		if (child < 0) {
			if (errno == ENOENT) {
				fatal_bitcoind_failure(bitcoind, "bitcoin-cli not found. Is bitcoin-cli (part of Bitcoin Core) available in your PATH?");
			}
			fatal("%s exec failed: %s", cmd[0], strerror(errno));
		}

		char *output = grab_fd(cmd, from);
		if (!output)
			fatal("Reading from %s failed: %s",
			      cmd[0], strerror(errno));

		while ((ret = waitpid(child, &status, 0)) < 0 && errno == EINTR);
		if (ret != child)
			fatal("Waiting for %s: %s", cmd[0], strerror(errno));
		if (!WIFEXITED(status))
			fatal("Death of %s: signal %i",
			      cmd[0], WTERMSIG(status));

		if (WEXITSTATUS(status) == 0)
			break;

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

	/* Use testnet by default, change later if we want another network */
	bitcoind->chainparams = chainparams_for_network("testnet");
	bitcoind->cli = NULL;
	bitcoind->datadir = NULL;
	bitcoind->ld = ld;
	bitcoind->log = log;
	for (size_t i = 0; i < BITCOIND_NUM_PRIO; i++) {
		bitcoind->num_requests[i] = 0;
		list_head_init(&bitcoind->pending[i]);
	}
	bitcoind->shutdown = false;
	bitcoind->error_count = 0;
	bitcoind->rpcuser = NULL;
	bitcoind->rpcpass = NULL;
	bitcoind->rpcconnect = NULL;
	bitcoind->rpcport = NULL;
	tal_add_destructor(bitcoind, destroy_bitcoind);

	return bitcoind;
}
