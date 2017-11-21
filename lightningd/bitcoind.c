/* Code for talking to bitcoind.  We use bitcoin-cli. */
#include "bitcoin/base58.h"
#include "bitcoin/block.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/tx.h"
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
#include <ccan/tal/tal.h>
#include <common/json.h>
#include <common/utils.h>
#include <errno.h>
#include <inttypes.h>

#define BITCOIN_CLI "bitcoin-cli"

char *bitcoin_datadir;

static char **gather_args(const struct bitcoind *bitcoind,
			  const tal_t *ctx, const char *cmd, va_list ap)
{
	size_t n = 0;
	char **args = tal_arr(ctx, char *, 2);

	args[n++] = cast_const(char *, bitcoind->chainparams->cli);
	if (bitcoind->chainparams->cli_args) {
		args[n++] = cast_const(char *, bitcoind->chainparams->cli_args);
		tal_resize(&args, n + 1);
	}

	if (bitcoind->datadir) {
		args[n++] = tal_fmt(args, "-datadir=%s", bitcoind->datadir);
		tal_resize(&args, n + 1);
	}
	args[n++] = cast_const(char *, cmd);
	tal_resize(&args, n + 1);

	while ((args[n] = va_arg(ap, char *)) != NULL) {
		args[n] = tal_strdup(args, args[n]);
		n++;
		tal_resize(&args, n + 1);
	}
	return args;
}

struct bitcoin_cli {
	struct list_node list;
	struct bitcoind *bitcoind;
	int fd;
	int *exitstatus;
	pid_t pid;
	char **args;
	char *output;
	size_t output_bytes;
	size_t new_output;
	void (*process)(struct bitcoin_cli *);
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

static void next_bcli(struct bitcoind *bitcoind);

/* For printing: simple string of args. */
static char *bcli_args(struct bitcoin_cli *bcli)
{
	size_t i;
	char *ret = tal_strdup(bcli, bcli->args[0]);

	for (i = 1; bcli->args[i]; i++) {
		ret = tal_strcat(bcli, take(ret), " ");
		ret = tal_strcat(bcli, take(ret), bcli->args[i]);
	}
	return ret;
}

static void bcli_finished(struct io_conn *conn, struct bitcoin_cli *bcli)
{
	int ret, status;
	struct bitcoind *bitcoind = bcli->bitcoind;

	/* FIXME: If we waited for SIGCHILD, this could never hang! */
	ret = waitpid(bcli->pid, &status, 0);
	if (ret != bcli->pid)
		fatal("%s %s", bcli_args(bcli),
		      ret == 0 ? "not exited?" : strerror(errno));

	if (!WIFEXITED(status))
		fatal("%s died with signal %i",
		      bcli_args(bcli),
		      WTERMSIG(status));

	if (!bcli->exitstatus) {
		if (WEXITSTATUS(status) != 0) {
			/* Allow 60 seconds of spurious errors, eg. reorg. */
			struct timerel t;

			log_unusual(bcli->bitcoind->log,
				    "%s exited with status %u",
				    bcli_args(bcli),
				    WEXITSTATUS(status));

			if (!bitcoind->error_count)
				bitcoind->first_error_time = time_mono();

			t = timemono_between(time_mono(),
					     bitcoind->first_error_time);
			if (time_greater(t, time_from_sec(60)))
				fatal("%s exited %u (after %u other errors) '%.*s'",
				      bcli_args(bcli),
				      WEXITSTATUS(status),
				      bitcoind->error_count,
				      (int)bcli->output_bytes,
				      bcli->output);
			bitcoind->error_count++;
		}
	} else
		*bcli->exitstatus = WEXITSTATUS(status);

	if (WEXITSTATUS(status) == 0)
		bitcoind->error_count = 0;

	bitcoind->req_running = false;

	/* Don't continue if were only here because we were freed for shutdown */
	if (bitcoind->shutdown)
		return;

	db_begin_transaction(bitcoind->ld->wallet->db);
	bcli->process(bcli);
	db_commit_transaction(bitcoind->ld->wallet->db);

	next_bcli(bitcoind);
}

static void next_bcli(struct bitcoind *bitcoind)
{
	struct bitcoin_cli *bcli;
	struct io_conn *conn;

	if (bitcoind->req_running)
		return;

	bcli = list_pop(&bitcoind->pending, struct bitcoin_cli, list);
	if (!bcli)
		return;

	bcli->pid = pipecmdarr(&bcli->fd, NULL, &bcli->fd, bcli->args);
	if (bcli->pid < 0)
		fatal("%s exec failed: %s", bcli->args[0], strerror(errno));

	bitcoind->req_running = true;
	conn = io_new_conn(bitcoind, bcli->fd, output_init, bcli);
	io_set_finish(conn, bcli_finished, bcli);
}

static void process_donothing(struct bitcoin_cli *bcli)
{
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

/* If ctx is non-NULL, and is freed before we return, we don't call process() */
static void
start_bitcoin_cli(struct bitcoind *bitcoind,
		  const tal_t *ctx,
		  void (*process)(struct bitcoin_cli *),
		  bool nonzero_exit_ok,
		  void *cb, void *cb_arg,
		  char *cmd, ...)
{
	va_list ap;
	struct bitcoin_cli *bcli = tal(bitcoind, struct bitcoin_cli);

	bcli->bitcoind = bitcoind;
	bcli->process = process;
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

	list_add_tail(&bitcoind->pending, &bcli->list);
	next_bcli(bitcoind);
}

static bool extract_feerate(struct bitcoin_cli *bcli,
			    const char *output, size_t output_bytes,
			    double *feerate)
{
	const jsmntok_t *tokens, *feeratetok;
	bool valid;

	tokens = json_parse_input(output, output_bytes, &valid);
	if (!tokens)
		fatal("%s: %s response",
		      bcli_args(bcli),
		      valid ? "partial" : "invalid");

	if (tokens[0].type != JSMN_OBJECT)
		fatal("%s: gave non-object (%.*s)?",
		      bcli_args(bcli),
		      (int)output_bytes, output);

	feeratetok = json_get_member(output, tokens, "feerate");
	if (!feeratetok)
		return false;

	return json_tok_double(output, feeratetok, feerate);
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

static void process_estimatefee(struct bitcoin_cli *bcli)
{
	double feerate;
	struct estimatefee *efee = bcli->cb_arg;

	/* FIXME: We could trawl recent blocks for median fee... */
	if (!extract_feerate(bcli, bcli->output, bcli->output_bytes, &feerate)) {
		log_unusual(bcli->bitcoind->log, "Unable to estimate %s/%u fee",
			    efee->estmode[efee->i], efee->blocks[efee->i]);
		efee->satoshi_per_kw[efee->i] = 0;
	} else
		/* Rate in satoshi per kw. */
		efee->satoshi_per_kw[efee->i] = feerate * 100000000 / 4;

	efee->i++;
	if (efee->i == tal_count(efee->satoshi_per_kw)) {
		efee->cb(bcli->bitcoind, efee->satoshi_per_kw, efee->arg);
		tal_free(efee);
	} else {
		/* Next */
		do_one_estimatefee(bcli->bitcoind, efee);
	}
}

static void do_one_estimatefee(struct bitcoind *bitcoind,
			       struct estimatefee *efee)
{
	char blockstr[STR_MAX_CHARS(u32)];

	sprintf(blockstr, "%u", efee->blocks[efee->i]);
	start_bitcoin_cli(bitcoind, NULL, process_estimatefee, false, NULL, efee,
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

static void process_sendrawtx(struct bitcoin_cli *bcli)
{
	void (*cb)(struct bitcoind *bitcoind,
		   int, const char *msg, void *) = bcli->cb;
	const char *msg = tal_strndup(bcli, (char *)bcli->output,
				      bcli->output_bytes);

	log_debug(bcli->bitcoind->log, "sendrawtx exit %u, gave %s",
		  *bcli->exitstatus, msg);

	cb(bcli->bitcoind, *bcli->exitstatus, msg, bcli->cb_arg);
}

void bitcoind_sendrawtx_(struct bitcoind *bitcoind,
			 const char *hextx,
			 void (*cb)(struct bitcoind *bitcoind,
				    int exitstatus, const char *msg, void *),
			 void *arg)
{
	log_debug(bitcoind->log, "sendrawtransaction: %s", hextx);
	start_bitcoin_cli(bitcoind, NULL, process_sendrawtx, true, cb, arg,
			  "sendrawtransaction", hextx, NULL);
}

static void process_chaintips(struct bitcoin_cli *bcli)
{
	const jsmntok_t *tokens, *t, *end;
	bool valid;
	size_t i;
	struct sha256_double tip;
	void (*cb)(struct bitcoind *bitcoind,
		   struct sha256_double *tipid,
		   void *arg) = bcli->cb;

	tokens = json_parse_input(bcli->output, bcli->output_bytes, &valid);
	if (!tokens)
		fatal("%s: %s response",
		      bcli_args(bcli),
		      valid ? "partial" : "invalid");

	if (tokens[0].type != JSMN_ARRAY)
		fatal("%s: gave non-array (%.*s)?",
		      bcli_args(bcli),
		      (int)bcli->output_bytes, bcli->output);

	valid = false;
	end = json_next(tokens);
	for (i = 0, t = tokens + 1; t < end; t = json_next(t), i++) {
		const jsmntok_t *status = json_get_member(bcli->output, t, "status");
		const jsmntok_t *hash = json_get_member(bcli->output, t, "hash");

		if (!status || !hash) {
			log_broken(bcli->bitcoind->log,
				   "%s: No status & hash: %.*s",
				    bcli_args(bcli),
				    (int)bcli->output_bytes, bcli->output);
			continue;
		}

		if (!json_tok_streq(bcli->output, status, "active")) {
			log_debug(bcli->bitcoind->log,
				  "Ignoring chaintip %.*s status %.*s",
				  hash->end - hash->start,
				  bcli->output + hash->start,
				  status->end - status->start,
				  bcli->output + status->start);
			continue;
		}
		if (valid) {
			log_unusual(bcli->bitcoind->log,
				    "%s: Two active chaintips? %.*s",
				    bcli_args(bcli),
				    (int)bcli->output_bytes, bcli->output);
			continue;
		}
		if (!bitcoin_blkid_from_hex(bcli->output + hash->start,
					    hash->end - hash->start,
					    &tip))
			fatal("%s: gave bad hash for %zu'th tip (%.*s)?",
			      bcli_args(bcli), i,
			      (int)bcli->output_bytes, bcli->output);
		valid = true;
	}
	if (!valid)
		fatal("%s: gave no active chaintips (%.*s)?",
		      bcli_args(bcli), (int)bcli->output_bytes, bcli->output);

	cb(bcli->bitcoind, &tip, bcli->cb_arg);
}

void bitcoind_get_chaintip_(struct bitcoind *bitcoind,
			    void (*cb)(struct bitcoind *bitcoind,
				       const struct sha256_double *tipid,
				       void *arg),
			    void *arg)
{
	start_bitcoin_cli(bitcoind, NULL, process_chaintips, false, cb, arg,
			  "getchaintips", NULL);
}

static void process_rawblock(struct bitcoin_cli *bcli)
{
	struct bitcoin_block *blk;
	void (*cb)(struct bitcoind *bitcoind,
		   struct bitcoin_block *blk,
		   void *arg) = bcli->cb;

	/* FIXME: Just get header if we can't get full block. */
	blk = bitcoin_block_from_hex(bcli, bcli->output, bcli->output_bytes);
	if (!blk)
		fatal("%s: bad block '%.*s'?",
		      bcli_args(bcli),
		      (int)bcli->output_bytes, (char *)bcli->output);

	cb(bcli->bitcoind, blk, bcli->cb_arg);
}

void bitcoind_getrawblock_(struct bitcoind *bitcoind,
			   const struct sha256_double *blockid,
			   void (*cb)(struct bitcoind *bitcoind,
				      struct bitcoin_block *blk,
				      void *arg),
			   void *arg)
{
	char hex[hex_str_size(sizeof(*blockid))];

	bitcoin_blkid_to_hex(blockid, hex, sizeof(hex));
	start_bitcoin_cli(bitcoind, NULL, process_rawblock, false, cb, arg,
			  "getblock", hex, "false", NULL);
}

static void process_getblockcount(struct bitcoin_cli *bcli)
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
		      bcli_args(bcli), p);

	cb(bcli->bitcoind, blockcount, bcli->cb_arg);
}

void bitcoind_getblockcount_(struct bitcoind *bitcoind,
			      void (*cb)(struct bitcoind *bitcoind,
					 u32 blockcount,
					 void *arg),
			      void *arg)
{
	start_bitcoin_cli(bitcoind, NULL, process_getblockcount, false, cb, arg,
			  "getblockcount", NULL);
}

static void process_getblockhash(struct bitcoin_cli *bcli)
{
	struct sha256_double blkid;
	void (*cb)(struct bitcoind *bitcoind,
		   const struct sha256_double *blkid,
		   void *arg) = bcli->cb;

	if (bcli->output_bytes == 0
	    || !bitcoin_blkid_from_hex(bcli->output, bcli->output_bytes-1,
				       &blkid)) {
		fatal("%s: bad blockid '%.*s'",
		      bcli_args(bcli), (int)bcli->output_bytes, bcli->output);
	}

	cb(bcli->bitcoind, &blkid, bcli->cb_arg);
}

void bitcoind_getblockhash_(struct bitcoind *bitcoind,
			    u32 height,
			    void (*cb)(struct bitcoind *bitcoind,
				       const struct sha256_double *blkid,
				       void *arg),
			    void *arg)
{
	char str[STR_MAX_CHARS(height)];
	sprintf(str, "%u", height);

	start_bitcoin_cli(bitcoind, NULL, process_getblockhash, false, cb, arg,
			  "getblockhash", str, NULL);
}

static void destroy_bitcoind(struct bitcoind *bitcoind)
{
	/* Suppresses the callbacks from bcli_finished as we free conns. */
	bitcoind->shutdown = true;
}

static char **cmdarr(const tal_t *ctx, const struct bitcoind *bitcoind,
		     const char *cmd, ...)
{
	va_list ap;
	char **args;

	va_start(ap, cmd);
	args = gather_args(bitcoind, ctx, cmd, ap);
	va_end(ap);
	return args;
}

void wait_for_bitcoind(struct bitcoind *bitcoind)
{
	int from, ret, status;
	pid_t child;
	char **cmd = cmdarr(bitcoind, bitcoind, "echo", NULL);
	char *output;
	bool printed = false;

	for (;;) {
		child = pipecmdarr(&from, NULL, &from, cmd);
		if (child < 0)
			fatal("%s exec failed: %s", cmd[0], strerror(errno));

		output = grab_fd(cmd, from);
		if (!output)
			fatal("Reading from %s failed: %s",
			      cmd[0], strerror(errno));

		ret = waitpid(child, &status, 0);
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
		if (WEXITSTATUS(status) != 28)
			fatal("%s exited with code %i: %s",
			      cmd[0], WEXITSTATUS(status), output);

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
	bitcoind->datadir = NULL;
	bitcoind->ld = ld;
	bitcoind->log = log;
	bitcoind->req_running = false;
	bitcoind->shutdown = false;
	bitcoind->error_count = 0;
	list_head_init(&bitcoind->pending);
	tal_add_destructor(bitcoind, destroy_bitcoind);

	return bitcoind;
}
