/* Code for talking to bitcoind.  We use bitcoin-cli. */
#include "bitcoin/base58.h"
#include "bitcoin/block.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/tx.h"
#include "bitcoind.h"
#include "json.h"
#include "lightningd.h"
#include "log.h"
#include "utils.h"
#include <ccan/cast/cast.h>
#include <ccan/io/io.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/str/hex/hex.h>
#include <ccan/take/take.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <errno.h>
#include <inttypes.h>

#define BITCOIN_CLI "bitcoin-cli"

char *bitcoin_datadir;

static char **gather_args(struct lightningd_state *dstate,
			  const tal_t *ctx, const char *cmd, va_list ap)
{
	size_t n = 0;
	char **args = tal_arr(ctx, char *, 3);

	args[n++] = BITCOIN_CLI;
	if (dstate->config.regtest)
		args[n++] = "-regtest=1";
	else
		args[n++] = tal_fmt(args, "-testnet=%u", dstate->testnet);
	if (bitcoin_datadir) {
		args[n++] = tal_fmt(args, "-datadir=%s", bitcoin_datadir);
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
	struct lightningd_state *dstate;
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

static void next_bcli(struct lightningd_state *dstate);

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
	struct lightningd_state *dstate = bcli->dstate;

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
			fatal("%s exited %u: '%.*s'", bcli_args(bcli),
			      WEXITSTATUS(status),
			      (int)bcli->output_bytes,
			      bcli->output);
		}
	} else
		*bcli->exitstatus = WEXITSTATUS(status);

	log_debug(dstate->base_log, "reaped %u: %s", ret, bcli_args(bcli));
	dstate->bitcoin_req_running = false;
	bcli->process(bcli);

	next_bcli(dstate);
}

static void next_bcli(struct lightningd_state *dstate)
{
	struct bitcoin_cli *bcli;
	struct io_conn *conn;

	if (dstate->bitcoin_req_running)
		return;

	bcli = list_pop(&dstate->bitcoin_req, struct bitcoin_cli, list);
	if (!bcli)
		return;

	log_debug(bcli->dstate->base_log, "starting: %s", bcli_args(bcli));

	bcli->pid = pipecmdarr(&bcli->fd, NULL, &bcli->fd, bcli->args);
	if (bcli->pid < 0)
		fatal("%s exec failed: %s", bcli->args[0], strerror(errno));

	dstate->bitcoin_req_running = true;
	conn = io_new_conn(dstate, bcli->fd, output_init, bcli);
	tal_steal(conn, bcli);
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
start_bitcoin_cli(struct lightningd_state *dstate,
		  const tal_t *ctx,
		  void (*process)(struct bitcoin_cli *),
		  bool nonzero_exit_ok,
		  void *cb, void *cb_arg,
		  char *cmd, ...)
{
	va_list ap;
	struct bitcoin_cli *bcli = tal(dstate, struct bitcoin_cli);

	bcli->dstate = dstate;
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
	bcli->args = gather_args(dstate, bcli, cmd, ap);
	va_end(ap);

	list_add_tail(&dstate->bitcoin_req, &bcli->list);
	next_bcli(dstate);
}

static void process_estimatefee_6(struct bitcoin_cli *bcli)
{
	double fee;
	char *p, *end;
	u64 fee_rate;
	void (*cb)(struct lightningd_state *, u64, void *) = bcli->cb;

	p = tal_strndup(bcli, bcli->output, bcli->output_bytes);
	fee = strtod(p, &end);
	if (end == p || *end != '\n')
		fatal("%s: gave non-numeric fee %s",
		      bcli_args(bcli), p);

	if (fee < 0) {
		log_unusual(bcli->dstate->base_log,
			    "Unable to estimate fee");
		fee_rate = 0;
	} else {
		/* Since we used 6 as an estimate, double it. */
		fee *= 2;
		fee_rate = fee * 100000000;
	}

	cb(bcli->dstate, fee_rate, bcli->cb_arg);
}

static void process_estimatefee_2(struct bitcoin_cli *bcli)
{
	double fee;
	char *p, *end;
	u64 fee_rate;
	void (*cb)(struct lightningd_state *, u64, void *) = bcli->cb;

	p = tal_strndup(bcli, bcli->output, bcli->output_bytes);
	fee = strtod(p, &end);
	if (end == p || *end != '\n')
		fatal("%s: gave non-numeric fee %s",
		      bcli_args(bcli), p);

	/* Don't know at 2?  Try 6... */
	if (fee < 0) {
		start_bitcoin_cli(bcli->dstate, NULL, process_estimatefee_6,
				  false, bcli->cb, bcli->cb_arg,
				  "estimatefee", "6", NULL);
		return;
	}
	fee_rate = fee * 100000000;
	cb(bcli->dstate, fee_rate, bcli->cb_arg);
}

void bitcoind_estimate_fee_(struct lightningd_state *dstate,
			    void (*cb)(struct lightningd_state *dstate,
				       u64, void *),
			    void *arg)
{
	start_bitcoin_cli(dstate, NULL, process_estimatefee_2, false, cb, arg,
			  "estimatefee", "2", NULL);
}

static void process_sendrawtx(struct bitcoin_cli *bcli)
{
	void (*cb)(struct lightningd_state *dstate,
		   int, const char *msg, void *) = bcli->cb;
	const char *msg = tal_strndup(bcli, (char *)bcli->output,
				      bcli->output_bytes);

	log_debug(bcli->dstate->base_log, "sendrawtx exit %u, gave %s",
		  *bcli->exitstatus, msg);

	cb(bcli->dstate, *bcli->exitstatus, msg, bcli->cb_arg);
}

void bitcoind_sendrawtx_(struct peer *peer,
			 struct lightningd_state *dstate,
			 const char *hextx,
			 void (*cb)(struct lightningd_state *dstate,
				    int exitstatus, const char *msg, void *),
			 void *arg)
{
	start_bitcoin_cli(dstate, NULL, process_sendrawtx, true, cb, arg,
			  "sendrawtransaction", hextx, NULL);
}

static void process_chaintips(struct bitcoin_cli *bcli)
{
	const jsmntok_t *tokens, *t, *end;
	bool valid;
	size_t i;
	struct sha256_double tip;
	void (*cb)(struct lightningd_state *dstate,
		   struct sha256_double *tipid,
		   void *arg) = bcli->cb;

	log_debug(bcli->dstate->base_log, "Got getchaintips result");

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

		if (!json_tok_streq(bcli->output, status, "active")) {
			log_debug(bcli->dstate->base_log,
				  "Ignoring chaintip %.*s status %.*s",
				  hash->end - hash->start,
				  bcli->output + hash->start,
				  status->end - status->start,
				  bcli->output + status->start);
			continue;
		}
		if (valid) {
			log_unusual(bcli->dstate->base_log,
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

	cb(bcli->dstate, &tip, bcli->cb_arg);
}

void bitcoind_get_chaintip_(struct lightningd_state *dstate,
			    void (*cb)(struct lightningd_state *dstate,
				       const struct sha256_double *tipid,
				       void *arg),
			    void *arg)
{
	start_bitcoin_cli(dstate, NULL, process_chaintips, false, cb, arg,
			  "getchaintips", NULL);
}

struct normalizing {
	u32 mediantime;
	struct sha256_double prevblk, blkid;
	struct sha256_double *txids;
	size_t i;
	void (*cb)(struct lightningd_state *dstate,
		   struct sha256_double *blkid,
		   struct sha256_double *prevblock,
		   struct sha256_double *txids,
		   u32 mediantime,
		   void *arg);
	void *cb_arg;
};

static void process_rawblock(struct bitcoin_cli *bcli)
{
	struct bitcoin_block *blk;
	void (*cb)(struct lightningd_state *dstate,
		   struct bitcoin_block *blk,
		   void *arg) = bcli->cb;

	/* FIXME: Just get header if we can't get full block. */
	blk = bitcoin_block_from_hex(bcli, bcli->output, bcli->output_bytes);
	if (!blk)
		fatal("%s: bad block '%.*s'?",
		      bcli_args(bcli),
		      (int)bcli->output_bytes, (char *)bcli->output);

	cb(bcli->dstate, blk, bcli->cb_arg);
}

void bitcoind_getrawblock_(struct lightningd_state *dstate,
			   const struct sha256_double *blockid,
			   void (*cb)(struct lightningd_state *dstate,
				      struct bitcoin_block *blk,
				      void *arg),
			   void *arg)
{
	char hex[hex_str_size(sizeof(*blockid))];

	bitcoin_blkid_to_hex(blockid, hex, sizeof(hex));
	start_bitcoin_cli(dstate, NULL, process_rawblock, false, cb, arg,
			  "getblock", hex, "false", NULL);
}

static void process_getblockcount(struct bitcoin_cli *bcli)
{
	u32 blockcount;
	char *p, *end;
	void (*cb)(struct lightningd_state *dstate,
		   u32 blockcount,
		   void *arg) = bcli->cb;

	p = tal_strndup(bcli, bcli->output, bcli->output_bytes);
	blockcount = strtol(p, &end, 10);
	if (end == p || *end != '\n')
		fatal("%s: gave non-numeric blockcount %s",
		      bcli_args(bcli), p);

	cb(bcli->dstate, blockcount, bcli->cb_arg);
}

void bitcoind_getblockcount_(struct lightningd_state *dstate,
			      void (*cb)(struct lightningd_state *dstate,
					 u32 blockcount,
					 void *arg),
			      void *arg)
{
	start_bitcoin_cli(dstate, NULL, process_getblockcount, false, cb, arg,
			  "getblockcount", NULL);
}

static void process_getblockhash(struct bitcoin_cli *bcli)
{
	struct sha256_double blkid;
	void (*cb)(struct lightningd_state *dstate,
		   const struct sha256_double *blkid,
		   void *arg) = bcli->cb;

	if (bcli->output_bytes == 0
	    || !bitcoin_blkid_from_hex(bcli->output, bcli->output_bytes-1,
				       &blkid)) {
		fatal("%s: bad blockid '%.*s'",
		      bcli_args(bcli), (int)bcli->output_bytes, bcli->output);
	}

	cb(bcli->dstate, &blkid, bcli->cb_arg);
}

void bitcoind_getblockhash_(struct lightningd_state *dstate,
			    u32 height,
			    void (*cb)(struct lightningd_state *dstate,
				       const struct sha256_double *blkid,
				       void *arg),
			    void *arg)
{
	char str[STR_MAX_CHARS(height)];
	sprintf(str, "%u", height);

	start_bitcoin_cli(dstate, NULL, process_getblockhash, false, cb, arg,
			  "getblockhash", str, NULL);
}
