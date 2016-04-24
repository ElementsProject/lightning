/* Code for talking to bitcoind.  We use bitcoin-cli. */
#include "bitcoin/base58.h"
#include "bitcoin/block.h"
#include "bitcoin/shadouble.h"
#include "bitcoin/tx.h"
#include "bitcoind.h"
#include "json.h"
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
#include <errno.h>
#include <inttypes.h>

#define BITCOIN_CLI "bitcoin-cli"

char *bitcoin_datadir;

static char **gather_args(const tal_t *ctx, const char *cmd, va_list ap)
{
	size_t n = 0;
	char **args = tal_arr(ctx, char *, 1);

	args[n++] = BITCOIN_CLI;
	tal_resize(&args, n + 1);
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
	pid_t pid;
	char **args;
	char *output;
	size_t output_bytes;
	size_t new_output;
	void (*process)(struct bitcoin_cli *);
	void *cb;
	void *cb_arg;
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

	if (WEXITSTATUS(status) != 0) {
		log_unusual(dstate->base_log,
			    "%s exited %u: '%.*s'", bcli_args(bcli),
			    WEXITSTATUS(status),
			    (int)bcli->output_bytes,
			    bcli->output);
		bcli->output = tal_free(bcli->output);
		bcli->output_bytes = 0;
	} else 
		log_debug(dstate->base_log, "reaped %u: %s",
			  ret, bcli_args(bcli));

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

static void
start_bitcoin_cli(struct lightningd_state *dstate,
		  void (*process)(struct bitcoin_cli *),
		  void *cb, void *cb_arg,
		  char *cmd, ...)
{
	va_list ap;
	struct bitcoin_cli *bcli = tal(dstate, struct bitcoin_cli);

	bcli->dstate = dstate;
	bcli->process = process;
	bcli->cb = cb;
	bcli->cb_arg = cb_arg;
	va_start(ap, cmd);
	bcli->args = gather_args(bcli, cmd, ap);
	va_end(ap);

	list_add_tail(&dstate->bitcoin_req, &bcli->list);
	next_bcli(dstate);
}

static void process_estimatefee(struct bitcoin_cli *bcli)
{
	double fee;
	char *p, *end;
	u64 fee_rate;
	void (*cb)(struct lightningd_state *, u64, void *) = bcli->cb;

	if (!bcli->output)
		fatal("%s failed", bcli_args(bcli));

	p = tal_strndup(bcli, bcli->output, bcli->output_bytes);
	fee = strtod(p, &end);
	if (end == p || *end != '\n')
		fatal("%s: gave non-numeric fee %s",
		      bcli_args(bcli), p);

	/* Don't know at 2?  Try 6... */
	if (fee < 0) {
		if (streq(bcli->args[3], "2")) {
			start_bitcoin_cli(bcli->dstate, process_estimatefee,
					  bcli->cb, bcli->cb_arg,
					  "estimatefee", "6", NULL);
			return;
		}
		log_unusual(bcli->dstate->base_log,
			    "Unable to estimate fee, using %"PRIu64,
			    bcli->dstate->config.closing_fee_rate);
		fee_rate = bcli->dstate->config.closing_fee_rate;
	} else {
		/* If we used 6 as an estimate, double it. */
		if (streq(bcli->args[3], "6"))
			fee *= 2;
		fee_rate = fee * 100000000;
	}

	cb(bcli->dstate, fee_rate, bcli->cb_arg);
}

void bitcoind_estimate_fee_(struct lightningd_state *dstate,
			    void (*cb)(struct lightningd_state *dstate,
				       u64, void *),
			    void *arg)
{
	start_bitcoin_cli(dstate, process_estimatefee, cb, arg,
			  "estimatefee", "2", NULL);
}

static void process_sendrawrx(struct bitcoin_cli *bcli)
{
	struct sha256_double txid;
	const char *out = (char *)bcli->output;

	/* We expect a txid, plus \n */
	if (!bcli->output)
		fatal("%s failed", bcli_args(bcli));
	if (bcli->output_bytes == 0
	    || !bitcoin_txid_from_hex(out, bcli->output_bytes-1, &txid))
		fatal("sendrawtransaction bad hex: %.*s",
		     (int)bcli->output_bytes, out);

	log_debug(bcli->dstate->base_log, "sendrawtx gave %.*s",
		  (int)bcli->output_bytes, out);

	/* FIXME: Compare against expected txid? */
}

void bitcoind_send_tx(struct lightningd_state *dstate,
		      const struct bitcoin_tx *tx)
{
	u8 *raw = linearize_tx(dstate, tx);
	char *hex = tal_arr(raw, char, hex_str_size(tal_count(raw)));

	hex_encode(raw, tal_count(raw), hex, tal_count(hex));
	start_bitcoin_cli(dstate, process_sendrawrx, NULL, NULL,
			  "sendrawtransaction", hex, NULL);
	tal_free(raw);
}

static void process_chaintips(struct bitcoin_cli *bcli)
{
	const jsmntok_t *tokens, *t, *end;
	bool valid;
	size_t i;
	struct sha256_double *tips;
	void (*cb)(struct lightningd_state *dstate,
		   struct sha256_double *blockids,
		   void *arg) = bcli->cb;

	log_debug(bcli->dstate->base_log, "Got getchaintips result");
	if (!bcli->output)
		fatal("%s failed", bcli_args(bcli));

	tokens = json_parse_input(bcli->output, bcli->output_bytes, &valid);
	if (!tokens)
		fatal("%s: %s response",
		      bcli_args(bcli),
		      valid ? "partial" : "invalid");

	if (tokens[0].type != JSMN_ARRAY)
		fatal("%s: gave non-array (%.*s)?",
		      bcli_args(bcli),
		      (int)bcli->output_bytes, bcli->output);

	tips = tal_arr(bcli, struct sha256_double, 0);
	end = json_next(tokens);
	for (i = 0, t = tokens + 1; t < end; t = json_next(t), i++) {
		const jsmntok_t *hash = json_get_member(bcli->output, t, "hash");
		tal_resize(&tips, i+1);
		if (!bitcoin_blkid_from_hex(bcli->output + hash->start,
					    hash->end - hash->start,
					    &tips[i]))
			fatal("%s: gave bad hash for %zu'th tip (%.*s)?",
			      bcli_args(bcli), i,
			      (int)bcli->output_bytes, bcli->output);
	}
	if (i == 0)
		fatal("%s: gave empty array (%.*s)?",
		      bcli_args(bcli), (int)bcli->output_bytes, bcli->output);

	cb(bcli->dstate, tips, bcli->cb_arg);
}

void bitcoind_get_chaintips_(struct lightningd_state *dstate,
			     void (*cb)(struct lightningd_state *dstate,
					struct sha256_double *blockids,
					void *arg),
			     void *arg)
{
	start_bitcoin_cli(dstate, process_chaintips, cb, arg,
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
	if (!bcli->output)
		fatal("%s: unknown block?", bcli_args(bcli));

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
	start_bitcoin_cli(dstate, process_rawblock, cb, arg,
			  "getblock", hex, "false", NULL);
}

static void process_getblockcount(struct bitcoin_cli *bcli)
{
	u32 blockcount;
	char *p, *end;
	void (*cb)(struct lightningd_state *dstate,
		   u32 blockcount,
		   void *arg) = bcli->cb;

	if (!bcli->output)
		fatal("%s: failed", bcli_args(bcli));

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
	start_bitcoin_cli(dstate, process_getblockcount, cb, arg,
			  "getblockcount", NULL);
}

static void process_getblockhash(struct bitcoin_cli *bcli)
{
	struct sha256_double blkid;
	void (*cb)(struct lightningd_state *dstate,
		   const struct sha256_double *blkid,
		   void *arg) = bcli->cb;

	if (!bcli->output)
		fatal("%s: failed", bcli_args(bcli));

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

	start_bitcoin_cli(dstate, process_getblockhash, cb, arg,
			  "getblockhash", str, NULL);
}

/* FIXME: Seg witness removes need for this! */
void normalized_txid(const struct bitcoin_tx *tx, struct sha256_double *txid)
{
	size_t i;
	struct bitcoin_tx tx_copy = *tx;
	struct bitcoin_tx_input input_copy[tx->input_count];

	/* Copy inputs, but scripts are 0 length. */
	for (i = 0; i < tx_copy.input_count; i++) {
		input_copy[i] = tx->input[i];
		input_copy[i].script_length = 0;
	}
	tx_copy.input = input_copy;

	bitcoin_txid(&tx_copy, txid);
}

/* Make testnet/regtest status matches us. */
void check_bitcoind_config(struct lightningd_state *dstate)
{
	void *ctx = tal(dstate, char);
	char *path, *config, **lines;
	size_t i;
	int testnet = -1, regtest = -1;

	path = path_simplify(ctx, path_join(ctx, path_cwd(ctx),
					    "../.bitcoin/bitcoin.conf"));
	config = grab_file(ctx, path);
	if (!config) {
		log_unusual(dstate->base_log, "Could not open %s to check it",
			    path);
		goto out;
	}

	lines = tal_strsplit(ctx, config, "\n", STR_NO_EMPTY);
	for (i = 0; lines[i]; i++) {
		char *str;
		if (tal_strreg(ctx, lines[i],
				    "^[ \t]*testnet[ \t]*=[ \t]*([01])", &str))
			testnet = atoi(str);
		else if (tal_strreg(ctx, lines[i],
				    "^[ \t]*regtest[ \t]*=[ \t]*([01])", &str))
			regtest = atoi(str);
	}

	if (dstate->config.testnet) {
		if (testnet != 1 && regtest != 1)
			log_unusual(dstate->base_log,
				    "%s does not set testnet/regtest,"
				    " but we are on testnet.",
				    path);
	} else if (testnet == 1 || regtest == 1)
		log_unusual(dstate->base_log,
			    "%s sets %s, but we are not on testnet",
			    path, testnet == 1 ? "testnet" : "regtest");
out:
	tal_free(ctx);
}
