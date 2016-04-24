/* Code for talking to bitcoind.  We use bitcoin-cli. */
#include "bitcoin/base58.h"
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

static void process_importaddress(struct bitcoin_cli *bcli)
{
	if (!bcli->output)
		fatal("%s failed", bcli_args(bcli));
	if (bcli->output_bytes != 0)
		fatal("%s unexpected output '%.*s'",
		      bcli_args(bcli),
		      (int)bcli->output_bytes, bcli->output);
}

void bitcoind_watch_addr(struct lightningd_state *dstate,
			 const struct ripemd160 *redeemhash)
{
	char *p2shaddr = p2sh_to_base58(dstate, dstate->config.testnet,
					redeemhash);

	start_bitcoin_cli(dstate, process_importaddress, NULL, NULL,
			  "importaddress", p2shaddr, "", "false", NULL);
	tal_free(p2shaddr);
}

static void process_transactions(struct bitcoin_cli *bcli)
{
	const jsmntok_t *tokens, *t, *end;
	bool valid;
	void (*cb)(struct lightningd_state *dstate,
		   const struct sha256_double *txid,
		   int confirmations, bool is_coinbase,
		   const struct sha256_double *blkhash) = bcli->cb;

	if (!bcli->output)
		fatal("%s failed", bcli_args(bcli));

	tokens = json_parse_input(bcli->output, bcli->output_bytes, &valid);
	if (!tokens)
		fatal("%s: %s response",
		      bcli_args(bcli),
		      valid ? "partial" : "invalid");

	if (tokens[0].type != JSMN_ARRAY)
		fatal("listtransactions: %s gave non-array (%.*s)?",
		      bcli_args(bcli),
		      (int)bcli->output_bytes, bcli->output);

	end = json_next(tokens);
	for (t = tokens + 1; t < end; t = json_next(t)) {
		struct sha256_double txid, blkhash;
		const jsmntok_t *txidtok, *conftok, *blkindxtok, *blktok;
		unsigned int conf;
		bool is_coinbase;

		txidtok = json_get_member(bcli->output, t, "txid");
		conftok = json_get_member(bcli->output, t, "confirmations");
		blkindxtok = json_get_member(bcli->output, t, "blockindex");
		if (!txidtok || !conftok)
			fatal("listtransactions: no %s field!",
			      txidtok ? "confirmations" : "txid");
		if (!bitcoin_txid_from_hex(bcli->output + txidtok->start,
					   txidtok->end - txidtok->start,
					   &txid)) {
			fatal("listtransactions: bad txid '%.*s'",
			      (int)(txidtok->end - txidtok->start),
			      bcli->output + txidtok->start);
		}
		if (!json_tok_number(bcli->output, conftok, &conf))
			fatal("listtransactions: bad confirmations '%.*s'",
			      (int)(conftok->end - conftok->start),
			      bcli->output + conftok->start);

		/* This can happen with zero conf. */
		blkindxtok = json_get_member(bcli->output, t, "blockindex");
		if (!blkindxtok) {
			if (conf != 0)
				fatal("listtransactions: no blockindex");
			is_coinbase = false;
		} else {
			unsigned int blkidx;
			if (conf == 0)
				fatal("listtransactions: expect no blockindex");
			if (!json_tok_number(bcli->output, blkindxtok, &blkidx))
				fatal("listtransactions: bad blockindex '%.*s'",
				      (int)(blkindxtok->end - blkindxtok->start),
				      bcli->output + blkindxtok->start);
			is_coinbase = (blkidx == 0);

			blktok = json_get_member(bcli->output, t, "blockhash");
			if (!blktok)
				fatal("listtransactions: no blockhash field!");

			if (!hex_decode(bcli->output + blktok->start,
					blktok->end - blktok->start,
					&blkhash, sizeof(blkhash))) {
				fatal("listtransactions: bad blockhash '%.*s'",
				      (int)(blktok->end - blktok->start),
				      bcli->output + blktok->start);
			}
		}
		/* FIXME: log txid, blkid */
		log_debug(bcli->dstate->base_log,
			  "txid %02x%02x%02x%02x..., conf %u, coinbase %u",
			  txid.sha.u.u8[0], txid.sha.u.u8[1],
			  txid.sha.u.u8[2], txid.sha.u.u8[3],
			  conf, is_coinbase);

		cb(bcli->dstate, &txid, conf, is_coinbase,
		   conf ? &blkhash : NULL);
	}
}

void bitcoind_poll_transactions(struct lightningd_state *dstate,
				void (*cb)(struct lightningd_state *dstate,
					   const struct sha256_double *txid,
					   int confirmations,
					   bool is_coinbase,
					   const struct sha256_double *blkhash))
{
	/* FIXME: Iterate and detect duplicates. */
	start_bitcoin_cli(dstate, process_transactions, cb, NULL,
			  "listtransactions", "*", "100000", "0", "true",
			  NULL);
}

struct txid_lookup {
	char txidhex[sizeof(struct sha256_double) * 2 + 1];
	void *cb_arg;
};

static void process_rawtx(struct bitcoin_cli *bcli)
{
	struct bitcoin_tx *tx;
	struct txid_lookup *lookup = bcli->cb_arg;
	void (*cb)(struct lightningd_state *dstate,
		   const struct bitcoin_tx *tx, void *arg) = bcli->cb;

	if (!bcli->output)
		fatal("%s: unknown txid?", bcli_args(bcli));

	tx = bitcoin_tx_from_hex(bcli, bcli->output, bcli->output_bytes);
 	if (!tx)
		fatal("%s: bad txid: %.*s?",
		      bcli_args(bcli),
		      (int)bcli->output_bytes, (char *)bcli->output);
	cb(bcli->dstate, tx, lookup->cb_arg);
	tal_free(lookup);
}

static void process_tx(struct bitcoin_cli *bcli)
{
	const jsmntok_t *tokens, *hex;
	bool valid;
	struct bitcoin_tx *tx;
	void (*cb)(struct lightningd_state *dstate,
		   const struct bitcoin_tx *tx, void *arg) = bcli->cb;
	struct txid_lookup *lookup = bcli->cb_arg;

	/* Failed?  Try getrawtransaction instead */
	if (!bcli->output) {
		start_bitcoin_cli(bcli->dstate, process_rawtx, cb, lookup,
				  "getrawtransaction", lookup->txidhex, NULL);
		return;
	}

	tokens = json_parse_input(bcli->output, bcli->output_bytes, &valid);
	if (!tokens)
		fatal("%s: %s response (%.*s)?",
		      bcli_args(bcli),
		      valid ? "partial" : "invalid",
		      (int)bcli->output_bytes, bcli->output);
	if (tokens[0].type != JSMN_OBJECT)
		fatal("%s: gave non-object (%.*s)?",
		      bcli_args(bcli),
		      (int)bcli->output_bytes, bcli->output);
	hex = json_get_member(bcli->output, tokens, "hex");
	if (!hex)
		fatal("%s: had no hex member (%.*s)?",
		      bcli_args(bcli),
		      (int)bcli->output_bytes, bcli->output);

	tx = bitcoin_tx_from_hex(bcli, bcli->output + hex->start,
				 hex->end - hex->start);
	if (!tx)
		fatal("%s: had bad hex member (%.*s)?",
		      bcli_args(bcli),
		      hex->end - hex->start, bcli->output + hex->start);
	cb(bcli->dstate, tx, lookup->cb_arg);
	tal_free(lookup);
}

/* FIXME: Cache! */
void bitcoind_txid_lookup_(struct lightningd_state *dstate,
			   const struct sha256_double *txid,
			   void (*cb)(struct lightningd_state *dstate,
				      const struct bitcoin_tx *tx,
				      void *arg),
			   void *arg)
{
	struct txid_lookup *lookup = tal(dstate, struct txid_lookup);

	/* We stash this here, and place lookup into cb_arg */
	lookup->cb_arg = arg;
	if (!bitcoin_txid_to_hex(txid, lookup->txidhex, sizeof(lookup->txidhex)))
		fatal("Incorrect txid size");
	start_bitcoin_cli(dstate, process_tx, cb, lookup,
			  "gettransaction", lookup->txidhex, NULL);
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

static void process_getblock_for_mediantime(struct bitcoin_cli *bcli)
{
	const jsmntok_t *tokens, *mediantime;
	bool valid;

	log_debug(bcli->dstate->base_log, "Got getblock result");
	if (!bcli->output)
		fatal("%s failed", bcli_args(bcli));

	tokens = json_parse_input(bcli->output, bcli->output_bytes, &valid);
	if (!tokens)
		fatal("%s: %s response",
		      bcli_args(bcli),
		      valid ? "partial" : "invalid");

	if (tokens[0].type != JSMN_OBJECT)
		fatal("%s: gave non-object (%.*s)?",
		      bcli_args(bcli),
		      (int)bcli->output_bytes, bcli->output);

	mediantime = json_get_member(bcli->output, tokens, "mediantime");
	if (!mediantime)
		fatal("%s: gave no mediantime field (%.*s)?",
		      bcli_args(bcli),
		      (int)bcli->output_bytes, bcli->output);

	if (!json_tok_number(bcli->output, mediantime, bcli->cb_arg))
		fatal("%s: gave invalud mediantime (%.*s)?",
		      bcli_args(bcli),
		      mediantime->end - mediantime->start,
		      bcli->output + mediantime->start);

	log_debug(bcli->dstate->base_log, "mediantime = %u",
		  *(u32 *)bcli->cb_arg);
}
	
void bitcoind_get_mediantime(struct lightningd_state *dstate,
			     const struct sha256_double *blockid,
			     u32 *mediantime)
{
	char hex[hex_str_size(sizeof(*blockid))];

	hex_encode(blockid, sizeof(*blockid), hex, sizeof(hex));
	start_bitcoin_cli(dstate, process_getblock_for_mediantime,
			  NULL, mediantime,
			  "getblock", hex, NULL);
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
		if (!hex_decode(bcli->output + hash->start,
				hash->end - hash->start,
				&tips[i], sizeof(tips[i])))
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

/* We append normalized ones, so block contains both.  Yuk! */
static void normalize_txids(struct lightningd_state *dstate,
			    const struct bitcoin_tx *tx,
			    struct normalizing *norm)
{
	size_t num = tal_count(norm->txids) / 2;
	normalized_txid(tx, &norm->txids[num + norm->i]);

	norm->i++;
	if (norm->i == num) {
		norm->cb(dstate, &norm->blkid, &norm->prevblk, norm->txids,
			 norm->mediantime, norm->cb_arg);
		tal_free(norm);
		return;
	}
	bitcoind_txid_lookup(dstate, &norm->txids[norm->i],
			     normalize_txids, norm);
}
	
static void process_getblock(struct bitcoin_cli *bcli)
{
	const jsmntok_t *tokens, *prevblk_tok, *txs_tok,
		*mediantime_tok, *blkid_tok, *t, *end;
	bool valid;
	u32 mediantime;
	struct sha256_double *txids;
	struct sha256_double *prevblk, blkid;
	size_t i;
	struct normalizing *norm = tal(bcli->dstate, struct normalizing);

	log_debug(bcli->dstate->base_log, "Got getblock result");
	if (!bcli->output)
		fatal("%s failed", bcli_args(bcli));

	tokens = json_parse_input(bcli->output, bcli->output_bytes, &valid);
	if (!tokens)
		fatal("%s: %s response",
		      bcli_args(bcli),
		      valid ? "partial" : "invalid");

	if (tokens[0].type != JSMN_OBJECT)
		fatal("%s: gave non-object (%.*s)?",
		      bcli_args(bcli),
		      (int)bcli->output_bytes, bcli->output);

	mediantime_tok = json_get_member(bcli->output, tokens, "mediantime");
	if (!mediantime_tok)
		fatal("%s: gave no mediantime field (%.*s)?",
		      bcli_args(bcli),
		      (int)bcli->output_bytes, bcli->output);

	if (!json_tok_number(bcli->output, mediantime_tok, &mediantime))
		fatal("%s: gave invalid mediantime (%.*s)?",
		      bcli_args(bcli),
		      mediantime_tok->end - mediantime_tok->start,
		      bcli->output + mediantime_tok->start);

	/* Genesis block doesn't have this! */
	prevblk_tok = json_get_member(bcli->output, tokens, "previousblockhash");
	if (prevblk_tok) {
		prevblk = tal(bcli, struct sha256_double);
		if (!hex_decode(bcli->output + prevblk_tok->start,
				prevblk_tok->end - prevblk_tok->start,
				prevblk, sizeof(*prevblk))) {
			fatal("%s: bad previousblockhash '%.*s'",
			      bcli_args(bcli),
			      (int)(prevblk_tok->end - prevblk_tok->start),
			      bcli->output + prevblk_tok->start);
		}
	} else
		prevblk = NULL;

	blkid_tok = json_get_member(bcli->output, tokens, "hash");
	if (!blkid_tok)
		fatal("%s: gave no hash field (%.*s)?",
		      bcli_args(bcli),
		      (int)bcli->output_bytes, bcli->output);

	if (!hex_decode(bcli->output + blkid_tok->start,
			blkid_tok->end - blkid_tok->start,
			&blkid, sizeof(blkid))) {
		fatal("%s: bad hash '%.*s'",
		      bcli_args(bcli),
		      (int)(blkid_tok->end - blkid_tok->start),
		      bcli->output + blkid_tok->start);
	}

	txs_tok = json_get_member(bcli->output, tokens,	"tx");
	if (!txs_tok)
		fatal("%s: gave no tx field (%.*s)?",
		      bcli_args(bcli),
		      (int)bcli->output_bytes, bcli->output);

	if (txs_tok->type != JSMN_ARRAY)
		fatal("%s: gave non-array txs field (%.*s)?",
		      bcli_args(bcli),
		      (int)bcli->output_bytes, bcli->output);

	/* It's a flat array of strings, so we can just use tok->size here. */
	txids = tal_arr(bcli, struct sha256_double, txs_tok->size);
	end = json_next(txs_tok);
	for (i = 0, t = txs_tok + 1; t < end; t = json_next(t), i++) {
		assert(i < txs_tok->size);
		if (!bitcoin_txid_from_hex(bcli->output + t->start,
					   t->end - t->start,
					   &txids[i]))
			fatal("%s: gave bad txid for %zu'th tx (%.*s)?",
			      bcli_args(bcli), i,
			      (int)bcli->output_bytes, bcli->output);
	}
	/* We must have coinbase, at least! */
	if (i == 0)
		fatal("%s: gave empty txids array (%.*s)?",
		      bcli_args(bcli), (int)bcli->output_bytes, bcli->output);

	log_debug(bcli->dstate->base_log,
		  "%.*s: mediantime = %u, prevhash=%.*s, %zu txids",
		  (int)(blkid_tok->end - blkid_tok->start),
		  bcli->output + blkid_tok->start,
		  mediantime,
		  prevblk_tok ? (int)(prevblk_tok->end - prevblk_tok->start) : 0,
		  prevblk_tok ? bcli->output + prevblk_tok->start : NULL,
		  i);

	/* FIXME: After segwitness, all txids will be "normalized" */
	norm->i = 0;
	norm->blkid = blkid;
	norm->prevblk = *prevblk;
	norm->txids = tal_dup_arr(norm, struct sha256_double, txids,
				  tal_count(txids), tal_count(txids));
	norm->mediantime = mediantime;
	norm->cb = bcli->cb;
	norm->cb_arg = bcli->cb_arg;

	bitcoind_txid_lookup(bcli->dstate, &norm->txids[0],
			     normalize_txids, norm);
}

void bitcoind_getblock_(struct lightningd_state *dstate,
			const struct sha256_double *blockid,
			void (*cb)(struct lightningd_state *dstate,
				   struct sha256_double *blkid,
				   struct sha256_double *prevblock,
				   struct sha256_double *txids,
				   u32 mediantime,
				   void *arg),
			void *arg)
{
	char hex[hex_str_size(sizeof(*blockid))];

	hex_encode(blockid, sizeof(*blockid), hex, sizeof(hex));
	start_bitcoin_cli(dstate, process_getblock, cb, arg,
			  "getblock", hex, NULL);
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
	    || !hex_decode(bcli->output, bcli->output_bytes-1,
			   &blkid, sizeof(blkid))) {
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
