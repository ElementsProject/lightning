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
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <errno.h>
#include <inttypes.h>

#define BITCOIN_CLI "bitcoin-cli"

static char **gather_args(const tal_t *ctx, const char *cmd, va_list ap)
{
	size_t n = 2;
	char **args = tal_arr(ctx, char *, n+1);

	args[0] = BITCOIN_CLI;
	args[1] = cast_const(char *, cmd);

	while ((args[n] = va_arg(ap, char *)) != NULL) {
		args[n] = tal_strdup(args, args[n]);
		n++;
		tal_resize(&args, n + 1);
	}
	return args;
}

struct bitcoin_cli {
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

static void bcli_finished(struct io_conn *conn, struct bitcoin_cli *bcli)
{
	int ret, status;

	/* FIXME: If we waited for SIGCHILD, this could never hang! */
	ret = waitpid(bcli->pid, &status, 0);
	if (ret != bcli->pid)
		fatal("bitcoind: '%s' '%s' %s",
		      bcli->args[0], bcli->args[1],
		      ret == 0 ? "not exited?" : strerror(errno));

	if (!WIFEXITED(status))
		fatal("bitcoind: '%s' '%s' died with signal %i",
		      bcli->args[0], bcli->args[1],
		      WTERMSIG(status));

	if (WEXITSTATUS(status) != 0)
		fatal("bitcoind: '%s' '%s' failed (%i '%.*s')",
		      bcli->args[0], bcli->args[1], WEXITSTATUS(status),
		      (int)bcli->output_bytes, bcli->output);

	assert(bcli->dstate->bitcoind_in_progress);
	bcli->dstate->bitcoind_in_progress--;
	bcli->process(bcli);
}

static void
start_bitcoin_cli(struct lightningd_state *dstate,
		  void (*process)(struct bitcoin_cli *),
		  void *cb, void *cb_arg,
		  char *cmd, ...)
{
	va_list ap;
	struct bitcoin_cli *bcli = tal(dstate, struct bitcoin_cli);
	struct io_conn *conn;

	bcli->dstate = dstate;
	bcli->process = process;
	bcli->cb = cb;
	bcli->cb_arg = cb_arg;
	va_start(ap, cmd);
	bcli->args = gather_args(bcli, cmd, ap);
	va_end(ap);

	bcli->pid = pipecmdarr(&bcli->fd, NULL, &bcli->fd, bcli->args);
	if (bcli->pid < 0)
		fatal("%s exec failed: %s", bcli->args[0], strerror(errno));

	conn = io_new_conn(dstate, bcli->fd, output_init, bcli);
	tal_steal(conn, bcli);
	dstate->bitcoind_in_progress++;
	io_set_finish(conn, bcli_finished, bcli);
}

static void process_importaddress(struct bitcoin_cli *bcli)
{
	if (bcli->output_bytes != 0)
		fatal("bitcoind: '%s' '%s' unexpeced output '%.*s'",
		      bcli->args[0], bcli->args[1],
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
		   int confirmations) = bcli->cb;

	tokens = json_parse_input(bcli->output, bcli->output_bytes, &valid);
	if (!tokens)
		fatal("bitcoind: '%s' '%s' %s response",
		      bcli->args[0], bcli->args[1],
		      valid ? "partial" : "invalid");

	if (tokens[0].type != JSMN_ARRAY)
		fatal("listtransactions: '%s' '%s' gave non-array (%.*s)?",
		      bcli->args[0], bcli->args[1],
		      (int)bcli->output_bytes, bcli->output);

	end = json_next(tokens);
	for (t = tokens + 1; t < end; t = json_next(t)) {
		struct sha256_double txid;
		const jsmntok_t *txidtok, *conftok;
		long int conf;
		char *end;

		txidtok = json_get_member(bcli->output, t, "txid");
		conftok = json_get_member(bcli->output, t, "confirmations");
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
		conf = strtol(bcli->output + conftok->start, &end, 10);
		if (end != bcli->output + conftok->end)
			fatal("listtransactions: bad confirmations '%.*s'",
			      (int)(conftok->end - conftok->start),
			      bcli->output + conftok->start);

		/* FIXME: log txid */
		log_debug(bcli->dstate->base_log,
			  "txid %02x%02x%02x%02x..., conf %li",
			  txid.sha.u.u8[0], txid.sha.u.u8[1],
			  txid.sha.u.u8[2], txid.sha.u.u8[3],
			  conf);

		cb(bcli->dstate, &txid, conf);
	}
}

void bitcoind_poll_transactions(struct lightningd_state *dstate,
				void (*cb)(struct lightningd_state *dstate,
					   const struct sha256_double *txid,
					   int confirmations))
{
	/* FIXME: Iterate and detect duplicates. */
	start_bitcoin_cli(dstate, process_transactions, cb, NULL,
			  "listtransactions", "*", "100000", "0", "true",
			  NULL);
}

static void process_rawtx(struct bitcoin_cli *bcli)
{
	struct bitcoin_tx *tx;
	void (*cb)(struct lightningd_state *dstate,
		   const struct bitcoin_tx *tx, void *arg) = bcli->cb;

	tx = bitcoin_tx_from_hex(bcli, bcli->output, bcli->output_bytes);
	if (!tx)
		fatal("Unknown txid (output %.*s)",
		      (int)bcli->output_bytes, (char *)bcli->output);
	cb(bcli->dstate, tx, bcli->cb_arg);
}

/* FIXME: Cache! */
void bitcoind_txid_lookup_(struct lightningd_state *dstate,
			   const struct sha256_double *txid,
			   void (*cb)(struct lightningd_state *dstate,
				      const struct bitcoin_tx *tx,
				      void *arg),
			   void *arg)
{
	char txidhex[hex_str_size(sizeof(*txid))];

	if (!bitcoin_txid_to_hex(txid, txidhex, sizeof(txidhex)))
		fatal("Incorrect txid size");
	start_bitcoin_cli(dstate, process_rawtx, cb, arg,
			  "getrawtransaction", txidhex, NULL);
}

static void process_sendrawrx(struct bitcoin_cli *bcli)
{
	struct sha256_double txid;
	const char *out = (char *)bcli->output;

	/* We expect a txid, plus \n */
	if (bcli->output_bytes == 0
	    || !bitcoin_txid_from_hex(out, bcli->output_bytes-1, &txid))
		fatal("sendrawtransaction failed: %.*s",
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

static void process_sendtoaddress(struct bitcoin_cli *bcli)
{
	const char *out = (char *)bcli->output;
	char *txidstr;

	/* We expect a txid (followed by \n, vs hex_str_size including \0) */
	if (bcli->output_bytes != hex_str_size(sizeof(struct sha256_double)))
		fatal("sendtoaddress failed: %.*s",
		      (int)bcli->output_bytes, out);

	txidstr = tal_strndup(bcli, out, bcli->output_bytes-1);
	log_debug(bcli->dstate->base_log, "sendtoaddress gave %s", txidstr);

	/* Now we need the raw transaction. */
	start_bitcoin_cli(bcli->dstate, process_rawtx, bcli->cb, bcli->cb_arg,
			  "getrawtransaction", txidstr, NULL);
}

void bitcoind_create_payment(struct lightningd_state *dstate,
			     const char *addr,
			     u64 satoshis,
			     void (*cb)(struct lightningd_state *dstate,
					const struct bitcoin_tx *tx,
					struct peer *peer),
			     struct peer *peer)
{
	char amtstr[STR_MAX_CHARS(satoshis) * 2 + 1];
	sprintf(amtstr, "%"PRIu64 "." "%08"PRIu64,
		satoshis / 100000000, satoshis % 100000000);
	
	start_bitcoin_cli(dstate, process_sendtoaddress, cb, peer,
			  "sendtoaddress", addr, amtstr, NULL);
}

/* We make sure they have walletbroadcast=0, so we don't broadcast
 * the anchor. */
void check_bitcoind_config(struct lightningd_state *dstate)
{
	void *ctx = tal(dstate, char);
	char *path, *config, **lines;
	size_t i;
	bool nowalletbroadcast = false;
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
			       "^[ \t]*walletbroadcast[ \t]*=[ \t]*0"))
			nowalletbroadcast = true;
		else if (tal_strreg(ctx, lines[i],
				    "^[ \t]*testnet[ \t]*=[ \t]*([01])", &str))
			testnet = atoi(str);
		else if (tal_strreg(ctx, lines[i],
				    "^[ \t]*regtest[ \t]*=[ \t]*([01])", &str))
			regtest = atoi(str);
	}

	if (!nowalletbroadcast)
		log_unusual(dstate->base_log,
			    "%s does not contain walletbroadcast=0",
			    path);
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
