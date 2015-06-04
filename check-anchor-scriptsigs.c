/* My example:
 * ./check-anchor-scriptsigs A-open.pb B-open.pb A-anchor-scriptsigs.pb B-anchor-scriptsigs.pb A-commit.tx B-commit.tx > A-anchor.tx
 * ./check-anchor-scriptsigs B-open.pb A-open.pb B-anchor-scriptsigs.pb A-anchor-scriptsigs.pb B-commit.tx A-commit.tx > B-anchor.tx
 */
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/structeq/structeq.h>
#include "lightning.pb-c.h"
#include "anchor.h"
#include "base58.h"
#include "pkt.h"
#include "bitcoin_script.h"
#include "permute_tx.h"
#include "signature.h"
#include "commit_tx.h"
#include "pubkey.h"
#include <openssl/ec.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenChannel *o1, *o2;
	OpenAnchorScriptsigs *ss1, *ss2;
	struct bitcoin_tx *anchor, *commit1, *commit2;
	struct sha256_double txid;
	u8 *tx_arr;
	size_t *inmap, *outmap;
	char *tx_hex;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <anchor-sig2-1> <anchor-sigs2> <commit-tx1> <commit-tx2>\n"
			   "Output the anchor transaction by merging the scriptsigs",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 7)
		opt_usage_exit_fail("Expected 6 arguments");

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	ss1 = pkt_from_file(argv[3], PKT__PKT_OPEN_ANCHOR_SCRIPTSIGS)
		->open_anchor_scriptsigs;
	ss2 = pkt_from_file(argv[4], PKT__PKT_OPEN_ANCHOR_SCRIPTSIGS)
		->open_anchor_scriptsigs;
	commit1 = bitcoin_tx_from_file(ctx, argv[5]);
	commit2 = bitcoin_tx_from_file(ctx, argv[6]);

	anchor = anchor_tx_create(ctx, o1, o2, &inmap, &outmap);
	if (!anchor)
		errx(1, "Failed transaction merge");
	if (!anchor_add_scriptsigs(anchor, ss1, ss2, inmap))
		errx(1, "Wrong number of scriptsigs");

	bitcoin_txid(anchor, &txid);

	/* Now check that the txid is spent by the commitment txs we created */
	assert(commit1->input_count == 1 && commit2->input_count == 1);
	if (!structeq(&txid, &commit1->input[0].txid))
		errx(1, "%s doesn't spend this anchor", argv[5]);
	if (!structeq(&txid, &commit2->input[0].txid))
		errx(1, "%s doesn't spend this anchor", argv[6]);

	/* Print it out in hex. */
	tx_arr = linearize_tx(ctx, anchor);
	tx_hex = tal_arr(tx_arr, char, hex_str_size(tal_count(tx_arr)));
	hex_encode(tx_arr, tal_count(tx_arr), tx_hex, tal_count(tx_hex));

	if (!write_all(STDOUT_FILENO, tx_hex, strlen(tx_hex)))
		err(1, "Writing out anchor transaction");

	tal_free(ctx);
	return 0;
}

