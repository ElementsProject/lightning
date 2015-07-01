#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include <ccan/structeq/structeq.h>
#include "lightning.pb-c.h"
#include "anchor.h"
#include "bitcoin/base58.h"
#include "pkt.h"
#include "bitcoin/script.h"
#include "permute_tx.h"
#include "bitcoin/signature.h"
#include "commit_tx.h"
#include "bitcoin/pubkey.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenChannel *o1, *o2;
	OpenAnchorScriptsigs *ss1, *ss2;
	struct bitcoin_tx *anchor;
	struct sha256_double txid;
	size_t *inmap, *outmap;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <anchor-sig2-1> <anchor-sigs2>\n"
			   "Output the anchor transaction by merging the scriptsigs",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 5)
		opt_usage_exit_fail("Expected 6 arguments");

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	ss1 = pkt_from_file(argv[3], PKT__PKT_OPEN_ANCHOR_SCRIPTSIGS)
		->open_anchor_scriptsigs;
	ss2 = pkt_from_file(argv[4], PKT__PKT_OPEN_ANCHOR_SCRIPTSIGS)
		->open_anchor_scriptsigs;

	anchor = anchor_tx_create(ctx, o1, o2, &inmap, &outmap);
	if (!anchor)
		errx(1, "Failed transaction merge");
	if (!anchor_add_scriptsigs(anchor, ss1, ss2, inmap))
		errx(1, "Wrong number of scriptsigs");

	bitcoin_txid(anchor, &txid);

	if (!bitcoin_tx_write(STDOUT_FILENO, anchor))
		err(1, "Writing out anchor transaction");

	tal_free(ctx);
	return 0;
}

