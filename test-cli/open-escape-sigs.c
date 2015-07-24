#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include "lightning.pb-c.h"
#include "anchor.h"
#include "bitcoin/base58.h"
#include "pkt.h"
#include "bitcoin/script.h"
#include "permute_tx.h"
#include "bitcoin/signature.h"
#include "escape_tx.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/privkey.h"
#include "protobuf_convert.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenChannel *o1, *o2;
	OpenAnchor *oa2;
	struct bitcoin_tx *escape;
	struct sha256 escape_hash2;
	struct sha256_double anchor_txid2;
	struct pkt *pkt;
	struct signature escape_sig, fast_escape_sig;
	struct privkey privkey;
	u8 *redeemscript;
	bool testnet;
	struct pubkey pubkey1, pubkey2, final1, final2;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <open-anchor-file2> <escape-privkey>\n"
			   "Create the signatures needed for the other side's escape transaction",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 5)
		opt_usage_exit_fail("Expected 4 arguments");

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	if (!proto_to_pubkey(o1->commitkey, &pubkey1))
		errx(1, "Invalid o1 commit pubkey");
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	proto_to_sha256(o2->escape_hash, &escape_hash2);
	if (!proto_to_pubkey(o2->final, &final2))
		errx(1, "Invalid o2 final pubkey");
	if (!proto_to_pubkey(o2->commitkey, &pubkey2))
		errx(1, "Invalid o2 commit pubkey");
	oa2 = pkt_from_file(argv[3], PKT__PKT_OPEN_ANCHOR)->open_anchor;

	if (!key_from_base58(argv[4], strlen(argv[4]), &testnet, &privkey, &final1))
		errx(1, "Invalid private key '%s'", argv[4]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[4]);

	proto_to_sha256(oa2->anchor_txid, &anchor_txid2.sha);

	/* Now create THEIR escape tx to spend output of their anchor. */
	escape = create_escape_tx(ctx, o2, o1, &anchor_txid2, oa2->index,
				  o2->total_input, o2->escape_fee);

	/* If contributions don't exceed fees, this fails. */
	if (!escape)
		errx(1, "Input %llu vs fees %llu",
		     (long long)o2->total_input,
		     (long long)o2->escape_fee);

	/* Sign input for their anchor. */
	redeemscript = bitcoin_redeem_anchor(ctx, &pubkey2, &pubkey1,
					     &final1, &escape_hash2);
	if (!sign_tx_input(ctx, escape, 0,
			   redeemscript, tal_count(redeemscript),
			   &privkey, &final1, &escape_sig))
		errx(1, "Could not sign their escape tx");

	/* Now create THEIR fast escape tx to spend output of their anchor. */
	escape = create_fast_escape_tx(ctx, o2, o1, &anchor_txid2, oa2->index,
				       o2->total_input, o2->escape_fee);
	/* If contributions don't exceed fees, this fails. */
	if (!escape)
		errx(1, "Input %llu vs fees %llu",
		     (long long)o2->total_input,
		     (long long)o2->escape_fee);

	/* It's spending the same output, so same redeemscript */
	if (!sign_tx_input(ctx, escape, 0,
			   redeemscript, tal_count(redeemscript),
			   &privkey, &final1, &fast_escape_sig))
		errx(1, "Could not sign their fast escape tx");

	pkt = open_escape_sig_pkt(ctx, &escape_sig, &fast_escape_sig);
	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}

