#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>
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
	OpenAnchor *oa1;
	OpenEscapeSigs *oe2;
	struct bitcoin_tx *tx;
	struct sha256 escape_secret, escape_hash1, escape_hash2, expect;
	struct sha256_double anchor_txid1;
	struct bitcoin_signature our_sig, their_sig;
	struct privkey privkey;
	u8 *redeemscript;
	bool testnet;
	bool fast_escape = false;
	struct pubkey pubkey1, pubkey2, final2;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <open-anchor-file1> <escape-sigs-file2> <escape-privkey> <escape-secret>\n"
			   "Create the escape transaction",
			   "Print this message.");
	opt_register_noarg("--fast", opt_set_bool, &fast_escape,
			   "Generate fast escape transaction"
			   " (instead of normal escape)");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 7)
		opt_usage_exit_fail("Expected 6 arguments");

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	proto_to_sha256(o1->escape_hash, &escape_hash1);
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	proto_to_sha256(o2->escape_hash, &escape_hash2);
	if (!proto_to_pubkey(o2->commitkey, &pubkey2))
		errx(1, "Invalid o2 commit pubkey");
	if (!proto_to_pubkey(o2->final, &final2))
		errx(1, "Invalid o2 final pubkey");
	oa1 = pkt_from_file(argv[3], PKT__PKT_OPEN_ANCHOR)->open_anchor;
	oe2 = pkt_from_file(argv[4], PKT__PKT_OPEN_ESCAPE_SIGS)->open_escape_sigs;

	if (!key_from_base58(argv[5], strlen(argv[5]), &testnet, &privkey, &pubkey1))
		errx(1, "Invalid private key '%s'", argv[5]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[5]);

	if (!hex_decode(argv[6], strlen(argv[6]), &escape_secret,
			sizeof(escape_secret)))
		errx(1, "Invalid escape secret '%s' - need 256 hex bits", argv[6]);

	/* Make sure secret is correct. */
	sha256(&expect, &escape_secret, sizeof(escape_secret));
	if (!structeq(&expect, &escape_hash1))
		errx(1, "Escape secret not what we promised");

	proto_to_sha256(oa1->anchor_txid, &anchor_txid1.sha);

	their_sig.stype = our_sig.stype = SIGHASH_ALL;
	if (fast_escape) {
		if (!proto_to_signature(oe2->fast_escape, &their_sig.sig))
			errx(1, "Bad fast escape signature in oe2");
		tx = create_fast_escape_tx(ctx, o1, o2,
					   &anchor_txid1, oa1->index,
					   o1->total_input, o1->escape_fee);
	} else {
		if (!proto_to_signature(oe2->escape, &their_sig.sig))
			errx(1, "Bad escape signature in oe2");
		tx = create_escape_tx(ctx, o1, o2,
				      &anchor_txid1, oa1->index,
				      o1->total_input, o1->escape_fee);
	}
	if (!tx)
		errx(1, "Could not create transaction");

	/* Sign input for the anchor. */
	redeemscript = bitcoin_redeem_anchor(ctx, &pubkey1, &pubkey2,
					     &final2, &escape_hash1);
	if (!check_tx_sig(tx, 0, redeemscript, tal_count(redeemscript),
			  &final2, &their_sig))
		errx(1, "Invalid %sescape signature in oe2",
		     fast_escape ? "fast-" : "");

	if (!sign_tx_input(ctx, tx, 0,
			   redeemscript, tal_count(redeemscript),
			   &privkey, &pubkey1, &our_sig.sig))
		errx(1, "Could not sign transaction");

	/* Now create script. */
	tx->input[0].script
		= scriptsig_p2sh_anchor_escape(ctx, &their_sig, &our_sig,
					       &escape_secret,
					       redeemscript,
					       tal_count(redeemscript));
	tx->input[0].script_length = tal_count(tx->input[0].script);
	
	/* Print it out in hex. */
	if (!bitcoin_tx_write(STDOUT_FILENO, tx))
		err(1, "Writing out transaction");

	tal_free(ctx);
	return 0;
}
