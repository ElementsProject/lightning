#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include "lightning.pb-c.h"
#include "bitcoin/base58.h"
#include "pkt.h"
#include "bitcoin/script.h"
#include "permute_tx.h"
#include "bitcoin/signature.h"
#include "bitcoin/pubkey.h"
#include "close_tx.h"
#include "find_p2sh_out.h"
#include "protobuf_convert.h"
#include "gather_updates.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenChannel *o1, *o2;
	OpenAnchor *a;
	struct bitcoin_tx *close_tx;
	struct bitcoin_signature sig1, sig2;
	struct pubkey pubkey1, pubkey2;
	u8 *redeemscript;
	CloseChannel *close;
	CloseChannelComplete *closecomplete;
	uint64_t our_amount, their_amount;

	err_set_progname(argv[0]);

	/* FIXME: Take update.pbs to adjust channel */
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <open-anchor-file> <close-protobuf> <close-complete-protobuf> [update-protobuf]...\n"
			   "Create the close transaction from the signatures",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 6)
		opt_usage_exit_fail("Expected 5+ arguments");

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	a = pkt_from_file(argv[3], PKT__PKT_OPEN_ANCHOR)->open_anchor;
	close = pkt_from_file(argv[4], PKT__PKT_CLOSE)->close;
	closecomplete = pkt_from_file(argv[5], PKT__PKT_CLOSE_COMPLETE)->close_complete;

	/* Pubkeys well-formed? */
	if (!proto_to_pubkey(o1->commit_key, &pubkey1))
		errx(1, "Invalid o1 commit_key");
	if (!proto_to_pubkey(o2->commit_key, &pubkey2))
		errx(1, "Invalid o2 commit_key");
	
	/* Get delta by accumulting all the updates. */
	gather_updates(o1, o2, a, argv + 6, &our_amount, &their_amount,
		       NULL, NULL, NULL);

	/* This is what the anchor pays to; figure out which output. */
	redeemscript = bitcoin_redeem_2of2(ctx, &pubkey1, &pubkey2);

	/* Now create the close tx to spend 2/2 output of anchor. */
	close_tx = create_close_tx(ctx, o1, o2, a, our_amount, their_amount);

	/* Signatures well-formed? */
	sig1.stype = sig2.stype = SIGHASH_ALL;
	if (!proto_to_signature(close->sig, &sig1.sig))
		errx(1, "Invalid close-packet");
	if (!proto_to_signature(closecomplete->sig, &sig2.sig))
		errx(1, "Invalid closecomplete-packet");

	/* Combined signatures must validate correctly. */
	if (!check_2of2_sig(close_tx, 0, redeemscript, tal_count(redeemscript),
			    &pubkey1, &pubkey2, &sig1, &sig2))
		errx(1, "Signature failed");

	/* Create p2sh input for close_tx */
	close_tx->input[0].script = scriptsig_p2sh_2of2(close_tx, &sig1, &sig2,
						      &pubkey1, &pubkey2);
	close_tx->input[0].script_length = tal_count(close_tx->input[0].script);

	/* Print it out in hex. */
	if (!bitcoin_tx_write(STDOUT_FILENO, close_tx))
		err(1, "Writing out transaction");

	tal_free(ctx);
	return 0;
}
