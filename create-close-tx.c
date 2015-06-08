/* My example:
 * ./create-close-tx A-anchor.tx A-open.pb B-open.pb A-close.pb B-close-complete.pb > A-close.tx
 */
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include "lightning.pb-c.h"
#include "anchor.h"
#include "base58.h"
#include "pkt.h"
#include "bitcoin_script.h"
#include "permute_tx.h"
#include "signature.h"
#include "pubkey.h"
#include "close_tx.h"
#include <openssl/ec.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenChannel *o1, *o2;
	struct bitcoin_tx *anchor, *close_tx;
	struct sha256_double anchor_txid;
	struct bitcoin_signature sig1, sig2;
	struct pubkey pubkey1, pubkey2;
	u8 *redeemscript, *p2sh, *tx_arr;
	char *tx_hex;
	CloseChannel *close;
	CloseChannelComplete *closecomplete;
	size_t i;

	err_set_progname(argv[0]);

	/* FIXME: Take update.pbs to adjust channel */
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<anchor-tx> <open-channel-file1> <open-channel-file2> <close-protobuf> <close-complete-protobuf>\n"
			   "Create the close transaction from the signatures",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 6)
		opt_usage_exit_fail("Expected 5 arguments");

	anchor = bitcoin_tx_from_file(ctx, argv[1]);
	o1 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[3], PKT__PKT_OPEN)->open;
	close = pkt_from_file(argv[4], PKT__PKT_CLOSE)->close;
	closecomplete = pkt_from_file(argv[5], PKT__PKT_CLOSE_COMPLETE)->close_complete;

	bitcoin_txid(anchor, &anchor_txid);

	/* Pubkeys well-formed? */
	if (!proto_to_pubkey(o1->anchor->pubkey, &pubkey1))
		errx(1, "Invalid anchor-1 key");
	if (!proto_to_pubkey(o2->anchor->pubkey, &pubkey2))
		errx(1, "Invalid anchor-2 key");
	
	/* This is what the anchor pays to; figure out which output. */
	redeemscript = bitcoin_redeem_2of2(ctx, &pubkey1, &pubkey2);

	/* This is the scriptPubKey commit tx will have */
	p2sh = scriptpubkey_p2sh(ctx, redeemscript);

	for (i = 0; i < anchor->output_count; i++) {
		if (anchor->output[i].script_length != tal_count(p2sh))
			continue;
		if (memcmp(anchor->output[i].script, p2sh, tal_count(p2sh)) == 0)
			break;
	}
	if (i == anchor->output_count)
		errx(1, "No matching output in %s", argv[1]);

	/* Now create the close tx to spend 2/2 output of anchor. */
	close_tx = create_close_tx(ctx, o1, o2, &anchor_txid, i);

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
	tx_arr = linearize_tx(ctx, close_tx);
	tx_hex = tal_arr(tx_arr, char, hex_str_size(tal_count(tx_arr)));
	hex_encode(tx_arr, tal_count(tx_arr), tx_hex, tal_count(tx_hex));

	if (!write_all(STDOUT_FILENO, tx_hex, strlen(tx_hex)))
		err(1, "Writing out transaction");

	tal_free(ctx);
	return 0;
}
