#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include "lightning.pb-c.h"
#include "anchor.h"
#include "bitcoin/base58.h"
#include "pkt.h"
#include "bitcoin/script.h"
#include "permute_tx.h"
#include "bitcoin/signature.h"
#include "bitcoin/pubkey.h"
#include "close_tx.h"
#include "find_p2sh_out.h"
#include "protobuf_convert.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenChannel *o1, *o2;
	OpenAnchor *oa1, *oa2;
	struct bitcoin_tx *close_tx;
	struct sha256_double anchor_txid1, anchor_txid2;
	struct sha256 escape_hash1, escape_hash2;
	struct pubkey pubkey1, pubkey2, final1, final2;
	CloseChannel *close;
	CloseChannelComplete *closecomplete;
	size_t i, inmap[2];
	int64_t delta;

	err_set_progname(argv[0]);

	/* FIXME: Take update.pbs to adjust channel */
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <open-anchor-file1> <open-anchor-file2> <close-protobuf> <close-complete-protobuf> [update-protobuf]...\n"
			   "Create the close transaction from the signatures",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 7)
		opt_usage_exit_fail("Expected 6+ arguments");

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	proto_to_sha256(o1->escape_hash, &escape_hash1);
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	proto_to_sha256(o2->escape_hash, &escape_hash2);
	oa1 = pkt_from_file(argv[3], PKT__PKT_OPEN_ANCHOR)->open_anchor;
	oa2 = pkt_from_file(argv[4], PKT__PKT_OPEN_ANCHOR)->open_anchor;
	proto_to_sha256(oa1->anchor_txid, &anchor_txid1.sha);
	proto_to_sha256(oa2->anchor_txid, &anchor_txid2.sha);
	close = pkt_from_file(argv[5], PKT__PKT_CLOSE)->close;
	closecomplete = pkt_from_file(argv[6], PKT__PKT_CLOSE_COMPLETE)->close_complete;

	/* Pubkeys well-formed? */
	if (!proto_to_pubkey(o1->commitkey, &pubkey1))
		errx(1, "Invalid open-1 key");
	if (!proto_to_pubkey(o2->commitkey, &pubkey2))
		errx(1, "Invalid open-2 key");
	if (!proto_to_pubkey(o1->final, &final1))
 		errx(1, "Invalid o1 final pubkey");
	if (!proto_to_pubkey(o2->final, &final2))
 		errx(1, "Invalid o2 final pubkey");
	
	/* Get delta by accumulting all the updates. */
	delta = 0;
	for (i = 7; i < argc; i++) {
		Update *u = pkt_from_file(argv[i], PKT__PKT_UPDATE)->update;
		delta += u->delta;
	}	

	close_tx = create_close_tx(ctx, o1, o2, delta,
				   &anchor_txid1, oa1->index, o1->total_input,
				   &anchor_txid2, oa2->index, o2->total_input,
				   inmap);

	if (!check_anchor_spend(close_tx, inmap,
				&pubkey1, &final1, &escape_hash1,
				&pubkey2, &final2, &escape_hash2,
				&pubkey1, close->sigs))
		errx(1, "Close signature check failed");
	
	if (!check_anchor_spend(close_tx, inmap,
				&pubkey1, &final1, &escape_hash1,
				&pubkey2, &final2, &escape_hash2,
				&pubkey2, closecomplete->sigs))
		errx(1, "Closecomplete signature check failed");

	if (!populate_anchor_inscripts(close_tx, close_tx, inmap,
				       &pubkey1, &final1, &escape_hash1,
				       &pubkey2, &final2, &escape_hash2,
				       close->sigs,
				       closecomplete->sigs))
		errx(1, "Malformed signatures");
	
	/* Print it out in hex. */
	if (!bitcoin_tx_write(STDOUT_FILENO, close_tx))
		err(1, "Writing out transaction");

	tal_free(ctx);
	return 0;
}
