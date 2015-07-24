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
#include "bitcoin/pubkey.h"
#include "bitcoin/privkey.h"
#include "close_tx.h"
#include "find_p2sh_out.h"
#include "protobuf_convert.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenChannel *o1, *o2;
	OpenAnchor *oa1, *oa2;
	struct sha256_double anchor_txid1, anchor_txid2;
	struct bitcoin_tx *close_tx;
	struct sha256 escape_hash1, escape_hash2;
	struct pkt *pkt;
	struct signature sigs[2];
	struct privkey privkey;
	bool testnet, complete = false;
	struct pubkey pubkey1, pubkey2, final1, final2;
	int64_t delta;
	size_t i, inmap[2];

	err_set_progname(argv[0]);

	/* FIXME: Take update.pbs to adjust channel */
	opt_register_noarg("--complete", opt_set_bool, &complete,
			   "Create a close_transaction_complete msg instead");
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <open-anchor-file1> <open-anchor-file2> <commit-privkey> [update-protobuf]...\n"
			   "Create the signature needed for the close transaction",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 6)
		opt_usage_exit_fail("Expected 5+ arguments");

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	proto_to_sha256(o1->escape_hash, &escape_hash1);
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	proto_to_sha256(o2->escape_hash, &escape_hash2);
	oa1 = pkt_from_file(argv[3], PKT__PKT_OPEN_ANCHOR)->open_anchor;
	oa2 = pkt_from_file(argv[4], PKT__PKT_OPEN_ANCHOR)->open_anchor;
	proto_to_sha256(oa1->anchor_txid, &anchor_txid1.sha);
	proto_to_sha256(oa2->anchor_txid, &anchor_txid2.sha);

	if (!key_from_base58(argv[5], strlen(argv[5]), &testnet, &privkey, &pubkey1))
		errx(1, "Invalid private key '%s'", argv[5]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[5]);

	/* Get delta by accumulting all the updates. */
	delta = 0;
	for (i = 6; i < argc; i++) {
		Update *u = pkt_from_file(argv[i], PKT__PKT_UPDATE)->update;
		delta += u->delta;
	}

	/* Get pubkeys */
	if (!proto_to_pubkey(o1->commitkey, &pubkey2))
		errx(1, "Invalid o1 commit pubkey");
	if (pubkey_len(&pubkey1) != pubkey_len(&pubkey2)
	    || memcmp(pubkey1.key, pubkey2.key, pubkey_len(&pubkey2)) != 0)
		errx(1, "o1 pubkey != this privkey");
	if (!proto_to_pubkey(o2->commitkey, &pubkey2))
		errx(1, "Invalid o2 commit pubkey");
	if (!proto_to_pubkey(o1->final, &final1))
		errx(1, "Invalid o1 final pubkey");
	if (!proto_to_pubkey(o2->final, &final2))
		errx(1, "Invalid o2 final pubkey");

	/* Now create the close tx to spend 2/2 outputs of anchors. */
	close_tx = create_close_tx(ctx, o1, o2, complete ? -delta : delta,
				   &anchor_txid1, oa1->index, o1->total_input,
				   &anchor_txid2, oa2->index, o2->total_input,
				   inmap);
	warnx("input[0].txid = %02x%02x%02x%02x...",
	      close_tx->input[0].txid.sha.u.u8[0],
	      close_tx->input[0].txid.sha.u.u8[1],
	      close_tx->input[0].txid.sha.u.u8[2],
	      close_tx->input[0].txid.sha.u.u8[3]);
	warnx("input[1].txid = %02x%02x%02x%02x...",
	      close_tx->input[1].txid.sha.u.u8[0],
	      close_tx->input[1].txid.sha.u.u8[1],
	      close_tx->input[1].txid.sha.u.u8[2],
	      close_tx->input[1].txid.sha.u.u8[3]);
	warnx("input %zu should be %02x%02x%02x%02x...",
	      inmap[0], 
	      anchor_txid1.sha.u.u8[0],
	      anchor_txid1.sha.u.u8[1],
	      anchor_txid1.sha.u.u8[2],
	      anchor_txid1.sha.u.u8[3]);

	/* Sign close. */
	if (!sign_anchor_spend(close_tx, inmap,
			       &pubkey1, &final1, &escape_hash1,
			       &pubkey2, &final2, &escape_hash2,
			       &pubkey1, &privkey, sigs))
		errx(1, "Failed creating signatures");

	if (complete)
		pkt = close_channel_complete_pkt(ctx, sigs);
	else
		pkt = close_channel_pkt(ctx, sigs);
	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}

