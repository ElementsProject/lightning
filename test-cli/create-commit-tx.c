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
#include "commit_tx.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/privkey.h"
#include "find_p2sh_out.h"
#include "protobuf_convert.h"
#include <unistd.h>

/* FIXME: this code doesn't work if we're not the ones proposing the delta */
int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenChannel *o1, *o2;
	OpenAnchor *oa1, *oa2;
	Pkt *pkt;
	AnchorSpend mysigs = ANCHOR_SPEND__INIT;
	struct bitcoin_tx *commit;
	struct sha256_double anchor_txid1, anchor_txid2;
	struct sha256 escape_hash1, escape_hash2;
	struct privkey privkey;
	bool testnet;
	struct signature sigs[2];
	AnchorSpend *their_sigs;
	size_t i, inmap[2];
	struct pubkey pubkey1, pubkey2, final1, final2;
	int64_t delta;
	struct sha256 rhash;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <open-anchor-file1> <open-anchor-file2> <commit-privkey> [final-update-accept|open-commit-sig] [<updates>]\n"
			   "Create the signature needed for the commit transaction",
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

	if (!key_from_base58(argv[5], strlen(argv[5]), &testnet, &privkey, &pubkey1))
		errx(1, "Invalid private key '%s'", argv[5]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[5]);

	/* Get pubkeys */
	if (!proto_to_pubkey(o1->commitkey, &pubkey2))
		errx(1, "Invalid o1 pubkey");
	if (pubkey_len(&pubkey1) != pubkey_len(&pubkey2)
	    || memcmp(pubkey1.key, pubkey2.key, pubkey_len(&pubkey2)) != 0)
		errx(1, "o1 pubkey != this privkey");
	if (!proto_to_pubkey(o2->commitkey, &pubkey2))
		errx(1, "Invalid o2 pubkey");
	if (!proto_to_pubkey(o1->final, &final1))
		errx(1, "Invalid o1 final pubkey");
	if (!proto_to_pubkey(o2->final, &final2))
		errx(1, "Invalid o2 final pubkey");

	/* Their signature comes from open-commit or from update-accept. */
	pkt = any_pkt_from_file(argv[6]);

	switch (pkt->pkt_case) {
	case PKT__PKT_UPDATE_ACCEPT:
		their_sigs = pkt->update_accept->sigs;
		break;
	case PKT__PKT_OPEN_COMMIT_SIG:
		their_sigs = pkt->open_commit_sig->sigs;
		break;
	default:
		errx(1, "Unexpected packet type %u in %s",
		     pkt->pkt_case, argv[6]);
	}

	/* Initial revocation hash comes from open. */
	proto_to_sha256(o1->revocation_hash, &rhash);
	
	delta = 0;
	/* Figure out cumulative delta since anchors, update revocation hash */
	for (i = 7; i < argc; i++) {
		Update *u = pkt_from_file(argv[i], PKT__PKT_UPDATE)->update;
		delta += u->delta;
		proto_to_sha256(u->revocation_hash, &rhash);
	}

	/* Now create commitment tx to spend 2/2 outputs of anchors. */
	commit = create_commit_tx(ctx, o1, o2, &rhash, delta,
				  &anchor_txid1, oa1->index, o1->total_input,
				  &anchor_txid2, oa2->index, o2->total_input,
				  inmap);

	/* If contributions don't exceed fees, this fails. */
	if (!commit)
		errx(1, "Bad commit amounts");

	if (!check_anchor_spend(commit, inmap,
				&pubkey1, &final1, &escape_hash1,
				&pubkey2, &final2, &escape_hash2,
				&pubkey2, their_sigs))
		errx(1, "Bad signatures");

	/* We generate our signatures. */
	if (!sign_anchor_spend(commit, inmap,
			       &pubkey1, &final1, &escape_hash1,
			       &pubkey2, &final2, &escape_hash2,
			       &pubkey1, &privkey, sigs))
		errx(1, "Could not create signatures");

	/* populate_anchor_inscripts wants args in protobuf */
	mysigs.sig0 = signature_to_proto(ctx, &sigs[0]);
	mysigs.sig1 = signature_to_proto(ctx, &sigs[1]);

	/* Shouldn't fail, since we checked them in check_anchor_spend */
	if (!populate_anchor_inscripts(commit, commit, inmap, 
				       &pubkey1, &final1, &escape_hash1,
				       &pubkey2, &final2, &escape_hash2,
				       &mysigs, their_sigs))
		errx(1, "Malformed signatures");
	    
	/* Print it out in hex. */
	if (!bitcoin_tx_write(STDOUT_FILENO, commit))
		err(1, "Writing out transaction");

	tal_free(ctx);
	return 0;
}
