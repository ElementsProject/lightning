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
#include "commit_tx.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/privkey.h"
#include "protobuf_convert.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenChannel *o1, *o2;
	OpenAnchor *oa1, *oa2;
	struct bitcoin_tx *commit;
	struct sha256 escape_hash1, escape_hash2;
	struct sha256_double anchor_txid1, anchor_txid2;
	struct pkt *pkt;
	struct signature sigs[2];
	struct privkey privkey;
	bool testnet;
	struct pubkey pubkey1, pubkey2, final1, final2;
	struct sha256 rhash;
	size_t inmap[2];

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <open-anchor-file1> <open-anchor-file2> <commit-privkey>\n"
			   "Create the signature needed for the commit transaction",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 6)
		opt_usage_exit_fail("Expected 5 arguments");

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	proto_to_sha256(o1->escape_hash, &escape_hash1);
	if (!proto_to_pubkey(o1->final, &final1))
		errx(1, "Invalid o1 final pubkey");
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	proto_to_sha256(o2->escape_hash, &escape_hash2);
	if (!proto_to_pubkey(o2->final, &final2))
		errx(1, "Invalid o2 final pubkey");
	if (!proto_to_pubkey(o2->commitkey, &pubkey2))
		errx(1, "Invalid o2 commit pubkey");
	oa1 = pkt_from_file(argv[3], PKT__PKT_OPEN_ANCHOR)->open_anchor;
	oa2 = pkt_from_file(argv[4], PKT__PKT_OPEN_ANCHOR)->open_anchor;

	if (!key_from_base58(argv[5], strlen(argv[5]), &testnet, &privkey, &pubkey1))
		errx(1, "Invalid private key '%s'", argv[5]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[5]);

	proto_to_sha256(oa1->anchor_txid, &anchor_txid1.sha);
	proto_to_sha256(oa2->anchor_txid, &anchor_txid2.sha);

	/* Now create THEIR commitment tx to spend outputs of anchors. */
	proto_to_sha256(o2->revocation_hash, &rhash);
	commit = create_commit_tx(ctx, o2, o1, &rhash, 0,
				  &anchor_txid2, oa2->index, o2->total_input,
				  &anchor_txid1, oa1->index, o1->total_input,
				  inmap);

	/* If contributions don't exceed fees, this fails. */
	if (!commit)
		errx(1, "Contributions %llu & %llu vs fees %llu & %llu",
		     (long long)o1->total_input,
		     (long long)o2->total_input,
		     (long long)o1->commitment_fee,
		     (long long)o2->commitment_fee);

	/* Since we're signing theirs, "my" and "their" args are backwards. */
	if (!sign_anchor_spend(commit, inmap,
			       &pubkey2, &final2, &escape_hash2,
			       &pubkey1, &final1, &escape_hash1,
			       &pubkey1, &privkey, sigs))
		errx(1, "Could not sign tx");

	pkt = open_commit_sig_pkt(ctx, sigs);
	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}

