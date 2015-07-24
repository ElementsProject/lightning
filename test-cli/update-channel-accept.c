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
#include "find_p2sh_out.h"
#include "protobuf_convert.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct sha256 seed, revocation_hash, their_rhash, escape_hash1, escape_hash2;
	OpenChannel *o1, *o2;
	OpenAnchor *oa1, *oa2;
	Update *update;
	struct bitcoin_tx *commit;
	struct sha256_double anchor_txid1, anchor_txid2;
	struct pkt *pkt;
	struct signature sigs[2];
	struct privkey privkey;
	bool testnet;
	struct pubkey pubkey1, pubkey2, final1, final2;
	int64_t delta;
	size_t i, inmap[2];

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<seed> <open-channel-file1> <open-channel-file2> <anchor-id-file1> <anchor-id-file2> <commit-privkey> <update-protobuf> [previous-updates]\n"
			   "Accept a new update message",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 6)
		opt_usage_exit_fail("Expected 5+ arguments");

	if (!hex_decode(argv[1], strlen(argv[1]), &seed, sizeof(seed)))
		errx(1, "Invalid seed '%s' - need 256 hex bits", argv[1]);
	
	o1 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	proto_to_sha256(o1->escape_hash, &escape_hash1);
	o2 = pkt_from_file(argv[3], PKT__PKT_OPEN)->open;
	proto_to_sha256(o2->escape_hash, &escape_hash2);
	oa1 = pkt_from_file(argv[4], PKT__PKT_OPEN_ANCHOR)->open_anchor;
	oa2 = pkt_from_file(argv[5], PKT__PKT_OPEN_ANCHOR)->open_anchor;
	proto_to_sha256(oa1->anchor_txid, &anchor_txid1.sha);
	proto_to_sha256(oa2->anchor_txid, &anchor_txid2.sha);

	if (!key_from_base58(argv[6], strlen(argv[6]), &testnet, &privkey, &pubkey1))
		errx(1, "Invalid private key '%s'", argv[6]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[6]);

	update = pkt_from_file(argv[7], PKT__PKT_UPDATE)->update;
	
	/* Figure out cumulative delta since anchor. */
	delta = update->delta;
	for (i = 8; i < argc; i++) {
		Update *u = pkt_from_file(argv[i], PKT__PKT_UPDATE)->update;
		delta += u->delta;
	}

	/* Get next revocation hash. */
	shachain_from_seed(&seed, argc - 7, &revocation_hash);
	sha256(&revocation_hash,
	       revocation_hash.u.u8, sizeof(revocation_hash.u.u8));
	
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

	/* Now create THEIR new commitment tx to spend 2/2 outputs of anchors. */
	proto_to_sha256(update->revocation_hash, &their_rhash);
	commit = create_commit_tx(ctx, o2, o1, &their_rhash, delta,
 				  &anchor_txid2, oa2->index, o2->total_input,
				  &anchor_txid1, oa1->index, o1->total_input,
				  inmap);

	/* If contributions don't exceed fees, this fails. */
	if (!commit)
		errx(1, "Delta too large");

	/* Sign it for them (since its theirs, reverse args). */
	if (!sign_anchor_spend(commit, inmap, &pubkey2, &final2, &escape_hash2,
			       &pubkey1, &final1, &escape_hash1,
			       &pubkey1, &privkey, sigs))
		errx(1, "Failed creating signatures");

	pkt = update_accept_pkt(ctx, sigs, &revocation_hash);
	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}

