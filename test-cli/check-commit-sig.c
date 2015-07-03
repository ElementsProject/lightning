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
#include "protobuf_convert.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenChannel *o1, *o2;
	OpenCommitSig *cs2;
	struct bitcoin_tx *anchor, *commit;
	struct sha256_double txid;
	u8 *subscript;
	size_t *inmap, *outmap;
	struct pubkey pubkey1, pubkey2;
	struct bitcoin_signature sig1, sig2;
	struct privkey privkey;
	bool testnet;
	struct sha256 rhash;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <commit-sig-2> <commit-key1>\n"
			   "Output the commitment transaction if both signatures are valid",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 5)
		opt_usage_exit_fail("Expected 4 arguments");

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	cs2 = pkt_from_file(argv[3], PKT__PKT_OPEN_COMMIT_SIG)->open_commit_sig;

	if (!key_from_base58(argv[4], strlen(argv[4]), &testnet, &privkey, &pubkey1))
		errx(1, "Invalid private key '%s'", argv[4]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[4]);

	/* Pubkey well-formed? */
	if (!proto_to_pubkey(o2->anchor->pubkey, &pubkey2))
		errx(1, "Invalid anchor-2 key");

	/* Get the transaction ID of the anchor. */
	anchor = anchor_tx_create(ctx, o1, o2, &inmap, &outmap);
	if (!anchor)
		errx(1, "Failed transaction merge");
	anchor_txid(anchor, &txid);

	/* Now create our commitment tx. */
	proto_to_sha256(o1->revocation_hash, &rhash);
	commit = create_commit_tx(ctx, o1, o2, &rhash, 0, &txid, outmap[0]);

	/* If contributions don't exceed fees, this fails. */
	if (!commit)
		errx(1, "Contributions %llu & %llu vs fees %llu & %llu",
		     (long long)o1->anchor->total,
		     (long long)o2->anchor->total,
		     (long long)o1->commitment_fee,
		     (long long)o2->commitment_fee);

	/* FIXME: Creating out signature just to check the script we create
	 * is overkill: if their signature and pubkey signed the commit txin,
	 * we're happy. */
	sig1.stype = SIGHASH_ALL;
	subscript = bitcoin_redeem_2of2(ctx, &pubkey1, &pubkey2);
	sign_tx_input(ctx, commit, 0, subscript, tal_count(subscript),
		      &privkey, &pubkey1, &sig1.sig);

	/* Signatures well-formed? */
	if (!proto_to_signature(cs2->sig, &sig2.sig))
		errx(1, "Invalid commit-sig-2");
	sig2.stype = SIGHASH_ALL;

	/* Combined signatures must validate correctly. */
	if (!check_2of2_sig(commit, 0, subscript, tal_count(subscript),
			    &pubkey1, &pubkey2, &sig1, &sig2))
		errx(1, "Signature failed");

	/* Create p2sh input for commit */
	commit->input[0].script = scriptsig_p2sh_2of2(commit, &sig1, &sig2,
						      &pubkey1, &pubkey2);
	commit->input[0].script_length = tal_count(commit->input[0].script);

	/* Print it out in hex. */
	if (!bitcoin_tx_write(STDOUT_FILENO, commit))
		err(1, "Writing out transaction");

	tal_free(ctx);
	return 0;
}

