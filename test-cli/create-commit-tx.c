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
#include "commit_tx.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/privkey.h"
#include "find_p2sh_out.h"
#include "protobuf_convert.h"
#include "gather_updates.h"
#include "funding.h"
#include "version.h"
#include <unistd.h>

/* FIXME: this code doesn't work if we're not the ones proposing the delta */
int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenChannel *o1, *o2;
	OpenAnchor *a;
	struct bitcoin_tx *commit;
	struct privkey privkey;
	bool testnet;
	struct bitcoin_signature sig1, sig2;
	struct pubkey pubkey1, pubkey2;
	u8 *redeemscript;
	struct sha256 rhash;
	struct channel_state *cstate;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <open-anchor-file> <commit-privkey> [<updates>]\n"
			   "Create the signature needed for the commit transaction",
			   "Print this message.");
	opt_register_version();

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 5)
		opt_usage_exit_fail("Expected 4+ arguments");

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	a = pkt_from_file(argv[3], PKT__PKT_OPEN_ANCHOR)->open_anchor;

	if (!key_from_base58(argv[4], strlen(argv[4]), &testnet, &privkey, &pubkey1))
		errx(1, "Invalid private key '%s'", argv[4]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[4]);

	/* Get pubkeys */
	if (!proto_to_pubkey(o1->commit_key, &pubkey2))
		errx(1, "Invalid o1 commit pubkey");
	if (!pubkey_eq(&pubkey1, &pubkey2))
		errx(1, "o1 pubkey != this privkey");
	if (!proto_to_pubkey(o2->commit_key, &pubkey2))
		errx(1, "Invalid o2 commit pubkey");

	sig2.stype = SIGHASH_ALL;

	cstate = gather_updates(ctx, o1, o2, a, commit_fee(o1, o2), argv + 5,
				NULL, &rhash, NULL, &sig2.sig);

	redeemscript = bitcoin_redeem_2of2(ctx, &pubkey1, &pubkey2);

	/* Now create commitment tx to spend 2/2 output of anchor. */
	commit = create_commit_tx(ctx, o1, o2, a, &rhash, cstate);

	/* This only fails on malformed packets */
	if (!commit)
		errx(1, "Malformed packets");

	/* We generate our signature. */
	sig1.stype = SIGHASH_ALL;
	sign_tx_input(ctx, commit, 0, redeemscript, tal_count(redeemscript),
		      &privkey, &pubkey1, &sig1.sig);

	/* Check it works with theirs... */
	if (!check_2of2_sig(commit, 0, redeemscript, tal_count(redeemscript),
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
