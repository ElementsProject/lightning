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
#include "protobuf_convert.h"
#include "funding.h"
#include "gather_updates.h"
#include "version.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenChannel *o1, *o2;
	OpenAnchor *a;
	struct bitcoin_tx *commit;
	u8 *subscript;
	struct pubkey pubkey1, pubkey2;
	struct bitcoin_signature sig;
	struct privkey privkey;
	bool testnet;
	struct sha256 rhash;
	struct channel_state *cstate;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <open-anchor-file1> <commit-key1> [<commit-sig>]\n"
			   "Check the commit sig is valid (either in open-anchor or commit-sig packet)",
			   "Print this message.");
	opt_register_version();

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 5 && argc != 6)
		opt_usage_exit_fail("Expected 4 or 5 arguments");

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	a = pkt_from_file(argv[3], PKT__PKT_OPEN_ANCHOR)->open_anchor;

	if (!key_from_base58(argv[4], strlen(argv[4]), &testnet, &privkey, &pubkey1))
		errx(1, "Invalid private key '%s'", argv[4]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[4]);

	sig.stype = SIGHASH_ALL;
	if (argc == 6) {
		OpenCommitSig *cs = pkt_from_file(argv[5],
						  PKT__PKT_OPEN_COMMIT_SIG)
			->open_commit_sig;
		if (!proto_to_signature(cs->sig, &sig.sig))
			errx(1, "Bad signature in %s", argv[5]);
	} else {
		if (!proto_to_signature(a->commit_sig, &sig.sig))
			errx(1, "Bad signature in %s", argv[3]);
	}

	/* Pubkey well-formed? */
	if (!proto_to_pubkey(o2->commit_key, &pubkey2))
		errx(1, "Invalid o2 commit_key");

	if (is_funder(o1) == is_funder(o2))
		errx(1, "Must be exactly one funder");

	cstate = initial_funding(ctx, is_funder(o1), a->amount,
				 commit_fee(o1->commitment_fee,
					    o2->commitment_fee));
	if (!cstate)
		errx(1, "Invalid open combination (need to cover fees)");
	
	/* Now create our commitment tx. */
	proto_to_sha256(o1->revocation_hash, &rhash);
	commit = commit_tx_from_pkts(ctx, o1, o2, a, &rhash, cstate);

	/* Check signature. */
	subscript = bitcoin_redeem_2of2(ctx, &pubkey1, &pubkey2);
	if (!check_tx_sig(commit, 0, subscript, tal_count(subscript),
			  &pubkey2, &sig))
		errx(1, "Their signature invalid");

	tal_free(ctx);
	return 0;
}

