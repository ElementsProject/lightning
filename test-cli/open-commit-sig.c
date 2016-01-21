#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
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
	struct pkt *pkt;
	struct signature sig;
	struct privkey privkey;
	bool testnet;
	struct pubkey pubkey1, pubkey2;
	u8 *subscript;
	struct sha256 rhash;
	struct channel_state *cstate;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <open-anchor-file1> <commit-privkey>\n"
			   "Create the signature needed for the commit transaction",
			   "Print this message.");
	opt_register_version();

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 5)
		opt_usage_exit_fail("Expected 4 arguments");

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	a = pkt_from_file(argv[3], PKT__PKT_OPEN_ANCHOR)->open_anchor;
	
	if (!key_from_base58(secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						      | SECP256K1_CONTEXT_SIGN),
			     argv[4], strlen(argv[4]), &testnet, &privkey, &pubkey1))
		errx(1, "Invalid private key '%s'", argv[4]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[4]);

	if (is_funder(o1) == is_funder(o2))
		errx(1, "Must be exactly one funder");
	
	/* Now create THEIR commitment tx to spend 2/2 output of anchor. */
	cstate = initial_funding(ctx, is_funder(o2), a->amount,
				 commit_fee(o2->commitment_fee,
					    o1->commitment_fee));
	if (!cstate)
		errx(1, "Invalid open combination (too low for fees)");

	proto_to_sha256(o2->revocation_hash, &rhash);
	commit = commit_tx_from_pkts(ctx, o2, o1, a, &rhash, cstate);

	/* If contributions don't exceed fees, this fails. */
	if (!commit)
		errx(1, "Invalid packets?");

	/* Their pubkey must be valid */
	if (!proto_to_pubkey(secp256k1_context_create(0),
			     o2->commit_key, &pubkey2))
		errx(1, "Invalid public open-channel-file2");

	/* Sign it for them. */
	subscript = bitcoin_redeem_2of2(ctx, &pubkey1, &pubkey2);
	sign_tx_input(secp256k1_context_create(SECP256K1_CONTEXT_SIGN),
		      commit, 0, subscript, tal_count(subscript),
		      &privkey, &pubkey1, &sig);

	pkt = open_commit_sig_pkt(ctx, &sig);
	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}

