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
	uint64_t to_them, to_us;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <open-anchor-file1> <commit-privkey>\n"
			   "Create the signature needed for the commit transaction",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 5)
		opt_usage_exit_fail("Expected 4 arguments");

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	a = pkt_from_file(argv[3], PKT__PKT_OPEN_ANCHOR)->open_anchor;
	
	if (!key_from_base58(argv[4], strlen(argv[4]), &testnet, &privkey, &pubkey1))
		errx(1, "Invalid private key '%s'", argv[4]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[4]);

	/* Now create THEIR commitment tx to spend 2/2 output of anchor. */
	if (!initial_funding(o1, o2, a, commit_fee(o1, o2), &to_us, &to_them))
		errx(1, "Invalid open combination (need 1 anchor offer)");

	proto_to_sha256(o2->revocation_hash, &rhash);
	commit = create_commit_tx(ctx, o2, o1, a, &rhash, to_them, to_us);

	/* If contributions don't exceed fees, this fails. */
	if (!commit)
		errx(1, "Invalid packets?");

	/* Their pubkey must be valid */
	if (!proto_to_pubkey(o2->commit_key, &pubkey2))
		errx(1, "Invalid public open-channel-file2");

	/* Sign it for them. */
	subscript = bitcoin_redeem_2of2(ctx, &pubkey1, &pubkey2);
	sign_tx_input(ctx, commit, 0, subscript, tal_count(subscript),
		      &privkey, &pubkey1, &sig);

	pkt = open_commit_sig_pkt(ctx, &sig);
	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}

