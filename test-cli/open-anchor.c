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
#include "funding.h"
#include "bitcoin/script.h"
#include "bitcoin/address.h"
#include "bitcoin/tx.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/privkey.h"
#include "bitcoin/shadouble.h"
#include "commit_tx.h"
#include "protobuf_convert.h"
#include "find_p2sh_out.h"
#include <unistd.h>
#include <time.h>
#include "opt_bits.h"
#include "version.h"

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct bitcoin_tx *anchor, *commit;
	OpenChannel *o1, *o2;
	OpenAnchor oa = OPEN_ANCHOR__INIT;
	struct sha256_double txid;
	struct sha256 rhash;
	struct pkt *pkt;
	struct pubkey pubkey1, pubkey2;
	struct privkey privkey;
	struct signature sig;
	bool testnet;
	u8 *redeemscript;
	struct channel_state *cstate;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <anchor-tx-file> <commit-privkey1>\n"
			   "A test program to output open_anchor message on stdout.",
			   "Print this message.");
	opt_register_version();

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 5)
		opt_usage_exit_fail("Expected 4 arguments");

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	if (!proto_to_pubkey(o2->commit_key, &pubkey2))
		errx(1, "Invalid o2 commit_key");

	anchor = bitcoin_tx_from_file(ctx, argv[3]);
	bitcoin_txid(anchor, &txid);

	if (!key_from_base58(argv[4], strlen(argv[4]), &testnet, &privkey, &pubkey1))
		errx(1, "Invalid private key '%s'", argv[4]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[4]);
	
	/* Figure out which output we want for commit tx. */
	redeemscript = bitcoin_redeem_2of2(ctx, &pubkey1, &pubkey2);
	oa.txid = sha256_to_proto(ctx, &txid.sha);
	oa.output_index = find_p2sh_out(anchor, redeemscript);
	oa.amount = anchor->output[oa.output_index].amount;

	/* Figure out initial how much to us, how much to them. */
	cstate = initial_funding(ctx, o1, o2, &oa, commit_fee(o1, o2));
	if (!cstate)
		errx(1, "Invalid open combination (need 1 anchor offer)");
	
	/* Now, create signature for their commitment tx. */
	proto_to_sha256(o2->revocation_hash, &rhash);
	invert_cstate(cstate);
 	commit = create_commit_tx(ctx, o2, o1, &oa, &rhash, cstate);

	sign_tx_input(ctx, commit, 0, redeemscript, tal_count(redeemscript),
		      &privkey, &pubkey1, &sig);

	oa.commit_sig = signature_to_proto(ctx, &sig);
	pkt = open_anchor_pkt(ctx, &oa);
	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}
