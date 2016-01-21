#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/structeq/structeq.h>
#include "lightning.pb-c.h"
#include "bitcoin/base58.h"
#include "pkt.h"
#include "bitcoin/script.h"
#include "permute_tx.h"
#include "bitcoin/signature.h"
#include "commit_tx.h"
#include "bitcoin/pubkey.h"
#include "find_p2sh_out.h"
#include "protobuf_convert.h"
#include "gather_updates.h"
#include "funding.h"
#include "version.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct sha256 seed, our_rhash, their_rhash, preimage;
	OpenChannel *o1, *o2;
	OpenAnchor *a;
	struct pkt *pkt;
	struct bitcoin_tx *commit;
	struct pubkey pubkey1, pubkey2;
	size_t num_updates;
	struct bitcoin_signature sig;
	u8 *redeemscript;
	struct channel_state *cstate;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<seed> <open-channel-file1> <open-channel-file2> <open-anchor-file> <all-previous-updates>\n"
			   "Create a new update-complete message",
			   "Print this message.");
	opt_register_version();

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 7)
		opt_usage_exit_fail("Expected 6+ arguments");

	if (!hex_decode(argv[1], strlen(argv[1]), &seed, sizeof(seed)))
		errx(1, "Invalid seed '%s' - need 256 hex bits", argv[1]);

	o1 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[3], PKT__PKT_OPEN)->open;
	a = pkt_from_file(argv[4], PKT__PKT_OPEN_ANCHOR)->open_anchor;

	sig.stype = SIGHASH_ALL;

	/* This also checks that preimage is correct! */
	cstate = gather_updates(ctx, o1, o2, a,
				commit_fee(o1->commitment_fee,
					   o2->commitment_fee),
				argv + 5,
				&num_updates,
				&our_rhash, &their_rhash, &sig.sig);
	if (num_updates < 1)
		errx(1, "Expected at least one update!");

	/* Get pubkeys */
	if (!proto_to_pubkey(o1->commit_key, &pubkey1))
		errx(1, "Invalid o1 commit pubkey");
	if (!proto_to_pubkey(o2->commit_key, &pubkey2))
		errx(1, "Invalid o2 commit pubkey");

	/* This is what the anchor pays to. */
	redeemscript = bitcoin_redeem_2of2(ctx, &pubkey1, &pubkey2);

	/* Check their signature signs our new commit tx correctly. */
	commit = commit_tx_from_pkts(ctx, o1, o2, a, &our_rhash, cstate);
	if (!commit)
		errx(1, "Delta too large");

	if (!check_tx_sig(commit, 0, redeemscript, tal_count(redeemscript),
			  &pubkey2, &sig))
		errx(1, "Invalid signature.");
	
	/* Hand over our preimage for previous tx. */
	shachain_from_seed(&seed, num_updates - 1, &preimage);
	pkt = update_complete_pkt(ctx, &preimage);
	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}

