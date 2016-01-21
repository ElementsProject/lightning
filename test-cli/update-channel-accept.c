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
#include "find_p2sh_out.h"
#include "protobuf_convert.h"
#include "gather_updates.h"
#include "funding.h"
#include "version.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct sha256 seed, revocation_hash, their_rhash;
	OpenChannel *o1, *o2;
	OpenAnchor *a;
	struct bitcoin_tx *commit;
	struct pkt *pkt;
	struct bitcoin_signature sig;
	struct privkey privkey;
	bool testnet;
	size_t num_updates;
	struct pubkey pubkey1, pubkey2;
	u8 *redeemscript;
	struct channel_state *cstate;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<seed> <open-channel-file1> <open-channel-file2> <open-anchor-file> <commit-privkey> <all-updates...>\n"
			   "Accept a new update message",
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

	if (!key_from_base58(argv[5], strlen(argv[5]), &testnet, &privkey, &pubkey1))
		errx(1, "Invalid private key '%s'", argv[5]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[5]);

	/* Figure out cumulative delta since anchor. */
	cstate = gather_updates(ctx, o1, o2, a,
				commit_fee(o1->commitment_fee,
					   o2->commitment_fee),
				argv + 6,
				&num_updates, NULL, &their_rhash, NULL);

	/* Get next revocation hash. */
	shachain_from_seed(&seed, num_updates, &revocation_hash);
	sha256(&revocation_hash,
	       revocation_hash.u.u8, sizeof(revocation_hash.u.u8));
	
	/* Get pubkeys */
	if (!proto_to_pubkey(o1->commit_key, &pubkey2))
		errx(1, "Invalid o1 commit pubkey");
	if (!pubkey_eq(&pubkey1, &pubkey2))
		errx(1, "o1 pubkey != this privkey");
	if (!proto_to_pubkey(o2->commit_key, &pubkey2))
		errx(1, "Invalid o2 commit pubkey");

	/* This is what the anchor pays to; figure out whick output. */
	redeemscript = bitcoin_redeem_2of2(ctx, &pubkey1, &pubkey2);

	/* Now create THEIR new commitment tx to spend 2/2 output of anchor. */
	invert_cstate(cstate);
	commit = commit_tx_from_pkts(ctx, o2, o1, a, &their_rhash, cstate);

	/* If contributions don't exceed fees, this fails. */
	if (!commit)
		errx(1, "Delta too large");

	/* Sign it for them. */
	sign_tx_input(commit, 0, redeemscript, tal_count(redeemscript),
		      &privkey, &pubkey1, &sig.sig);

	pkt = update_accept_pkt(ctx, &sig.sig, &revocation_hash);
	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}

