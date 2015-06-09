/* My example:
 * ./update-channel <A-SEED> <my-delta-in-satoshis> A-open.pb B-open.pb anchor.tx <A-TMPKEY> > A-update-1.pb
 */
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include "lightning.pb-c.h"
#include "anchor.h"
#include "base58.h"
#include "pkt.h"
#include "bitcoin_script.h"
#include "permute_tx.h"
#include "signature.h"
#include "commit_tx.h"
#include "pubkey.h"
#include "find_p2sh_out.h"
#include <openssl/ec.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct sha256 seed, revocation_hash;
	OpenChannel *o1, *o2;
	struct bitcoin_tx *anchor, *commit;
	struct sha256_double anchor_txid;
	struct pkt *pkt;
	struct signature sig;
	EC_KEY *privkey;
	bool testnet;
	struct pubkey pubkey1, pubkey2;
	u8 *redeemscript;
	unsigned long long to_them = 0, from_them = 0;
	int64_t delta, this_delta;
	size_t i;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<seed> <anchor-tx> <open-channel-file1> <open-channel-file2> <commit-privkey> [previous-updates]\n"
			   "Create a new update message",
			   "Print this message.");
	opt_register_arg("--to-them=<satoshi>",
			 opt_set_ulonglongval_si, NULL, &to_them,
			 "Amount to pay them (must use this or --from-them)");
	opt_register_arg("--from-them=<satoshi>",
			 opt_set_ulonglongval_si, NULL, &from_them,
			 "Amount to pay us (must use this or --to-them)");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (!from_them && !to_them)
		opt_usage_exit_fail("Must use --to-them or --from-them");

	if (argc < 5)
		opt_usage_exit_fail("Expected 4+ arguments");

	if (!hex_decode(argv[1], strlen(argv[1]), &seed, sizeof(seed)))
		errx(1, "Invalid seed '%s' - need 256 hex bits", argv[1]);

	this_delta = from_them - to_them;
	if (!this_delta)
		errx(1, "Delta must not be zero");
	
	anchor = bitcoin_tx_from_file(ctx, argv[2]);
	bitcoin_txid(anchor, &anchor_txid);
	o1 = pkt_from_file(argv[3], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[4], PKT__PKT_OPEN)->open;

	privkey = key_from_base58(argv[5], strlen(argv[5]), &testnet, &pubkey1);
	if (!privkey)
		errx(1, "Invalid private key '%s'", argv[5]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[5]);

	/* Figure out cumulative delta since anchor. */
	delta = this_delta;
	for (i = 6; i < argc; i++) {
		Update *u = pkt_from_file(argv[i], PKT__PKT_UPDATE)->update;
		delta += u->delta;
	}

	/* Get next revocation hash. */
	shachain_from_seed(&seed, argc - 5, &revocation_hash);
	sha256(&revocation_hash,
	       revocation_hash.u.u8, sizeof(revocation_hash.u.u8));
	
	/* Get pubkeys */
	if (!proto_to_pubkey(o1->anchor->pubkey, &pubkey2))
		errx(1, "Invalid o1 commit pubkey");
	if (pubkey_len(&pubkey1) != pubkey_len(&pubkey2)
	    || memcmp(pubkey1.key, pubkey2.key, pubkey_len(&pubkey2)) != 0)
		errx(1, "o1 pubkey != this privkey");
	if (!proto_to_pubkey(o2->anchor->pubkey, &pubkey2))
		errx(1, "Invalid o2 final pubkey");

	/* This is what the anchor pays to; figure out whick output. */
	redeemscript = bitcoin_redeem_2of2(ctx, &pubkey1, &pubkey2);

	/* Now create THEIR new commitment tx to spend 2/2 output of anchor. */
	commit = create_commit_tx(ctx, o2, o1, &revocation_hash, delta,
				  &anchor_txid,
				  find_p2sh_out(anchor, redeemscript));

	/* If contributions don't exceed fees, this fails. */
	if (!commit)
		errx(1, "Delta too large");

	/* Their pubkey must be valid */
	if (!proto_to_pubkey(o2->anchor->pubkey, &pubkey2))
		errx(1, "Invalid public open-channel-file2");

	/* Sign it for them. */
	sign_tx_input(ctx, commit, 0, redeemscript, tal_count(redeemscript),
		      privkey, &sig);

	pkt = update_pkt(ctx, &revocation_hash, this_delta, &sig);
	if (!write_all(STDOUT_FILENO, pkt,
		       sizeof(pkt->len) + le32_to_cpu(pkt->len)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}

