/* My example:
 * ./open-commit-sig A-open.pb B-open.pb cUBCjrdJu8tfvM7FT8So6aqs6G6bZS1Cax6Rc9rFzYL6nYG4XNEC A-leak-anchor-sigs.pb B-leak-anchor-sigs.pb > A-commit-sig.pb
 * ./open-commit-sig B-open.pb A-open.pb cQXhbUnNRsFcdzTQwjbCrud5yVskHTEas7tZPUWoJYNk5htGQrpi B-leak-anchor-sigs.pb A-leak-anchor-sigs.pb > B-commit-sig.pb
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
#include "bitcoin/base58.h"
#include "pkt.h"
#include "bitcoin/script.h"
#include "permute_tx.h"
#include "bitcoin/signature.h"
#include "commit_tx.h"
#include "bitcoin/pubkey.h"
#include "find_p2sh_out.h"
#include "protobuf_convert.h"
#include <openssl/ec.h>
#include <unistd.h>

/* FIXME: this code doesn't work if we're not the ones proposing the delta */
int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenChannel *o1, *o2;
	Pkt *pkt;
	struct bitcoin_tx *anchor, *commit;
	struct sha256_double anchor_txid;
	EC_KEY *privkey;
	bool testnet;
	struct bitcoin_signature sig1, sig2;
	size_t i;
	struct pubkey pubkey1, pubkey2;
	u8 *redeemscript, *tx_arr;
	char *tx_hex;
	int64_t delta;
	struct sha256 rhash;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<anchor-tx> <open-channel-file1> <open-channel-file2> <commit-privkey> [final-update-accept|open-commit-sig] [<updates>]\n"
			   "Create the signature needed for the commit transaction",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 6)
		opt_usage_exit_fail("Expected 5+ arguments");

	anchor = bitcoin_tx_from_file(ctx, argv[1]);
	bitcoin_txid(anchor, &anchor_txid);
	o1 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[3], PKT__PKT_OPEN)->open;

	privkey = key_from_base58(argv[4], strlen(argv[4]), &testnet, &pubkey1);
	if (!privkey)
		errx(1, "Invalid private key '%s'", argv[4]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[4]);

	/* Get pubkeys */
	if (!proto_to_pubkey(o1->anchor->pubkey, &pubkey2))
		errx(1, "Invalid o1 anchor pubkey");
	if (pubkey_len(&pubkey1) != pubkey_len(&pubkey2)
	    || memcmp(pubkey1.key, pubkey2.key, pubkey_len(&pubkey2)) != 0)
		errx(1, "o1 pubkey != this privkey");
	if (!proto_to_pubkey(o2->anchor->pubkey, &pubkey2))
		errx(1, "Invalid o2 anchor pubkey");

	/* Their signature comes from open-commit or from update-accept. */
	sig2.stype = SIGHASH_ALL;
	pkt = any_pkt_from_file(argv[5]);

	switch (pkt->pkt_case) {
	case PKT__PKT_UPDATE_ACCEPT:
		if (!proto_to_signature(pkt->update_accept->sig, &sig2.sig))
			errx(1, "Invalid update-accept sig");
		break;
	case PKT__PKT_OPEN_COMMIT_SIG:
		if (!proto_to_signature(pkt->open_commit_sig->sig, &sig2.sig))
			errx(1, "Invalid open-commit-sig sig");
		break;
	default:
		errx(1, "Unexpected packet type %u in %s",
		     pkt->pkt_case, argv[5]);
	}

	/* Initial revocation hash comes from open. */
	proto_to_sha256(o1->revocation_hash, &rhash);
	
	delta = 0;
	/* Figure out cumulative delta since anchor, update revocation hash */
	for (i = 6; i < argc; i++) {
		Update *u = pkt_from_file(argv[i], PKT__PKT_UPDATE)->update;
		delta += u->delta;
		proto_to_sha256(u->revocation_hash, &rhash);
	}
	redeemscript = bitcoin_redeem_2of2(ctx, &pubkey1, &pubkey2);

	/* Now create commitment tx to spend 2/2 output of anchor. */
	commit = create_commit_tx(ctx, o1, o2, &rhash, delta, &anchor_txid,
				  find_p2sh_out(anchor, redeemscript));

	/* If contributions don't exceed fees, this fails. */
	if (!commit)
		errx(1, "Bad commit amounts");

	/* We generate our signature. */
	sig1.stype = SIGHASH_ALL;
	sign_tx_input(ctx, commit, 0, redeemscript, tal_count(redeemscript),
		      privkey, &pubkey1, &sig1.sig);

	if (!check_2of2_sig(commit, 0, redeemscript, tal_count(redeemscript),
			    &pubkey1, &pubkey2, &sig1, &sig2))
		errx(1, "Signature failed");

	/* Create p2sh input for commit */
	commit->input[0].script = scriptsig_p2sh_2of2(commit, &sig1, &sig2,
						      &pubkey1, &pubkey2);
	commit->input[0].script_length = tal_count(commit->input[0].script);

	/* Print it out in hex. */
	tx_arr = linearize_tx(ctx, commit);
	tx_hex = tal_arr(tx_arr, char, hex_str_size(tal_count(tx_arr)));
	hex_encode(tx_arr, tal_count(tx_arr), tx_hex, tal_count(tx_hex));

	if (!write_all(STDOUT_FILENO, tx_hex, strlen(tx_hex)))
		err(1, "Writing out transaction");

	tal_free(ctx);
	return 0;
}
