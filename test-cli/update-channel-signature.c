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

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct sha256 seed, revocation_hash, preimage;
	OpenChannel *o1, *o2;
	UpdateAccept *ua;
	Update *update;
	struct bitcoin_tx *anchor, *commit;
	struct sha256_double anchor_txid;
	struct pkt *pkt;
	struct bitcoin_signature sig;
	EC_KEY *privkey;
	bool testnet;
	struct pubkey pubkey1, pubkey2;
	u8 *redeemscript;
	int64_t delta;
	size_t i, p2sh_out;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<seed> <anchor-tx> <open-channel-file1> <open-channel-file2> <commit-privkey> <update-protobuf> <update-accept-protobuf> [previous-updates]...\n"
			   "Create a new update-channel-signature message",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 8)
		opt_usage_exit_fail("Expected 7+ arguments");

	if (!hex_decode(argv[1], strlen(argv[1]), &seed, sizeof(seed)))
		errx(1, "Invalid seed '%s' - need 256 hex bits", argv[1]);

	anchor = bitcoin_tx_from_file(ctx, argv[2]);
	bitcoin_txid(anchor, &anchor_txid);
	o1 = pkt_from_file(argv[3], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[4], PKT__PKT_OPEN)->open;

	privkey = key_from_base58(argv[5], strlen(argv[5]), &testnet, &pubkey1);
	if (!privkey)
		errx(1, "Invalid private key '%s'", argv[5]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[5]);

	update = pkt_from_file(argv[6], PKT__PKT_UPDATE)->update;
	ua = pkt_from_file(argv[7], PKT__PKT_UPDATE_ACCEPT)->update_accept;

	sig.stype = SIGHASH_ALL;
	if (!proto_to_signature(ua->sig, &sig.sig))
		errx(1, "Invalid update signature");

	/* Figure out cumulative delta since anchor. */
	delta = 0;
	for (i = 8; i < argc; i++) {
		Update *u = pkt_from_file(argv[i], PKT__PKT_UPDATE)->update;
		delta += u->delta;
	}

	/* Give up revocation preimage for old tx. */
	shachain_from_seed(&seed, argc - 7 - 1, &preimage);
	
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
	p2sh_out = find_p2sh_out(anchor, redeemscript);

	/* Check our new commit is signed correctly by them. */
	proto_to_sha256(update->revocation_hash, &revocation_hash);
	commit = create_commit_tx(ctx, o1, o2, &revocation_hash, delta,
				  &anchor_txid, p2sh_out);
	if (!commit)
		errx(1, "Delta too large");

	/* Check their signature signs this input correctly. */
	if (!check_tx_sig(commit, 0, redeemscript, tal_count(redeemscript),
			  &pubkey2, &sig))
		errx(1, "Invalid signature.");

	/* Now create THEIR new commitment tx to spend 2/2 output of anchor. */
	proto_to_sha256(ua->revocation_hash, &revocation_hash);
	commit = create_commit_tx(ctx, o2, o1, &revocation_hash, -delta,
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
		      privkey, &pubkey1, &sig.sig);

	pkt = update_signature_pkt(ctx, &sig.sig, &preimage);
	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}

