/* My example:
 * ./update-channel-complete <A-SEED> B-open.pb > A-update-complete-1.pb
 */
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/structeq/structeq.h>
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
	struct sha256 seed, revocation_hash, our_rhash, their_rhash, preimage;
	OpenChannel *o1, *o2;
	UpdateSignature *us;
	Update *update;
	struct pkt *pkt;
	struct bitcoin_tx *anchor, *commit;
	struct pubkey pubkey1, pubkey2;
	size_t i, num_updates, p2sh_out;
	struct sha256_double anchor_txid;
	struct bitcoin_signature sig;
	int64_t delta;
	u8 *redeemscript;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<seed> <anchor-tx> <open-channel-file1> <open-channel-file2> <update-protobuf> <update-signature-protobuf> [previous-updates]\n"
			   "Create a new update-complete message",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 7)
		opt_usage_exit_fail("Expected 6+ arguments");

	if (!hex_decode(argv[1], strlen(argv[1]), &seed, sizeof(seed)))
		errx(1, "Invalid seed '%s' - need 256 hex bits", argv[1]);

	anchor = bitcoin_tx_from_file(ctx, argv[2]);
	bitcoin_txid(anchor, &anchor_txid);
	o1 = pkt_from_file(argv[3], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[4], PKT__PKT_OPEN)->open;
	update = pkt_from_file(argv[5], PKT__PKT_UPDATE)->update;
	us = pkt_from_file(argv[6], PKT__PKT_UPDATE_SIGNATURE)->update_signature;
	
	/* We need last revocation hash (either in update or update-accept),
	 * and the delta */
	proto_to_sha256(o2->revocation_hash, &revocation_hash);
	num_updates = 0;
	delta = update->delta;
	for (i = 7; i < argc; i++) {
		Pkt *p = any_pkt_from_file(argv[i]);
		switch (p->pkt_case) {
		case PKT__PKT_UPDATE:
			proto_to_sha256(p->update->revocation_hash,
					&revocation_hash);
			delta += p->update->delta;
			num_updates++;
			break;
		case PKT__PKT_UPDATE_ACCEPT:
			if (i != argc - 1)
				errx(1, "Only need last update_accept");
			proto_to_sha256(p->update_accept->revocation_hash,
					&revocation_hash);
			break;
		default:
			errx(1, "Expected update/update-accept in %s", argv[i]);
		}
	}

	/* They gave us right preimage to match rhash of previous commit tx? */
	proto_to_sha256(us->revocation_preimage, &preimage);
	sha256(&their_rhash, preimage.u.u8, sizeof(preimage.u.u8));
	if (!structeq(&their_rhash, &revocation_hash))
		errx(1, "Their preimage was incorrect");

	/* Get pubkeys */
	if (!proto_to_pubkey(o1->anchor->pubkey, &pubkey1))
		errx(1, "Invalid o1 commit pubkey");
	if (!proto_to_pubkey(o2->anchor->pubkey, &pubkey2))
		errx(1, "Invalid o2 final pubkey");

	/* This is what the anchor pays to; figure out whick output. */
	redeemscript = bitcoin_redeem_2of2(ctx, &pubkey1, &pubkey2);
	p2sh_out = find_p2sh_out(anchor, redeemscript);

	/* Check their signature signs our new commit tx correctly. */
	shachain_from_seed(&seed, num_updates + 1, &preimage);
	sha256(&our_rhash, &preimage, sizeof(preimage));
	commit = create_commit_tx(ctx, o1, o2, &our_rhash, delta,
							  &anchor_txid, p2sh_out);
	if (!commit)
		errx(1, "Delta too large");

	sig.stype = SIGHASH_ALL;
	if (!proto_to_signature(us->sig, &sig.sig))
		errx(1, "Invalid update-signature signature");

	if (!check_tx_sig(commit, 0, redeemscript, tal_count(redeemscript),
			  &pubkey2, &sig))
		errx(1, "Invalid signature.");
	
	/* Hand over our preimage for previous tx. */
	shachain_from_seed(&seed, num_updates, &preimage);
	pkt = update_complete_pkt(ctx, &preimage);
	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}

