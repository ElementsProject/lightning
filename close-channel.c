/* My example:
 * ./close-channel A-anchor.tx A-open.pb B-open.pb cUBCjrdJu8tfvM7FT8So6aqs6G6bZS1Cax6Rc9rFzYL6nYG4XNEC > A-close.pb
 * ./close-channel --complete A-anchor.tx B-open.pb A-open.pb cQXhbUnNRsFcdzTQwjbCrud5yVskHTEas7tZPUWoJYNk5htGQrpi > B-close-complete.pb
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
#include "bitcoin/pubkey.h"
#include "close_tx.h"
#include "find_p2sh_out.h"
#include "protobuf_convert.h"
#include <openssl/ec.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenChannel *o1, *o2;
	struct bitcoin_tx *anchor, *close_tx;
	struct sha256_double anchor_txid;
	struct pkt *pkt;
	struct signature sig;
	EC_KEY *privkey;
	bool testnet, complete = false;
	struct pubkey pubkey1, pubkey2;
	u8 *redeemscript;
	int64_t delta;
	size_t i;

	err_set_progname(argv[0]);

	/* FIXME: Take update.pbs to adjust channel */
	opt_register_noarg("--complete", opt_set_bool, &complete,
			   "Create a close_transaction_complete msg instead");
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<anchor-tx> <open-channel-file1> <open-channel-file2> <commit-privkey> [update-protobuf]...\n"
			   "Create the signature needed for the close transaction",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 5)
		opt_usage_exit_fail("Expected 4+ arguments");

	anchor = bitcoin_tx_from_file(ctx, argv[1]);
	o1 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[3], PKT__PKT_OPEN)->open;

	privkey = key_from_base58(argv[4], strlen(argv[4]), &testnet, &pubkey1);
	if (!privkey)
		errx(1, "Invalid private key '%s'", argv[4]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[4]);

	bitcoin_txid(anchor, &anchor_txid);

	/* Get delta by accumulting all the updates. */
	delta = 0;
	for (i = 5; i < argc; i++) {
		Update *u = pkt_from_file(argv[i], PKT__PKT_UPDATE)->update;
		delta += u->delta;
	}

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

	/* Now create the close tx to spend 2/2 output of anchor. */
	/* Assumes that updates are all from closer -> closee */
	close_tx = create_close_tx(ctx, o1, o2, complete ? -delta : delta,
				   &anchor_txid,
				   find_p2sh_out(anchor, redeemscript));

	/* Sign it for them. */
	sign_tx_input(ctx, close_tx, 0, redeemscript, tal_count(redeemscript),
		      privkey, &pubkey1, &sig);

	if (complete)
		pkt = close_channel_complete_pkt(ctx, &sig);
	else
		pkt = close_channel_pkt(ctx, &sig);
	if (!write_all(STDOUT_FILENO, pkt,
		       sizeof(pkt->len) + le32_to_cpu(pkt->len)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}

