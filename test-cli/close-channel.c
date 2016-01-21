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
#include "funding.h"
#include "commit_tx.h"
#include "bitcoin/signature.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/privkey.h"
#include "close_tx.h"
#include "find_p2sh_out.h"
#include "protobuf_convert.h"
#include "gather_updates.h"
#include "opt_bits.h"
#include "version.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenChannel *o1, *o2;
	OpenAnchor *a;
	struct bitcoin_tx *close_tx;
	struct pkt *pkt;
	struct signature sig;
	struct privkey privkey;
	bool testnet;
	struct pubkey pubkey1, pubkey2;
	u8 *redeemscript;
	char *close_file = NULL;
	u64 close_fee = 10000;
	struct channel_state *cstate;

	err_set_progname(argv[0]);

	opt_register_arg("--complete=<close-msg-file>",
			 opt_set_charp, NULL, &close_file,
			 "Create a close_transaction_complete msg instead");
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <anchor-file> <commit-privkey> [{+/-}update-protobuf]...\n"
			   "Create the signature needed for the close transaction",
			   "Print this message.");
	opt_register_arg("--close-fee=<bits>",
			 opt_set_bits, opt_show_bits, &close_fee,
			 "100's of satoshi to pay for close tx");
	opt_register_version();

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 5)
		opt_usage_exit_fail("Expected 4+ arguments");

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	a = pkt_from_file(argv[3], PKT__PKT_OPEN_ANCHOR)->open_anchor;

	if (!key_from_base58(argv[4], strlen(argv[4]), &testnet, &privkey, &pubkey1))
		errx(1, "Invalid private key '%s'", argv[4]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[4]);

	if (close_file) {
		CloseChannel *c;
		c = pkt_from_file(close_file, PKT__PKT_CLOSE)->close;
		close_fee = c->close_fee;
	}
	
	cstate = gather_updates(ctx, o1, o2, a, close_fee, argv + 5, NULL,
		       NULL, NULL, NULL);

	/* Get pubkeys */
	if (!proto_to_pubkey(o1->commit_key, &pubkey2))
		errx(1, "Invalid o1 commit pubkey");
	if (!pubkey_eq(&pubkey1, &pubkey2))
		errx(1, "o1 pubkey != this privkey");
	if (!proto_to_pubkey(o2->commit_key, &pubkey2))
		errx(1, "Invalid o2 commit pubkey");

	/* This is what the anchor pays to. */
	redeemscript = bitcoin_redeem_2of2(ctx, &pubkey1, &pubkey2);

	close_tx = create_close_tx(ctx, o1, o2, a,
				   cstate->a.pay_msat / 1000,
				   cstate->b.pay_msat / 1000);

	/* Sign it for them. */
	sign_tx_input(close_tx, 0, redeemscript, tal_count(redeemscript),
		      &privkey, &pubkey1, &sig);

	if (close_file)
		pkt = close_channel_complete_pkt(ctx, &sig);
	else
		pkt = close_channel_pkt(ctx, close_fee, &sig);
	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}

