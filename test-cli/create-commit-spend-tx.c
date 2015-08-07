#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include <ccan/structeq/structeq.h>
#include "lightning.pb-c.h"
#include "bitcoin/base58.h"
#include "pkt.h"
#include "bitcoin/script.h"
#include "permute_tx.h"
#include "bitcoin/signature.h"
#include "commit_tx.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/privkey.h"
#include "bitcoin/address.h"
#include "opt_bits.h"
#include "find_p2sh_out.h"
#include "protobuf_convert.h"
#include "test-cli/gather_updates.h"
#include "funding.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	OpenChannel *o1, *o2;
	OpenAnchor *a;
	struct bitcoin_tx *commit, *tx;
	struct bitcoin_signature sig;
	struct privkey privkey;
	bool testnet;
	struct pubkey pubkey1, pubkey2, outpubkey;
	u8 *redeemscript;
	struct sha256 rhash;
	size_t p2sh_out;
	u64 fee = 10000;
	u32 locktime;

	err_set_progname(argv[0]);

	/* FIXME: If we've updated channel since, we need the final
	 * revocation hash we sent (either update_accept or update_complete) */
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<commitment-tx> <open-channel-file1> <open-channel-file2> <open-anchor-file> <my-privoutkey> <someaddress> [previous-updates]\n"
			   "Create the transaction to spend our commit transaction",
			   "Print this message.");
	opt_register_arg("--fee=<bits>",
			 opt_set_bits, opt_show_bits, &fee,
			 "100's of satoshi to pay in transaction fee");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 6)
		opt_usage_exit_fail("Expected 5+ arguments");

	commit = bitcoin_tx_from_file(ctx, argv[1]);

	o1 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[3], PKT__PKT_OPEN)->open;
	a = pkt_from_file(argv[4], PKT__PKT_OPEN_ANCHOR)->open_anchor;
	if (!proto_to_rel_locktime(o2->delay, &locktime))
		errx(1, "Invalid locktime in o2");

 	/* We need our private key to spend commit output. */
	if (!key_from_base58(argv[5], strlen(argv[5]), &testnet, &privkey, &pubkey1))
		errx(1, "Invalid private key '%s'", argv[5]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[5]);

	if (!pubkey_from_hexstr(argv[6], &outpubkey))
		errx(1, "Invalid bitcoin pubkey '%s'", argv[6]);

	/* Get pubkeys */
	if (!proto_to_pubkey(o1->final_key, &pubkey2))
		errx(1, "Invalid o1 final pubkey");
	if (pubkey_len(&pubkey1) != pubkey_len(&pubkey2)
	    || memcmp(pubkey1.key, pubkey2.key, pubkey_len(&pubkey2)) != 0)
		errx(1, "o1 pubkey != this privkey");
	if (!proto_to_pubkey(o2->final_key, &pubkey2))
		errx(1, "Invalid o2 final pubkey");

	/* We use this simply to get final revocation hash. */
	gather_updates(ctx, o1, o2, a, commit_fee(o1, o2), argv + 7,
		       NULL, &rhash, NULL, NULL);

	/* Create redeem script */
	redeemscript = bitcoin_redeem_secret_or_delay(ctx, &pubkey1, locktime,
						      &pubkey2, &rhash);

	/* Now, create transaction to spend it. */
	tx = bitcoin_tx(ctx, 1, 1);
	bitcoin_txid(commit, &tx->input[0].txid);
	p2sh_out = find_p2sh_out(commit, redeemscript);
	tx->input[0].index = p2sh_out;
	tx->input[0].input_amount = commit->output[p2sh_out].amount;
	tx->fee = fee;

	/* Sequence number is inverted timeout. */
	tx->input[0].sequence_number = ~locktime;

	if (commit->output[p2sh_out].amount <= fee)
		errx(1, "Amount of %llu won't exceed fee",
		     (unsigned long long)commit->output[p2sh_out].amount);

	tx->output[0].amount = commit->output[p2sh_out].amount - fee;
	tx->output[0].script = scriptpubkey_p2sh(tx,
						 bitcoin_redeem_single(tx, &outpubkey));
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Now get signature, to set up input script. */
	if (!sign_tx_input(tx, tx, 0, redeemscript, tal_count(redeemscript),
			   &privkey, &pubkey1, &sig.sig))
		errx(1, "Could not sign tx");
	sig.stype = SIGHASH_ALL;
	tx->input[0].script = scriptsig_p2sh_secret(tx, NULL, 0, &sig,
						    redeemscript,
						    tal_count(redeemscript));
	tx->input[0].script_length = tal_count(tx->input[0].script);

	/* Print it out in hex. */
	if (!bitcoin_tx_write(STDOUT_FILENO, tx))
		err(1, "Writing out transaction");

	tal_free(ctx);
	return 0;
}
