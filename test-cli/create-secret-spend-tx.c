#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include <ccan/structeq/structeq.h>
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
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct bitcoin_tx *intx, *tx;
	struct bitcoin_signature sig;
	struct privkey privkey;
	bool testnet;
	struct pubkey pubkey, other_pubkey, dst_pubkey;
	u8 *redeemscript;
	struct sha256 shash, blob;
	u64 fee = 10000;
	u32 locktime;
	bool use_secret = false, use_hash = false, hash_secret = false;

	err_set_progname(argv[0]);

	/* There are two cases: if we have the secret, and if we don't. */
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<txin> <other-key> <delay> <privkey> <dstpubkey> <secret-or-hash>\n"
			   "Create the transaction to spend a time-or-secret-locked output",
			   "Print this message.");
	opt_register_arg("--fee=<bits>",
			 opt_set_bits, opt_show_bits, &fee,
			 "100's of satoshi to pay in transaction fee");
	opt_register_noarg("--secret",
			   opt_set_bool, &use_secret,
			   "We have the secret");
	opt_register_noarg("--no-secret",
			   opt_set_bool, &use_hash,
			   "We do not have the secret");
	opt_register_noarg("--hash-secret",
			   opt_set_bool, &hash_secret,
			   "We have the secret, but don't use it");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 7)
		opt_usage_exit_fail("Expected 6 arguments");

	if (hash_secret)
		use_hash = true;

	if (!use_secret && !use_hash)
		opt_usage_exit_fail("Need --secret, --no-secret or --hash_secret");

	intx = bitcoin_tx_from_file(ctx, argv[1]);
	if (!pubkey_from_hexstr(argv[2], &other_pubkey))
		errx(1, "Invalid bitcoin pubkey '%s'", argv[2]);
	locktime = atoi(argv[3]);
	if (!locktime)
		errx(1, "Invalid locktime '%s'", argv[3]);

	/* Seconds offset for locktime. */
	locktime += 500000000;

 	/* We need our private key to spend output. */
	if (!key_from_base58(argv[4], strlen(argv[4]), &testnet, &privkey, &pubkey))
		errx(1, "Invalid private key '%s'", argv[4]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[4]);

	if (!pubkey_from_hexstr(argv[5], &dst_pubkey))
		errx(1, "Invalid bitcoin pubkey '%s'", argv[5]);

	if (!hex_decode(argv[6], strlen(argv[6]), &blob, sizeof(blob)))
		errx(1, "Invalid %s '%s' - need 256 hex bits", argv[6],
		     use_hash ? "secrethash" : "secret");

	if (hash_secret || use_secret)
		sha256(&shash, &blob, sizeof(blob));
	else
		shash = blob;

	/* Create redeem script */
	if (use_secret) {
		redeemscript = bitcoin_redeem_secret_or_delay(ctx, &other_pubkey,
							      locktime,
							      &pubkey, &shash);
	} else {
		redeemscript = bitcoin_redeem_secret_or_delay(ctx, &pubkey,
							      locktime,
							      &other_pubkey,
							      &shash);
	}

	/* Now, create transaction to spend it. */
	tx = bitcoin_tx(ctx, 1, 1);
	bitcoin_txid(intx, &tx->input[0].txid);
	tx->input[0].index = find_p2sh_out(intx, redeemscript);
	tx->input[0].input_amount = intx->output[tx->input[0].index].amount;
	tx->fee = fee;

	/* Sequence number is inverted timeout. */
	if (use_hash)
		tx->input[0].sequence_number = ~locktime;

	if (tx->input[0].input_amount <= tx->fee)
		errx(1, "Amount of %llu won't exceed fee",
		     (unsigned long long)tx->input[0].input_amount);

	tx->output[0].amount = tx->input[0].input_amount - tx->fee;
	tx->output[0].script = scriptpubkey_p2sh(tx,
				    bitcoin_redeem_single(tx, &dst_pubkey));
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Now get signature, to set up input script. */
	sig.stype = SIGHASH_ALL;
	if (!sign_tx_input(tx, tx, 0, redeemscript, tal_count(redeemscript),
			   &privkey, &pubkey, &sig.sig))
		errx(1, "Could not sign tx");

	if (use_secret) {
		tx->input[0].script
			= scriptsig_p2sh_secret(tx,
						&blob, sizeof(blob), &sig,
						redeemscript,
						tal_count(redeemscript));
	} else {
		tx->input[0].script
			= scriptsig_p2sh_secret(tx,
						NULL, 0, &sig,
						redeemscript,
						tal_count(redeemscript));
	}
	tx->input[0].script_length = tal_count(tx->input[0].script);

	/* Print it out in hex. */
	if (!bitcoin_tx_write(STDOUT_FILENO, tx))
		err(1, "Writing out transaction");

	tal_free(ctx);
	return 0;
}
