/* My example:
 * ./check-commit-sig A-open.pb B-open.pb A-commit-sig.pb B-commit-sig.pb cUBCjrdJu8tfvM7FT8So6aqs6G6bZS1Cax6Rc9rFzYL6nYG4XNEC A-leak-anchor-sigs.pb B-leak-anchor-sigs.pb > A-commit.tx
 * ./check-commit-sig B-open.pb A-open.pb B-commit-sig.pb A-commit-sig.pb cUBCjrdJu8tfvM7FT8So6aqs6G6bZS1Cax6Rc9rFzYL6nYG4XNEC B-leak-anchor-sigs.pb A-leak-anchor-sigs.pb > B-commit.tx
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
#include <openssl/ec.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct sha256 revoke, revoke_hash;
	OpenChannel *o2;
	struct bitcoin_tx *commit, *tx;
	u8 *tx_arr, *redeemscript, *p2sh;
	size_t i;
	struct pubkey pubkey1, pubkey2, outpubkey;
	struct bitcoin_signature sig;
	char *tx_hex;
	EC_KEY *privkey;
	bool testnet;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<commit-tx> <revocation-preimage> <privkey> <open-channel-file2> <outpubkey>\n"
			   "Create a transaction which spends commit-tx's revocable output, and sends it P2SH to outpubkey",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 6)
		opt_usage_exit_fail("Expected 5 arguments");

	commit = bitcoin_tx_from_file(ctx, argv[1]);

	if (!hex_decode(argv[2], strlen(argv[2]), &revoke, sizeof(revoke)))
		errx(1, "Invalid revokation hash '%s' - need 256 hex bits",
		     argv[2]);

	privkey = key_from_base58(argv[3], strlen(argv[3]), &testnet, &pubkey1);
	if (!privkey)
		errx(1, "Invalid private key '%s'", argv[3]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[3]);

	o2 = pkt_from_file(argv[4], PKT__PKT_OPEN)->open;

	if (!pubkey_from_hexstr(argv[5], &outpubkey))
		errx(1, "Invalid bitcoin pubkey '%s'", argv[5]);

	if (!proto_to_pubkey(o2->anchor->pubkey, &pubkey2))
		errx(1, "Invalid anchor1 pubkey");

	/* Now, which commit output?  Match redeem script. */
	sha256(&revoke_hash, &revoke, sizeof(revoke));
	redeemscript = bitcoin_redeem_revocable(ctx, &pubkey1,
						o2->locktime_seconds,
						&pubkey2, &revoke_hash);
	p2sh = scriptpubkey_p2sh(ctx, redeemscript);

	for (i = 0; i < commit->output_count; i++) {
		if (commit->output[i].script_length != tal_count(p2sh))
			continue;
		if (memcmp(commit->output[i].script, p2sh, tal_count(p2sh)) == 0)
			break;
	}
	if (i == commit->output_count)
		errx(1, "No matching output in %s", argv[1]);

	tx = bitcoin_tx(ctx, 1, 1);
	bitcoin_txid(commit, &tx->input[0].txid);
	tx->input[0].index = i;

	tx->output[0].amount = commit->output[i].amount;
	tx->output[0].script = scriptpubkey_p2sh(tx,
						 bitcoin_redeem_single(tx, &outpubkey));
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Now get signature, to set up input script. */
	if (!sign_tx_input(tx, tx, 0, redeemscript, tal_count(redeemscript),
			   privkey, &pubkey1, &sig.sig))
		errx(1, "Could not sign tx");
	sig.stype = SIGHASH_ALL;
	tx->input[0].script = scriptsig_p2sh_revoke(tx, &revoke, &sig,
						    redeemscript,
						    tal_count(redeemscript));
	tx->input[0].script_length = tal_count(tx->input[0].script);

	/* Print it out in hex. */
	tx_arr = linearize_tx(ctx, commit);
	tx_hex = tal_arr(tx_arr, char, hex_str_size(tal_count(tx_arr)));
	hex_encode(tx_arr, tal_count(tx_arr), tx_hex, tal_count(tx_hex));

	if (!write_all(STDOUT_FILENO, tx_hex, strlen(tx_hex)))
		err(1, "Writing out transaction");

	tal_free(ctx);
	return 0;
}

