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
#include "bitcoin/privkey.h"
#include "protobuf_convert.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct sha256 revoke_preimage, revoke_hash;
	OpenChannel *o1, *o2;
	Pkt *pkt;
	struct bitcoin_tx *commit, *tx;
	u8 *tx_arr, *redeemscript, *p2sh;
	size_t i;
	struct pubkey pubkey1, pubkey2, outpubkey;
	struct bitcoin_signature sig;
	char *tx_hex;
	struct privkey privkey;
	bool testnet;
	u32 locktime_seconds;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<commit-tx> <revocation-preimage> <final-privkey> <open-channel-file1> <open-channel-file2> <outpubkey>\n"
			   "Create a transaction which spends commit-tx's revocable output, and sends it P2SH to outpubkey",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 7)
		opt_usage_exit_fail("Expected 6 arguments");

	commit = bitcoin_tx_from_file(ctx, argv[1]);

	pkt = any_pkt_from_file(argv[2]);
	switch (pkt->pkt_case) {
	case PKT__PKT_UPDATE_SIGNATURE:
		proto_to_sha256(pkt->update_signature->revocation_preimage,
				&revoke_preimage);
		break;
	case PKT__PKT_UPDATE_COMPLETE:
		proto_to_sha256(pkt->update_complete->revocation_preimage,
				&revoke_preimage);
		break;
	default:
		errx(1, "Expected update or update-complete in %s", argv[2]);
	}

	if (!key_from_base58(argv[3], strlen(argv[3]), &testnet, &privkey, &pubkey1))
		errx(1, "Invalid private key '%s'", argv[3]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[3]);

	o1 = pkt_from_file(argv[4], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[5], PKT__PKT_OPEN)->open;
	if (!proto_to_locktime(o2, &locktime_seconds))
		errx(1, "Invalid locktime in o2");

	if (!pubkey_from_hexstr(argv[6], &outpubkey))
		errx(1, "Invalid bitcoin pubkey '%s'", argv[6]);

	/* Get pubkeys */
	if (!proto_to_pubkey(o1->final, &pubkey2))
		errx(1, "Invalid o1 final pubkey");
	if (pubkey_len(&pubkey1) != pubkey_len(&pubkey2)
	    || memcmp(pubkey1.key, pubkey2.key, pubkey_len(&pubkey2)) != 0)
		errx(1, "o1 pubkey != this privkey");
	if (!proto_to_pubkey(o2->final, &pubkey2))
		errx(1, "Invalid o2 final pubkey");

	/* Now, which commit output?  Match redeem script. */
	sha256(&revoke_hash, &revoke_preimage, sizeof(revoke_preimage));
	redeemscript = bitcoin_redeem_revocable(ctx, &pubkey2,
						locktime_seconds,
						&pubkey1, &revoke_hash);
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
	tx->input[0].input_amount = commit->output[i].amount;

	/* Leave 10,000 satoshi as fee. */
	tx->fee = 10000;
	tx->output[0].amount = commit->output[i].amount - tx->fee;
	tx->output[0].script = scriptpubkey_p2sh(tx,
						 bitcoin_redeem_single(tx, &outpubkey));
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Now get signature, to set up input script. */
	if (!sign_tx_input(tx, tx, 0, redeemscript, tal_count(redeemscript),
			   &privkey, &pubkey1, &sig.sig))
		errx(1, "Could not sign tx");
	sig.stype = SIGHASH_ALL;
	tx->input[0].script = scriptsig_p2sh_revoke(tx, &revoke_preimage, &sig,
						    redeemscript,
						    tal_count(redeemscript));
	tx->input[0].script_length = tal_count(tx->input[0].script);

	/* Print it out in hex. */
	tx_arr = linearize_tx(ctx, tx);
	tx_hex = tal_arr(tx_arr, char, hex_str_size(tal_count(tx_arr)));
	hex_encode(tx_arr, tal_count(tx_arr), tx_hex, tal_count(tx_hex));

	if (!write_all(STDOUT_FILENO, tx_hex, strlen(tx_hex)))
		err(1, "Writing out transaction");

	tal_free(ctx);
	return 0;
}

