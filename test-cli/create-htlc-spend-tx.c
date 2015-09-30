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
#include "protobuf_convert.h"
#include "find_p2sh_out.h"
#include "version.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct sha256 revoke_hash, htlc_rhash, val, expect;
	OpenChannel *o1, *o2;
	UpdateAddHtlc *u;
	struct bitcoin_tx *commit, *tx;
	u8 *redeemscript;
	struct pubkey pubkey1, pubkey2, key, outpubkey;
	struct bitcoin_signature sig;
	struct privkey privkey;
	bool testnet;
	u32 locktime, htlc_abstimeout;
	char *rvalue = NULL, *preimage = NULL;
	bool received, own_commit_tx;
	Pkt *pkt;
	const void *secret = NULL;
	size_t secret_len = 0;

	err_set_progname(argv[0]);

	opt_register_arg("--rvalue", opt_set_charp, NULL, &rvalue,
			 "Use R value to spend htlc output");
	opt_register_arg("--commit-preimage=<update-msg>", opt_set_charp, NULL, &preimage,
			 "Use commit revocation preimage to spend htlc output");
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <commit-tx> [+-]<htlc-add-message-file> <final-update-message-for-commit-tx> <final-privkey> <outpubkey>\n"
			   "Create a transaction which spends commit-tx's htlc output, and sends it P2SH to outpubkey\n"
			   "It relies on timeout, unless --rvalue or --commit-preimage is specified",
			   "Print this message.");
	opt_register_version();

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 8)
		opt_usage_exit_fail("Expected 7 arguments");

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	commit = bitcoin_tx_from_file(ctx, argv[3]);
	if (strstarts(argv[4], "+"))
		received = false;
	else if (strstarts(argv[4], "-"))
		received = true;
	else
		errx(1, "%s doesn't begin with + or -", argv[4]);
	u = pkt_from_file(argv[4]+1, PKT__PKT_UPDATE_ADD_HTLC)->update_add_htlc;

	/* This gives us the revocation hash. */
	pkt = any_pkt_from_file(argv[5]);
	switch (pkt->pkt_case) {
	case PKT__PKT_UPDATE_ADD_HTLC:
		proto_to_sha256(pkt->update_add_htlc->revocation_hash,
				&revoke_hash);
		break;
	case PKT__PKT_UPDATE:
		proto_to_sha256(pkt->update->revocation_hash, &revoke_hash);
		break;
	case PKT__PKT_UPDATE_ACCEPT:
		proto_to_sha256(pkt->update_accept->revocation_hash,
				&revoke_hash);
		break;
	default:
		errx(1, "Expected update or update-add-htlc for %s", argv[5]);
	}

	if (!key_from_base58(argv[6], strlen(argv[6]), &testnet, &privkey, &key))
		errx(1, "Invalid private key '%s'", argv[6]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[6]);

	if (!pubkey_from_hexstr(argv[7], &outpubkey))
		errx(1, "Invalid commit key '%s'", argv[7]);

	/* Get pubkeys */
	if (!proto_to_pubkey(o1->final_key, &pubkey1))
		errx(1, "Invalid o1 final pubkey");
	if (!proto_to_pubkey(o2->final_key, &pubkey2))
		errx(1, "Invalid o2 final pubkey");

	if (pubkey_len(&key) == pubkey_len(&pubkey1)
	    && memcmp(key.key, pubkey1.key, pubkey_len(&pubkey1)) == 0) {
		own_commit_tx = true;
	} else if (pubkey_len(&key) == pubkey_len(&pubkey2)
		   && memcmp(key.key, pubkey2.key, pubkey_len(&pubkey2)) == 0) {
		own_commit_tx = false;
	} else
		errx(1, "Privkey doesn't match either key");

	if (!proto_to_rel_locktime(o2->delay, &locktime))
		errx(1, "Invalid o2 delay");
	if (!proto_to_abs_locktime(u->expiry, &htlc_abstimeout))
		errx(1, "Invalid htlc expiry");
	proto_to_sha256(u->r_hash, &htlc_rhash);

	if (received) {
		redeemscript = scriptpubkey_htlc_recv(ctx, &pubkey1, &pubkey2,
						      htlc_abstimeout,
						      locktime, &revoke_hash,
						      &htlc_rhash);
	} else {
		redeemscript = scriptpubkey_htlc_send(ctx, &pubkey1, &pubkey2,
						      htlc_abstimeout,
						      locktime, &revoke_hash,
						      &htlc_rhash);
	}

	if (rvalue) {
		if (!hex_decode(rvalue, strlen(rvalue), &val, sizeof(val)))
			errx(1, "Invalid rvalue '%s' - need 256 hex bits",
			     rvalue);
		sha256(&expect, &val, sizeof(val));
		if (!structeq(&expect, &htlc_rhash))
			errx(1, "--rvalue is not correct");
		secret = &val;
		secret_len = sizeof(val);
	}
	if (preimage) {
		Pkt *pkt = any_pkt_from_file(preimage);
		switch (pkt->pkt_case) {
		case PKT__PKT_UPDATE_SIGNATURE:
			proto_to_sha256(pkt->update_signature->revocation_preimage,
					&val);
			break;
		case PKT__PKT_UPDATE_COMPLETE:
			proto_to_sha256(pkt->update_complete->revocation_preimage,
					&val);
			break;
		default:
			errx(1, "Expected update or update-complete in %s",
			     preimage);
		}
		sha256(&expect, &val, sizeof(val));
		if (!structeq(&expect, &revoke_hash))
			errx(1, "--commit-preimage is not correct");
		secret = &val;
		secret_len = sizeof(val);
	}

	tx = bitcoin_tx(ctx, 1, 1);
	bitcoin_txid(commit, &tx->input[0].txid);
	tx->input[0].index = find_p2sh_out(commit, redeemscript);
	tx->input[0].input_amount = commit->output[tx->input[0].index].amount;

	if (!secret_len) {
		/* We must be relying on HTLC timeout. */
		tx->lock_time = htlc_abstimeout;
		/* Locktime only applies if an input has seq != ffffffff... */
		tx->input[0].sequence_number = 0;
	}

	/* If it's our own commit tx, we also need delay. */
	if (own_commit_tx)
		tx->input[0].sequence_number = bitcoin_nsequence(locktime);

	/* Leave 10,000 satoshi as fee (if we can!). */
	tx->fee = 10000;
	if (tx->input[0].input_amount <= tx->fee)
		errx(1, "Cannot afford fee: only %llu satoshi!",
		     (long long)tx->input[0].input_amount);
	tx->output[0].amount = tx->input[0].input_amount - tx->fee;
	tx->output[0].script = scriptpubkey_p2sh(tx,
						 bitcoin_redeem_single(tx, &outpubkey));
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Now get signature, to set up input script. */
	if (!sign_tx_input(tx, tx, 0, redeemscript, tal_count(redeemscript),
			   &privkey, &key, &sig.sig))
		errx(1, "Could not sign tx");

	sig.stype = SIGHASH_ALL;
	tx->input[0].script = scriptsig_p2sh_secret(tx, secret, secret_len,
						    &sig,
						    redeemscript,
						    tal_count(redeemscript));
	tx->input[0].script_length = tal_count(tx->input[0].script);

	/* Print it out in hex. */
	if (!bitcoin_tx_write(STDOUT_FILENO, tx))
		err(1, "Writing out transaction");

	tal_free(ctx);
	return 0;
}

