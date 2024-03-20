/* For example, in the spec tests we use the following keys:
 *
 * lightning/devtools/mkfunding 16835ac8c154b616baac524163f41fb0c4f82c7b972ad35d4d6f18d854f6856b 1 0.01btc 253 76edf0c303b9e692da9cb491abedef46ca5b81d32f102eb4648461b239cb0f99 0000000000000000000000000000000000000000000000000000000000000010 0000000000000000000000000000000000000000000000000000000000000020
 *
 * lightning/devtools/mkfunding 16835ac8c154b616baac524163f41fb0c4f82c7b972ad35d4d6f18d854f6856b 0 0.02btc 253 bc2f48a76a6b8815940accaf01981d3b6347a68fbe844f81c50ecbadf27cd179 0000000000000000000000000000000000000000000000000000000000000030 0000000000000000000000000000000000000000000000000000000000000040
 *
 * lightning/devtools/mkfunding 16835ac8c154b616baac524163f41fb0c4f82c7b972ad35d4d6f18d854f6856b 3 0.03btc 253 16c5027616e940d1e72b4c172557b3b799a93c0582f924441174ea556aadd01c 0000000000000000000000000000000000000000000000000000000000000050 0000000000000000000000000000000000000000000000000000000000000060
 */
#include "config.h"
#include <bitcoin/script.h>
#include <ccan/err/err.h>
#include <ccan/str/hex/hex.h>
#include <common/derive_basepoints.h>
#include <common/initial_commit_tx.h>
#include <common/setup.h>
#include <common/status.h>
#include <common/utxo.h>
#include <stdio.h>

void status_fmt(enum log_level level,
		const struct node_id *node_id,
		const char *fmt, ...)
{
}

static char *sig_as_hex(const struct bitcoin_signature *sig)
{
	u8 compact_sig[64];

	secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx,
						    compact_sig,
						    &sig->s);
	return tal_hexstr(NULL, compact_sig, sizeof(compact_sig));
}

static struct bitcoin_tx *tx_spending_utxo(const tal_t *ctx,
					   const struct utxo *utxo,
					   size_t num_output,
					   u32 nlocktime,
					   u32 nsequence)
{
	struct bitcoin_tx *tx = bitcoin_tx(ctx, chainparams, 1, num_output,
					   nlocktime);

	assert(!utxo->is_p2sh);
	bitcoin_tx_add_input(tx, &utxo->outpoint,
			     nsequence, NULL, utxo->amount,
			     utxo->scriptPubkey, NULL);

	return tx;
}

static struct bitcoin_tx *funding_tx(const tal_t *ctx,
				     const struct utxo *utxo,
				     struct amount_sat funding,
				     const struct pubkey *local_fundingkey,
				     const struct pubkey *remote_fundingkey)
{
	u8 *wscript;
	struct bitcoin_tx *tx;

	tx = tx_spending_utxo(ctx, utxo,
			      1, 0, BITCOIN_TX_DEFAULT_SEQUENCE);

	wscript = bitcoin_redeem_2of2(tx, local_fundingkey, remote_fundingkey);
	bitcoin_tx_add_output(tx, scriptpubkey_p2wsh(tx, wscript), wscript, funding);
	tal_free(wscript);

	bitcoin_tx_finalize(tx);
	assert(bitcoin_tx_check(tx));
	return tx;
}

int main(int argc, char *argv[])
{
	struct privkey input_privkey;
	struct privkey local_funding_privkey, remote_funding_privkey;
	struct pubkey funding_localkey, funding_remotekey, inputkey;
	struct amount_sat fee, funding_amount;
	unsigned int feerate_per_kw;
	int argnum;
	struct bitcoin_tx *tx;
	size_t weight;
	struct utxo input;
	struct bitcoin_signature sig;
	struct bitcoin_txid txid;
	u8 **witnesses;

	common_setup(argv[0]);
	chainparams = chainparams_for_network("bitcoin");

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
						 SECP256K1_CONTEXT_SIGN);

	if (argc != 1 + 7)
		errx(1, "Usage: mkfunding <input-txid> <input-txout> <input-amount> <feerate-per-kw> <input-privkey> <local-funding-privkey> <remote-funding-privkey>");

	input.is_p2sh = false;
	input.close_info = NULL;

	argnum = 1;
	if (!bitcoin_txid_from_hex(argv[argnum],
				   strlen(argv[argnum]), &input.outpoint.txid))
		errx(1, "Bad input-txid");
	argnum++;
	input.outpoint.n = atoi(argv[argnum++]);
	if (!parse_amount_sat(&input.amount, argv[argnum], strlen(argv[argnum])))
		errx(1, "Bad input-amount");
	argnum++;
	feerate_per_kw = atoi(argv[argnum++]);
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			&input_privkey, sizeof(input_privkey)))
		errx(1, "Parsing input-privkey");
	argnum++;
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			&local_funding_privkey, sizeof(local_funding_privkey)))
		errx(1, "Parsing local-funding-privkey");
	argnum++;
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			&remote_funding_privkey, sizeof(remote_funding_privkey)))
		errx(1, "Parsing remote-funding-privkey");
	argnum++;

	if (!pubkey_from_privkey(&input_privkey, &inputkey)
	    || !pubkey_from_privkey(&local_funding_privkey, &funding_localkey)
	    || !pubkey_from_privkey(&remote_funding_privkey, &funding_remotekey))
		errx(1, "Bad privkeys");

	/* nVersion, input count, output count, nLocktime */
	weight = 4 * (4 + 1 + 1 + 4);
	/* Add segwit fields: marker + flag */
	weight += 1 + 1;
	/* Single output: Satoshis, script length, p2wsh. */
	weight += 4 * (8 + 1 + BITCOIN_SCRIPTPUBKEY_P2WSH_LEN);
	/* Single input: txid, index, scriptlen, nSequence */
	weight += 4 * (32 + 4 + 1 + 4);
	/* Single witness: witness element count, len[0], sig, len[2], key */
	weight += 1 + (1 + 73 + 1 + 33);

	fee = amount_tx_fee(feerate_per_kw, weight);
	if (!amount_sat_sub(&funding_amount, input.amount, fee))
		errx(1, "Input %s can't afford fee %s",
		     fmt_amount_sat(NULL, input.amount),
		     fmt_amount_sat(NULL, fee));

	/* Find the P2WPKH script from input pubkey */
	input.scriptPubkey = scriptpubkey_p2wpkh(NULL, &inputkey);

	/* No change output, so we don't need a bip32 base. */
	tx = funding_tx(NULL, &input, funding_amount,
			&funding_localkey, &funding_remotekey);

	/* P2WSH of inputkey */
	bitcoin_tx_input_set_script(tx, 0, NULL);
	sign_tx_input(tx, 0, NULL, p2wpkh_scriptcode(NULL, &inputkey),
		      &input_privkey, &inputkey,
		      SIGHASH_ALL, &sig);
	witnesses = bitcoin_witness_p2wpkh(NULL, &sig, &inputkey);
	bitcoin_tx_input_set_witness(tx, 0, witnesses);

	printf("# funding sig: %s\n", sig_as_hex(&sig));
	printf("# funding witnesses: [\n");
	for (size_t i = 0; i < tal_count(witnesses); i++)
		printf("\t%s\n", tal_hex(NULL, witnesses[i]));
	printf("# ]\n");
 	printf("# funding amount: %s\n",
	       fmt_amount_sat(NULL, funding_amount));

	bitcoin_txid(tx, &txid);
 	printf("# funding txid: %s\n",
	       fmt_bitcoin_txid(NULL, &txid));

	printf("tx: %s\n", tal_hex(NULL, linearize_tx(NULL, tx)));
	common_shutdown();

	return 0;
}
