/* Code to make a mutual close tx, useful for generating test cases.
 *
 * For example, in the spec tests we use the following:
 *
 * lightning/devtools/mkclose 189c40b0728f382fe91c87270926584e48e0af3a6789f37454afee6c7560311d 0 0.00999877btc 253 0.00999877btc 0000000000000000000000000000000000000000000000000000000000000010 0000000000000000000000000000000000000000000000000000000000000020 026957e53b46df017bd6460681d068e1d23a7b027de398272d0b15f59b78d060a9 03a9f795ff2e4c27091f40e8f8277301824d1c3dfa6b0204aa92347314e41b1033
 */
#include "config.h"
#include <bitcoin/script.h>
#include <ccan/err/err.h>
#include <ccan/str/hex/hex.h>
#include <common/htlc_wire.h>
#include <common/initial_commit_tx.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <stdio.h>

static bool verbose = false;

void status_fmt(enum log_level level,
		const struct node_id *node_id,
		const char *fmt, ...)
{
	if (verbose) {
		va_list ap;

		va_start(ap, fmt);
		printf("#TRACE: ");
		vprintf(fmt, ap);
		printf("\n");
		va_end(ap);
	}
}

void status_failed(enum status_failreason reason, const char *fmt, ...)
{
	abort();
}

static char *sig_as_hex(const struct bitcoin_signature *sig)
{
	u8 compact_sig[64];

	secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx,
						    compact_sig,
						    &sig->s);
	return tal_hexstr(NULL, compact_sig, sizeof(compact_sig));
}

int main(int argc, char *argv[])
{
	struct pubkey funding_pubkey[NUM_SIDES], outkey[NUM_SIDES];
	struct privkey funding_privkey[NUM_SIDES];
	struct amount_sat funding_amount;
	struct bitcoin_outpoint funding;
	u32 feerate_per_kw;
	struct amount_sat fee;
	struct bitcoin_signature local_sig, remote_sig;
	struct amount_msat local_msat, remote_msat;
	int argnum, num_outputs;
	struct bitcoin_tx *tx;
	u8 **witness;
	const u8 *funding_wscript;
	const struct chainparams *chainparams = chainparams_for_network("bitcoin");
	const struct amount_sat dust_limit = AMOUNT_SAT(546);
	bool option_anchor_outputs = false;

	setup_locale();

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
						 SECP256K1_CONTEXT_SIGN);

	if (argv[1] && streq(argv[1], "-v")) {
		verbose = true;
		argv++;
		argc--;
	}

	if (argc != 10)
		errx(1, "Usage: mkclose [-v] <funding-txid> <funding-txout> <funding-amount> <feerate-per-kw> <local-msat> <local-funding-privkey> <remote-funding-privkey> <local-close-pubkey> <remote-close-pubkey>\n"
			"(Fee is deducted from local-msat)");

	argnum = 1;
	if (!bitcoin_txid_from_hex(argv[argnum],
				   strlen(argv[argnum]), &funding.txid))
		errx(1, "Bad funding-txid");
	argnum++;
	funding.n = atoi(argv[argnum++]);
	if (!parse_amount_sat(&funding_amount, argv[argnum], strlen(argv[argnum])))
		errx(1, "Bad funding-amount");
	argnum++;
	feerate_per_kw = atoi(argv[argnum++]);
	if (!parse_amount_msat(&local_msat,
			       argv[argnum], strlen(argv[argnum])))
		errx(1, "Bad local-msat");
	argnum++;
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			&funding_privkey[LOCAL], sizeof(funding_privkey[LOCAL])))
		errx(1, "Parsing local-funding_privkey");
	argnum++;
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			&funding_privkey[REMOTE], sizeof(funding_privkey[REMOTE])))
		errx(1, "Parsing remote-funding_privkey");
	argnum++;
	if (!pubkey_from_hexstr(argv[argnum], strlen(argv[argnum]),
				&outkey[LOCAL]))
		errx(1, "Parsing local-close-pubkey");
	argnum++;
	if (!pubkey_from_hexstr(argv[argnum], strlen(argv[argnum]),
				&outkey[REMOTE]))
		errx(1, "Parsing remote-close-pubkey");
	argnum++;

	fee = commit_tx_base_fee(feerate_per_kw, 0,
				 option_anchor_outputs,
				 false);
	/* BOLT #3:
	 * If `option_anchors` applies to the commitment
	 * transaction, also subtract two times the fixed anchor size
	 * of 330 sats from the funder (either `to_local` or
	 * `to_remote`).
	 */
	if (option_anchor_outputs && !amount_sat_add(&fee, fee, AMOUNT_SAT(660)))
		errx(1, "Can't afford anchors");

	if (!amount_msat_sub_sat(&local_msat, local_msat, fee))
		errx(1, "Can't afford fee %s",
		     fmt_amount_sat(NULL, fee));
	if (!amount_sat_sub_msat(&remote_msat, funding_amount, local_msat))
		errx(1, "Can't afford local_msat");

	if (!pubkey_from_privkey(&funding_privkey[LOCAL], &funding_pubkey[LOCAL])
	    || !pubkey_from_privkey(&funding_privkey[REMOTE], &funding_pubkey[REMOTE]))
		errx(1, "Bad deriving funding pubkeys");

	tx = bitcoin_tx(NULL, chainparams, 1, 2, 0);

	num_outputs = 0;
	if (amount_msat_greater_eq_sat(local_msat, dust_limit)) {
		u8 *script = scriptpubkey_p2wpkh(NULL, &outkey[LOCAL]);
		printf("# local witness script: %s\n", tal_hex(NULL, script));
		/* One output is to us. */
		bitcoin_tx_add_output(tx, script, NULL,
				      amount_msat_to_sat_round_down(local_msat));
		num_outputs++;
	} else
		printf("# local output trimmed\n");

	if (amount_msat_greater_eq_sat(remote_msat, dust_limit)) {
		u8 *script = scriptpubkey_p2wpkh(NULL, &outkey[REMOTE]);
		printf("# remote witness script: %s\n", tal_hex(NULL, script));
		/* Other output is to them. */
		bitcoin_tx_add_output(tx, script, NULL,
				      amount_msat_to_sat_round_down(remote_msat));
		num_outputs++;
	} else
		printf("# remote output trimmed\n");

	/* Can't have no outputs at all! */
	if (num_outputs == 0)
		errx(1, "Can't afford any output!");

	funding_wscript = bitcoin_redeem_2of2(NULL,
					      &funding_pubkey[LOCAL],
					      &funding_pubkey[REMOTE]);
	printf("# funding witness script = %s\n",
	       tal_hex(NULL, funding_wscript));

	/* Our input spends the anchor tx output. */
	bitcoin_tx_add_input(tx, &funding,
			     BITCOIN_TX_DEFAULT_SEQUENCE, NULL,
			     funding_amount, NULL, funding_wscript);

	sign_tx_input(tx, 0, NULL, funding_wscript,
		      &funding_privkey[LOCAL],
		      &funding_pubkey[LOCAL],
		      SIGHASH_ALL, &local_sig);
	printf("localsig: %s\n", sig_as_hex(&local_sig));
	sign_tx_input(tx, 0, NULL, funding_wscript,
		      &funding_privkey[REMOTE],
		      &funding_pubkey[REMOTE],
		      SIGHASH_ALL, &remote_sig);
	printf("remotesig: %s\n", sig_as_hex(&remote_sig));

	witness =
		bitcoin_witness_2of2(NULL, &local_sig, &remote_sig,
				     &funding_pubkey[LOCAL],
				     &funding_pubkey[REMOTE]);
	bitcoin_tx_input_set_witness(tx, 0, witness);
	printf("# signed close transaction: %s\n",
	       tal_hex(NULL, linearize_tx(NULL, tx)));

	return 0;
}
