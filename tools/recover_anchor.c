/* Code to produce a tx that spends a to-remote anchor output.
 *
 * Use "guesstoremote" to get the script, csv, and privkey needed for this.
 *
 * lightningd/tools/recover_anchor
 * 	<psbt to sign>
 * 	<index of input on psbt to sign>
 * 	<amount that the input is worth>
 * 	<script>
 * 	<csv>
 * 	<privkey>
 */
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/privkey.h>
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <bitcoin/shadouble.h>
#include <bitcoin/signature.h>
#include <ccan/ccan/err/err.h>
#include <ccan/ccan/str/hex/hex.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <common/bech32.h>
#include <common/setup.h>
#include <common/utils.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <wally_psbt.h>

extern const struct chainparams *chainparams;

int main(int argc, char *argv[])
{
	int argnum, sequence, psbt_input;
	struct wally_psbt *psbt;
	struct bitcoin_signature sig;
	struct privkey privkey;
	struct sha256_double hash;
	struct wally_tx_witness_stack *stack;
	struct amount_sat output_amt;
	u8 *witness_script, *scriptpub;
	u8 der[73];
	size_t siglen;

	common_setup(argv[0]);

	chainparams = chainparams_for_network("regtest");

	if (argc != 7)
		errx(1, "<psbt> <input to sign> <amount> <script> <csv> <privkey>\n\tHint: Use ./tools/hsmtool guesstoremote to find the script, csv, and privkey");

	/* pull out the psbt */
	argnum = 1;
	psbt = psbt_from_b64(tmpctx, argv[argnum], strlen(argv[argnum]));
	if (!psbt)
		errx(1, "Bad PSBT %s", argv[argnum]);
	argnum++;

	psbt_input = atol(argv[argnum++]);
	if (psbt_input >= psbt->num_inputs)
		errx(1, "Provided PSBT doesn't have a %d input\n", psbt_input);

	/* What's the amount of this output? */
	if (!parse_amount_sat(&output_amt, argv[argnum], strlen(argv[argnum])))
		errx(1, "Provided amount does not parse\n");

	argnum++;
	/* What's the witness script? */
	witness_script = tal_hexdata(tmpctx, argv[argnum],
				     strlen(argv[argnum]));

	/* What should we set the sequence number to? */
	argnum++;
	sequence = atol(argv[argnum++]);

	/* What's the private key to sign with? */
	if (!hex_decode(argv[argnum], strlen(argv[argnum]),
			&privkey, sizeof(privkey)))
		errx(1, "Bad privkey");

	/* Put the script and amount onto the psbt, so we can sign it */
	scriptpub = scriptpubkey_p2wsh(tmpctx, witness_script);
	psbt_input_set_wit_utxo(psbt, psbt_input, scriptpub, output_amt);
	sig.sighash_type = SIGHASH_ALL;

	tal_wally_start();
	wally_psbt_input_set_sighash(&psbt->inputs[psbt_input],
				     sig.sighash_type);
	tal_wally_end(psbt);

	/* Sign the input */
	psbt_input_hash_for_sig(psbt, psbt_input, &hash);
	sign_hash(&privkey, &hash, &sig.s);

	tal_wally_start();
	wally_tx_witness_stack_init_alloc(2, &stack);

	siglen = signature_to_der(der, &sig);
	wally_tx_witness_stack_add(stack, der, siglen);
	wally_tx_witness_stack_add(stack, witness_script,
				   tal_bytelen(witness_script));

	wally_psbt_input_set_final_witness(&psbt->inputs[psbt_input], stack);
	tal_wally_end(psbt);
	/* Calls tal_wally internally */
	psbt_input_set_witscript(psbt, psbt_input, witness_script);

	/* Set the sequence number to match the csv */
	psbt->tx->inputs[psbt_input].sequence = sequence;

	/* Print out the updated/signed PSBT now */
	printf("psbt with signed output: \n");
	printf("%s\n", psbt_to_b64(tmpctx, psbt));

	exit(0);
}
