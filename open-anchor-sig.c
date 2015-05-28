/* My example:
 * ./open-anchor-sig A-open.pb B-open.pb cUjoranStkpgTRumAJZNiNEkknJv5UA7wzW1nZ7aPsm9ZWjkxypZ > A-anchor-scriptsigs.pb
 * ./open-anchor-sig B-open.pb A-open.pb cNggXygY8fPHWHEdoDqRa6xALau8gVMLq6q6vzMs2eNegLrJGNAW > B-anchor-scriptsigs.pb
 */
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include "bitcoin_tx.h"
#include "signature.h"
#include "lightning.pb-c.h"
#include "overflows.h"
#include "pkt.h"
#include "bitcoin_script.h"
#include "perturb.h"
#include "bitcoin_address.h"
#include "base58.h"

#include <openssl/ec.h>
#include <unistd.h>

/* Produce an anchor transaction from what both sides want. */
static struct bitcoin_tx *merge_transaction(const tal_t *ctx,
					    const OpenChannel *o1,
					    const OpenChannel *o2,
					    size_t *inmap)
{
	uint64_t i;
	struct bitcoin_tx *tx = tal(ctx, struct bitcoin_tx);
	u8 *redeemscript;

	/* Use lesser of two versions. */
	if (o1->tx_version < o2->tx_version)
		tx->version = o1->tx_version;
	else
		tx->version = o2->tx_version;

	if (add_overflows_size_t(o1->anchor->n_inputs, o2->anchor->n_inputs))
		return tal_free(tx);
	tx->input_count = o1->anchor->n_inputs + o2->anchor->n_inputs;

	tx->input = tal_arr(tx, struct bitcoin_tx_input, tx->input_count);
	/* Populate inputs. */
	for (i = 0; i < o1->anchor->n_inputs; i++) {
		BitcoinInput *pb = o1->anchor->inputs[i];
		struct bitcoin_tx_input *in = &tx->input[i];
		proto_to_sha256(pb->txid, &in->txid.sha);
		in->index = pb->output;
		in->sequence_number = 0xFFFFFFFF;
		/* Leave inputs as stubs for now, for signing. */
		in->script_length = 0;
		in->script = NULL;
	}
	for (i = 0; i < o2->anchor->n_inputs; i++) {
		BitcoinInput *pb = o2->anchor->inputs[i];
		struct bitcoin_tx_input *in
			= &tx->input[o1->anchor->n_inputs + i];
		proto_to_sha256(pb->txid, &in->txid.sha);
		in->index = pb->output;
		in->sequence_number = 0xFFFFFFFF;
		/* Leave inputs as stubs for now, for signing. */
		in->script_length = 0;
		in->script = NULL;
	}

	/* Populate outputs. */
	tx->output_count = 1;
	/* Allocate for worst case. */
	tx->output = tal_arr(tx, struct bitcoin_tx_output, 3);

	if (add_overflows_u64(o1->anchor->total, o2->anchor->total))
		return tal_free(tx);

	/* Make the 2 of 2 payment for the commitment txs. */
	redeemscript = bitcoin_redeem_2of2(tx, o1->anchor->pubkey,
					   o2->anchor->pubkey);
	tx->output[0].amount = o1->anchor->total + o2->anchor->total;
	tx->output[0].script = scriptpubkey_p2sh(tx, redeemscript);
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Add change transactions (if any) */
	if (o1->anchor->change) {
		struct bitcoin_tx_output *out = &tx->output[tx->output_count++];
		out->amount = o1->anchor->change->amount;
		out->script_length = o1->anchor->change->script.len;
		out->script = o1->anchor->change->script.data;
	}
	if (o2->anchor->change) {
		struct bitcoin_tx_output *out = &tx->output[tx->output_count++];
		out->amount = o2->anchor->change->amount;
		out->script_length = o2->anchor->change->script.len;
		out->script = o2->anchor->change->script.data;
	}

	perturb_inputs(o1->seed, o2->seed, 0, tx->input, tx->input_count, inmap);
	perturb_outputs(o1->seed, o2->seed, 0, tx->output, tx->output_count, NULL);
	return tx;
}

/* All the input scripts are already set to 0.  We just need to make this one. */
static u8 *sign_tx_input(const tal_t *ctx,
			 struct bitcoin_tx *tx,
			 unsigned int i,
			 const BitcoinInput *input,
			 EC_KEY *privkey,
			 const struct bitcoin_compressed_pubkey *pubkey)
{
	struct sha256_double hash;
	struct sha256_ctx shactx;
	struct bitcoin_address addr;
	u8 *sig;

	/* Transaction gets signed as if the output subscript is the
	 * only input script. */
	tx->input[i].script_length = input->subscript.len;
	tx->input[i].script = input->subscript.data;

	sha256_init(&shactx);
	sha256_tx(&shactx, tx);
	sha256_le32(&shactx, SIGHASH_ALL);
	sha256_double_done(&shactx, &hash);

	/* Reset it for next time. */
	tx->input[i].script_length = 0;
	tx->input[i].script = NULL;

	sig = sign_hash(ctx, privkey, &hash);
	if (!sig)
		return NULL;

	if (!is_pay_to_pubkey_hash(&input->subscript))
		errx(1, "FIXME: Don't know how to handle input");
	bitcoin_address(pubkey, &addr);
	return scriptsig_pay_to_pubkeyhash(ctx, &addr, sig, tal_count(sig));
}
	
int main(int argc, char *argv[])
{
	OpenChannel *o1, *o2;
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct bitcoin_tx *anchor;
	struct pkt *pkt;
	size_t i;
	u8 **sigs;
	size_t *map;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <privkey>...\n"
			   "Create signatures for transactions, and output to stdout",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 3)
		opt_usage_and_exit(NULL);

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	map = tal_arr(ctx, size_t, o1->anchor->n_inputs + o2->anchor->n_inputs);

	/* Create merged transaction */
	anchor = merge_transaction(ctx, o1, o2, map);
	if (!anchor)
		errx(1, "Failed transaction merge");

	/* Sign our inputs. */
	if (o1->anchor->n_inputs != argc - 3)
		errx(1, "Expected %zu private keys", o1->anchor->n_inputs);

	sigs = tal_arr(ctx, u8 *, o1->anchor->n_inputs);
	for (i = 0; i < o1->anchor->n_inputs; i++) {
		/* FIXME: Support non-compressed keys? */
		struct bitcoin_compressed_pubkey pubkey;
		EC_KEY *privkey;
		bool testnet;

		privkey = key_from_base58(argv[3+i], strlen(argv[3+i]),
					  &testnet, &pubkey);
		if (!privkey)
			errx(1, "Invalid private key '%s'", argv[3+i]);
		if (!testnet)
			errx(1, "Private key '%s' not on testnet!", argv[3+i]);
		
		sigs[i] = sign_tx_input(sigs, anchor, map[i],
					o1->anchor->inputs[i],
					privkey, &pubkey);
	}

	pkt = open_anchor_sig_pkt(ctx, sigs, o1->anchor->n_inputs);
	if (!write_all(STDOUT_FILENO, pkt,
		       sizeof(pkt->len) + le32_to_cpu(pkt->len)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}
