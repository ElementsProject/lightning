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
#include "bitcoin/address.h"
#include "bitcoin/tx.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/privkey.h"
#include "bitcoin/shadouble.h"
#include "protobuf_convert.h"
#include <unistd.h>
#include <time.h>
#include "opt_bits.h"

/* Bitcoin nodes are allowed to be 2 hours in the future. */ 
#define LOCKTIME_MIN (2 * 60 * 60)

struct input {
	struct bitcoin_tx_input in;
	struct privkey privkey;
	struct pubkey pubkey;
	struct bitcoin_signature sig;
};

static void parse_anchor_input(const char *spec, struct input *in)
{
	const char *slash;
	char *end;
	long l;
	bool testnet;

	slash = strchr(spec, '/');
	if (!slash)
		errx(1, "Expected / in <txid>/<num>/<satoshis>/<hexscript>/<privkey>");

	if (!bitcoin_txid_from_hex(spec, slash - spec, &in->in.txid))
		errx(1, "Expected 256-bit hex txid before /");

	in->in.index = l = strtol(slash + 1, &end, 10);
	if (end == slash + 1 || *end != '/' || (int64_t)in->in.index != (int64_t)l)
		errx(1, "Expected <outputnum> after /");

	slash = end;
	in->in.input_amount = l = strtol(slash + 1, &end, 10);
	if (end == slash + 1 || *end != '/' || (int64_t)in->in.input_amount != (int64_t)l)
		errx(1, "Expected <satoshis> after second /");

	slash = end;
	end = (char *)slash + 1 + strcspn(slash + 1, "/");
	in->in.script_length = hex_data_size(end - (slash + 1));
	in->in.script = tal_arr(in, u8, in->in.script_length);
	if (!hex_decode(slash + 1, end - (slash + 1),
			in->in.script, in->in.script_length))
		errx(1, "Expected hex string after third /");

	if (*end != '/')
		errx(1, "Expected / after hexscript");

	if (!key_from_base58(end+1, strlen(end + 1), &testnet,
			     &in->privkey, &in->pubkey))
		errx(1, "Invalid private key '%s'", end+1);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", end+1);
}

int main(int argc, char *argv[])
{
	OpenChannel *o1, *o2;
	struct bitcoin_tx *anchor;
	const tal_t *ctx = tal_arr(NULL, char, 0);
	u64 anchor_fee, amount, total_in, change;
	struct input *in;
	u8 *redeemscript;
	size_t i;
	struct pubkey pubkey1, pubkey2;

	err_set_progname(argv[0]);

	anchor_fee = 10000;
	
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<open-channel-file1> <open-channel-file2> <amount> <changepubkey> <txid>/<outnum>/<satoshis>/<script-in-hex>/<privkey>...\n"
			   "A test program to create an anchor tx on stdout.",
			   "Print this message.");
	opt_register_arg("--anchor-fee=<bits>",
			 opt_set_bits, opt_show_bits, &anchor_fee,
			 "100's of satoshi to pay for anchor");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 6)
		opt_usage_exit_fail("Expected 5 or more arguments");

	o1 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	o2 = pkt_from_file(argv[2], PKT__PKT_OPEN)->open;
	if (!proto_to_pubkey(o1->commit_key, &pubkey1))
		errx(1, "Invalid o1 commit_key");
	if (!proto_to_pubkey(o2->commit_key, &pubkey2))
		errx(1, "Invalid o2 commit_key");

	amount = atol(argv[3]);
	if (!amount)
		errx(1, "Invalid total: must be > 0");

	in = tal_arr(ctx, struct input, argc - 5);

	total_in = 0;
	for (i = 0; i < tal_count(in); i++) {
		parse_anchor_input(argv[5+i], &in[i]);
		total_in += in[i].in.input_amount;
	}

	if (total_in < amount + anchor_fee)
		errx(1, "Only %llu satoshi in, and %llu out (+%llu fee)",
		     (unsigned long long)total_in,
		     (unsigned long long)amount,
		     (unsigned long long)anchor_fee);

	change = total_in - (amount + anchor_fee);

	/* If there's change, we have an extra output. */
	anchor = bitcoin_tx(ctx, tal_count(in), change ? 2 : 1);
	anchor->fee = anchor_fee;

	/* Commitment redeems this via 2 of 2 payment. */
	redeemscript = bitcoin_redeem_2of2(ctx, &pubkey1, &pubkey2);

	/* Set up outputs. */
	anchor->output[0].amount = amount;
	anchor->output[0].script = scriptpubkey_p2sh(anchor, redeemscript);
	anchor->output[0].script_length = tal_count(anchor->output[0].script);

	if (change) {
		struct pubkey change_key;

		if (!pubkey_from_hexstr(argv[4], &change_key))
			errx(1, "Invalid change key %s", argv[3]);

		redeemscript = bitcoin_redeem_single(anchor, &change_key);
		anchor->output[1].amount = change;
		anchor->output[1].script = scriptpubkey_p2sh(anchor,
							     redeemscript);
		anchor->output[1].script_length
			= tal_count(anchor->output[1].script);
	}

	/* Set up inputs (leaving scripts empty for signing) */
	for (i = 0; i < tal_count(in); i++) {
		anchor->input[i].input_amount = in[i].in.input_amount;
		anchor->input[i].txid = in[i].in.txid;
		anchor->input[i].index = in[i].in.index;
	}
	
	/* Now, sign each input. */
	for (i = 0; i < tal_count(in); i++) {
		in[i].sig.stype = SIGHASH_ALL;
		if (!sign_tx_input(ctx, anchor, i, in[i].in.script,
				   in[i].in.script_length,
				   &in[i].privkey, &in[i].pubkey,
				   &in[i].sig.sig))
			errx(1, "Error signing input %zi", i);
	}

	/* Finally, complete inputs using signatures. */
	for (i = 0; i < tal_count(in); i++) {
		if (!is_pay_to_pubkey_hash(in[i].in.script,
					   in[i].in.script_length))
			errx(1, "FIXME: Don't know how to handle input %zi", i);
		anchor->input[i].script
			= scriptsig_pay_to_pubkeyhash(anchor, &in[i].pubkey,
						      &in[i].sig);
		anchor->input[i].script_length
			= tal_count(anchor->input[i].script);
	}

	/* Print it out in hex. */
	if (!bitcoin_tx_write(STDOUT_FILENO, anchor))
		err(1, "Writing out transaction");

	tal_free(ctx);
	return 0;
}
