/* My example:
 * ./open-channel 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff 50000000000 mzqiPPbjTdcgM6NpNWJLHFt29tWD69bciE cUBCjrdJu8tfvM7FT8So6aqs6G6bZS1Cax6Rc9rFzYL6nYG4XNEC mi1BzT4tCB7K4kZH3yK1hM517bXH4pNmEH 08ffaf638849198f9c8f04aa75d225a5a104d5e7c540770ca55ad08b9a32d10c/1/100000000000/76a9148d2d939aa2aff2d341cde3e61a89bf9c2c21d12388ac > A-open.pb
 * ./open-channel 112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00 9795000 mpDyc5kPAJZB7Zz9iW9acq3Jk8yiTJ7HKj cQXhbUnNRsFcdzTQwjbCrud5yVskHTEas7tZPUWoJYNk5htGQrpi mrvw5JC5SKcEsRpSaRss6A3jLR6DMwpxep 8cb044605f33ca907b966701f49e0bd80b4294696b57f8cf45f22398a1e63a23/0/9800000/76a9143b2aab840afb327a12c8a90fb4ed45b6892eb80988ac > B-open.pb
 */
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include "lightning.pb-c.h"
#include "base58.h"
#include "pkt.h"
#include "bitcoin_script.h"
#include <openssl/ec.h>
#include <unistd.h>

/* Bitcoin nodes are allowed to be 2 hours in the future. */ 
#define LOCKTIME_MIN (2 * 60 * 60)

static char *opt_set_bits(const char *arg, u64 *satoshi)
{
	unsigned long long ll;
	char *ret = opt_set_ulonglongval_si(arg, &ll);
	if (ret)
		return ret;
	*satoshi = ll * 100;
	if (*satoshi / 100 != ll)
		return "Invalid number of bits";
	return NULL;
}

static void opt_show_bits(char buf[OPT_SHOW_LEN], const u64 *bits)
{
	unsigned long long ll = *bits / 100;
	opt_show_ulonglongval_si(buf, &ll);
}

static BitcoinInput *parse_anchor_input(const tal_t *ctx, const char *spec)
{
	BitcoinInput *in = tal(ctx, BitcoinInput);
	struct sha256 txid;
	const char *slash;
	char *end;
	long l;

	bitcoin_input__init(in);

	slash = strchr(spec, '/');
	if (!slash)
		errx(1, "Expected / in <txid>/<num>/<satoshis>/<hexscript>");

	if (!hex_decode(spec, slash - spec, &txid, sizeof(txid)))
		errx(1, "Expected 256-bit hex txid before /");
	in->txid = sha256_to_proto(in, &txid);

	in->output = l = strtol(slash + 1, &end, 10);
	if (end == slash + 1 || *end != '/' || (int64_t)in->output != (int64_t)l)
		errx(1, "Expected <outputnum> after /");

	slash = end;
	in->amount = l = strtol(slash + 1, &end, 10);
	if (end == slash + 1 || *end != '/' || (int64_t)in->amount != (int64_t)l)
		errx(1, "Expected <satoshis> after second /");

	slash = end;
	in->subscript.len = strlen(slash + 1) / 2;
	in->subscript.data = tal_arr(in, u8, in->subscript.len);
	if (!hex_decode(slash + 1, strlen(slash + 1),
			in->subscript.data, in->subscript.len))
		errx(1, "Expected hex string after third /");

	return in;
}

/* FIXME: This is too weak, even for us! */
static u64 weak_random64(void)
{
	return time(NULL);
}

/* Simple helper to open a channel. */
int main(int argc, char *argv[])
{
	struct sha256 seed, revocation_hash;
	struct bitcoin_address changeaddr, returnaddr;
	struct pkt *pkt;
	const tal_t *ctx = tal_arr(NULL, char, 0);
	Anchor anchor = ANCHOR__INIT;
	u64 commit_tx_fee, total_in;
	unsigned int locktime_seconds;
	bool testnet;
	u8 *script_to_me;
	size_t i;
	struct bitcoin_compressed_pubkey commitkey;
	EC_KEY *commitprivkey;

	err_set_progname(argv[0]);

	/* Default values. */
	anchor.min_confirms = 3;
	/* Remember, other side contributes to fee, too. */
	anchor.fee = 5000;
	/* We only need this for involuntary close, so make it larger. */
	commit_tx_fee = 100000;
	/* This means we have ~1 day before they can steal our money. */
	locktime_seconds = LOCKTIME_MIN + 24 * 60 * 60;
	
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<seed> <amount> <changeaddr> <commitprivkey> <returnaddr> <txid>/<outnum>/<satoshis>/<script-in-hex>...\n"
			   "A test program to output openchannel on stdout.",
			   "Print this message.");
	opt_register_arg("--min-anchor-confirms",
			 opt_set_uintval, opt_show_uintval, &anchor.min_confirms,
			 "Number of anchor confirmations before channel is active");
	opt_register_arg("--anchor-fee=<bits>",
			 opt_set_bits, opt_show_bits, &anchor.fee,
			 "100's of satoshi to pay for anchor");
	opt_register_arg("--locktime=<seconds>",
			 opt_set_uintval, opt_show_uintval, &locktime_seconds,
			 "Seconds to lock out our transaction redemption");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 7)
		opt_usage_and_exit(NULL);

	if (!hex_decode(argv[1], strlen(argv[1]), &seed, sizeof(seed)))
		errx(1, "Invalid seed '%s' - need 256 hex bits", argv[1]);

	anchor.total = atol(argv[2]);
	if (!anchor.total)
		errx(1, "Invalid total: must be > 0");

	if (!bitcoin_from_base58(&testnet, &changeaddr, argv[3], strlen(argv[3])))
		errx(1, "Invalid bitcoin address '%s'", argv[3]);
	if (!testnet)
		errx(1, "Bitcoin address '%s' not on testnet!", argv[3]);

	/* We don't really need the privkey here, but it's the most
	 * convenient way to get the pubkey from bitcoind. */
	commitprivkey = key_from_base58(argv[4], strlen(argv[4]), &testnet,
					&commitkey);
	if (!commitprivkey)
		errx(1, "Invalid private key '%s'", argv[4]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[4]);

	if (!bitcoin_from_base58(&testnet, &returnaddr, argv[5], strlen(argv[5])))
		errx(1, "Invalid bitcoin address '%s'", argv[5]);
	if (!testnet)
		errx(1, "Bitcoin address '%s' not on testnet!", argv[5]);
	
	anchor.n_inputs = (argc - 6);
	anchor.inputs = tal_arr(ctx, BitcoinInput *, anchor.n_inputs);
	anchor.pubkey = pubkey_to_proto(ctx, &commitkey);

	total_in = 0;
	for (i = 0; i < anchor.n_inputs; i++) {
		anchor.inputs[i] = parse_anchor_input(anchor.inputs, argv[i+6]);
		total_in += anchor.inputs[i]->amount;
	}

	if (total_in < anchor.total + anchor.fee)
		errx(1, "Only %llu satoshi in, and %llu out (+%llu fee)",
		     (unsigned long long)total_in,
		     (unsigned long long)anchor.total,
		     (unsigned long long)anchor.fee);

	/* If there's change, say where to send it. */
	if (total_in != anchor.total + anchor.fee) {
		anchor.change = tal(ctx, BitcoinOutput);
		bitcoin_output__init(anchor.change);
		anchor.change->amount = total_in - (anchor.total + anchor.fee);
		/* FIXME: Use p2sh? */
		anchor.change->script.data
			= scriptpubkey_pay_to_pubkeyhash(anchor.change,
							 &changeaddr);
		anchor.change->script.len
			= tal_count(anchor.change->script.data);
	}
	
	/* Get first revocation hash. */
	shachain_from_seed(&seed, 0, &revocation_hash);

	/* Make simple output script to pay to my pubkey. */
	script_to_me = scriptpubkey_pay_to_pubkeyhash(ctx, &returnaddr);

	pkt = openchannel_pkt(ctx, weak_random64(), &revocation_hash,
			      tal_count(script_to_me), script_to_me,
			      commit_tx_fee, locktime_seconds, &anchor);

	if (!write_all(STDOUT_FILENO, pkt,
		       sizeof(pkt->len) + le32_to_cpu(pkt->len)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}
