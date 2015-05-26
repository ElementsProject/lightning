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

static BitcoinOutputId *parse_anchor_input(const tal_t *ctx, const char *spec)
{
	BitcoinOutputId *o = tal(ctx, BitcoinOutputId);
	struct sha256 txid;
	const char *slash;
	char *end;
	long l;

	bitcoin_output_id__init(o);

	slash = strchr(spec, '/');
	if (!slash)
		errx(1, "Expected / in <txid>/<outputnum>");
	o->output = l = strtol(slash + 1, &end, 10);
	if (end == slash + 1 || *end || (int64_t)o->output != (int64_t)l)
		errx(1, "Expected <outputnum> after /");

	if (!hex_decode(spec, slash - spec, &txid, sizeof(txid)))
		errx(1, "Expected 256-bit hex txid before /");

	o->txid = proto_sha256_hash(o, &txid);
	return o;
}

static u8 *pay_to_pubkey(const tal_t *ctx, const struct bitcoin_address *addr)
{
	u8 *script = tal_arr(ctx, u8, 2 + 20 + 2);
	script[0] = 0x76; /* OP_DUP */
	script[1] = 0xA9; /* OP_HASH160 */
	memcpy(script+2, addr, 20);
	script[22] = 0x88; /* OP_EQUALVERIFY */
	script[23] = 0xAC; /* OP_CHECKSIG */

	return script;
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
	struct bitcoin_address ouraddr;
	EC_KEY *privkey;
	struct pkt *pkt;
	const tal_t *ctx = tal_arr(NULL, char, 0);
	Anchor anchor = ANCHOR__INIT;
	u64 commit_tx_fee;
	unsigned int locktime_seconds;
	bool testnet;
	struct bitcoin_compressed_pubkey pubkey;
	u8 *script_to_me;
	size_t i;

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
			   "<seed> <privkey> <ouraddr> <txid>/<outnum>...\n"
			   "A test program to output openchannel on stdout.",
			   "Print this message.");
	opt_register_arg("--min-anchor-confirms",
			 opt_set_uintval, opt_show_uintval, &anchor.min_confirms,
			 "Number of anchor confirmations before channel is active");
	opt_register_arg("--anchor-fee=<bits>",
			 opt_set_bits, opt_show_bits, &anchor.fee,
			 "100's of satoshi to pay for anchor");
	opt_register_arg("--commitment-fee=<bits>",
			 opt_set_bits, opt_show_bits, &commit_tx_fee,
			 "100's of satoshi to pay for commitment");
	opt_register_arg("--locktime=<seconds>",
			 opt_set_uintval, opt_show_uintval, &locktime_seconds,
			 "Seconds to lock out our transaction redemption");
	/* FIXME: Implement change address and amount. */

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 5)
		opt_usage_and_exit(NULL);

	if (!hex_decode(argv[1], strlen(argv[1]), &seed, sizeof(seed)))
		errx(1, "Invalid seed '%s' - need 256 hex bits", argv[1]);

	privkey = key_from_base58(argv[2], strlen(argv[2]), &testnet, &pubkey);
	if (!privkey)
		errx(1, "Invalid private key '%s'", argv[2]);
	if (!testnet)
		errx(1, "Private key '%s' not a testnet key!", argv[2]);

	if (!bitcoin_from_base58(&testnet, &ouraddr, argv[3], strlen(argv[3])))
		errx(1, "Invalid bitcoin address '%s'", argv[3]);
	if (!testnet)
		errx(1, "Bitcoin address '%s' not on testnet!", argv[3]);
	
	anchor.n_inputs = (argc - 4);
	anchor.inputs = tal_arr(ctx, BitcoinOutputId *, anchor.n_inputs);

	for (i = 0; i < anchor.n_inputs; i++)
		anchor.inputs[i] = parse_anchor_input(anchor.inputs, argv[i+4]);

	/* Get first revocation hash. */
	shachain_from_seed(&seed, 0, &revocation_hash);

	/* Make simple output script to pay to my pubkey. */
	script_to_me = pay_to_pubkey(ctx, &ouraddr);

	pkt = openchannel_pkt(ctx, weak_random64(), &revocation_hash,
			      tal_count(script_to_me), script_to_me,
			      commit_tx_fee, locktime_seconds, &anchor);

	if (!write_all(STDOUT_FILENO, pkt,
		       sizeof(pkt->len) + le32_to_cpu(pkt->len)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}
