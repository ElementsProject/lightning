/* My example:
 * ./open-channel 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff 50000000000 030da36b810c0930e5fe8b74014665873f6901d9f46018a5fda743a93dec7f0e4e cUBCjrdJu8tfvM7FT8So6aqs6G6bZS1Cax6Rc9rFzYL6nYG4XNEC cTuY5gncxDymqe9dfF7R8QFdAsxMZxdViRMjs8Dj7xJJRsQcmPCt 08ffaf638849198f9c8f04aa75d225a5a104d5e7c540770ca55ad08b9a32d10c/1/100000000000/76a9148d2d939aa2aff2d341cde3e61a89bf9c2c21d12388ac > A-open.pb
 * ./open-channel 112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00 9795000 022e314a8f7a814e0900bf094f704b233dc693349cf55b888b43d902d7be251e95 cQXhbUnNRsFcdzTQwjbCrud5yVskHTEas7tZPUWoJYNk5htGQrpi cQXhbUnNRsFcdzTQwjbCrud5yVskHTEas7tZPUWoJYNk5htGQrpi 8cb044605f33ca907b966701f49e0bd80b4294696b57f8cf45f22398a1e63a23/0/9800000/76a9143b2aab840afb327a12c8a90fb4ed45b6892eb80988ac > B-open.pb
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
#include "bitcoin_address.h"
#include "bitcoin_tx.h"
#include "pubkey.h"
#include "shadouble.h"
#include <openssl/ec.h>
#include <unistd.h>
#include "opt_bits.h"

/* Bitcoin nodes are allowed to be 2 hours in the future. */ 
#define LOCKTIME_MIN (2 * 60 * 60)

static BitcoinInput *parse_anchor_input(const tal_t *ctx, const char *spec)
{
	BitcoinInput *in = tal(ctx, BitcoinInput);
	struct sha256_double txid;
	const char *slash;
	char *end;
	long l;

	bitcoin_input__init(in);

	slash = strchr(spec, '/');
	if (!slash)
		errx(1, "Expected / in <txid>/<num>/<satoshis>/<hexscript>");

	if (!bitcoin_txid_from_hex(spec, slash - spec, &txid))
		errx(1, "Expected 256-bit hex txid before /");
	in->txid = sha256_to_proto(in, &txid.sha);

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
	struct pkt *pkt;
	const tal_t *ctx = tal_arr(NULL, char, 0);
	Anchor anchor = ANCHOR__INIT;
	u64 commit_tx_fee, total_in;
	unsigned int locktime_seconds;
	bool testnet;
	size_t i;
	struct pubkey commitkey, outkey, changekey;
	EC_KEY *commitprivkey, *outprivkey;

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
			   "<seed> <amount> <changepubkey> <commitprivkey> <outprivkey> <txid>/<outnum>/<satoshis>/<script-in-hex>...\n"
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

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 7)
		opt_usage_exit_fail("Expected 6 or more arguments");

	if (!hex_decode(argv[1], strlen(argv[1]), &seed, sizeof(seed)))
		errx(1, "Invalid seed '%s' - need 256 hex bits", argv[1]);

	anchor.total = atol(argv[2]);
	if (!anchor.total)
		errx(1, "Invalid total: must be > 0");

	if (!pubkey_from_hexstr(argv[3], &changekey))
		errx(1, "Invalid bitcoin pubkey '%s'", argv[3]);

	/* We don't really need the privkey here, but it's the most
	 * convenient way to get the pubkey from bitcoind. */
	commitprivkey = key_from_base58(argv[4], strlen(argv[4]), &testnet,
					&commitkey);
	if (!commitprivkey)
		errx(1, "Invalid private key '%s'", argv[4]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[4]);

	outprivkey = key_from_base58(argv[5], strlen(argv[5]), &testnet,
				     &outkey);
	if (!outprivkey)
		errx(1, "Invalid private key '%s'", argv[5]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[5]);
	
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
		anchor.change = tal(ctx, Change);
		change__init(anchor.change);
		anchor.change->pubkey = pubkey_to_proto(anchor.change,
							&changekey);
		anchor.change->amount = total_in - (anchor.total + anchor.fee);
	}

	/* Get first revocation hash. */
	shachain_from_seed(&seed, 0, &revocation_hash);
	sha256(&revocation_hash,
	       revocation_hash.u.u8, sizeof(revocation_hash.u.u8));

	pkt = openchannel_pkt(ctx, weak_random64(), &revocation_hash, &outkey,
			      commit_tx_fee, locktime_seconds, &anchor);

	if (!write_all(STDOUT_FILENO, pkt,
		       sizeof(pkt->len) + le32_to_cpu(pkt->len)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}
