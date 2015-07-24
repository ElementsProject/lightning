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

/* Simple helper to open a channel. */
int main(int argc, char *argv[])
{
	struct sha256 seed, revocation_hash, escape_secret, escape_hash;
	struct pkt *pkt;
	const tal_t *ctx = tal_arr(NULL, char, 0);
	u64 commit_tx_fee, escape_fee, total_in;
	unsigned int locktime_seconds, min_confirms;
	bool testnet;
	struct pubkey commitkey, outkey;
	struct privkey commitprivkey, outprivkey;

	err_set_progname(argv[0]);

	/* Default values. */
	min_confirms = 3;
	/* We only need this for involuntary close, so make it larger. */
	commit_tx_fee = 100000;
	/* Don't let them waste too much of our money if they abort. */
	escape_fee = 10000;
	/* This means we have ~1 day before they can steal our money. */
	locktime_seconds = LOCKTIME_MIN + 24 * 60 * 60;
	
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<seed> <amount> <commitprivkey> <outprivkey> <escape-secret>\n"
			   "A test program to output openchannel on stdout.",
			   "Print this message.");
	opt_register_arg("--min-anchor-confirms",
			 opt_set_uintval, opt_show_uintval, &min_confirms,
			 "Number of anchor confirmations before channel is active");
	opt_register_arg("--commitment-fee=<bits>",
			 opt_set_bits, opt_show_bits, &commit_tx_fee,
			 "100's of satoshi to pay for commitment");
	opt_register_arg("--escape-fee=<bits>",
			 opt_set_bits, opt_show_bits, &escape_fee,
			 "100's of satoshi to pay for escape transactions");
	opt_register_arg("--locktime=<seconds>",
			 opt_set_uintval, opt_show_uintval, &locktime_seconds,
			 "Seconds to lock out our transaction redemption");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 6)
		opt_usage_exit_fail("Expected 5 arguments");

	if (!hex_decode(argv[1], strlen(argv[1]), &seed, sizeof(seed)))
		errx(1, "Invalid seed '%s' - need 256 hex bits", argv[1]);

	total_in = atol(argv[2]);
	if (!total_in)
		errx(1, "Invalid total: must be > 0");

	/* We don't really need the privkey here, but it's the most
	 * convenient way to get the pubkey from bitcoind. */
	if (!key_from_base58(argv[3], strlen(argv[3]), &testnet,
			     &commitprivkey, &commitkey))
		errx(1, "Invalid private key '%s'", argv[3]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[3]);

	if (!key_from_base58(argv[4], strlen(argv[4]), &testnet,
			     &outprivkey, &outkey))
		errx(1, "Invalid private key '%s'", argv[4]);
	if (!testnet)
		errx(1, "Private key '%s' not on testnet!", argv[4]);
	
	if (!hex_decode(argv[5], strlen(argv[5]), &escape_secret,
			sizeof(escape_secret)))
		errx(1, "Invalid escape hash '%s' - need 256 hex bits", argv[5]);

	/* Get first revocation hash. */
	shachain_from_seed(&seed, 0, &revocation_hash);
	sha256(&revocation_hash,
	       revocation_hash.u.u8, sizeof(revocation_hash.u.u8));

	/* Get hash from escape secret. */
	sha256(&escape_hash, escape_secret.u.u8, sizeof(escape_secret.u.u8));

	pkt = openchannel_pkt(ctx, &revocation_hash, &commitkey, &outkey,
			      commit_tx_fee, locktime_seconds, total_in,
			      &escape_hash, escape_fee, min_confirms);

	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}
