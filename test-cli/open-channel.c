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
	struct sha256 seed, revocation_hash;
	struct pkt *pkt;
	const tal_t *ctx = tal_arr(NULL, char, 0);
	unsigned int locktime_seconds, min_confirms;
	u64 commit_tx_fee;
	bool offer_anchor = false;
	struct pubkey commitkey, finalkey;

	err_set_progname(argv[0]);

	/* This means we have ~1 day before they can steal our money. */
	locktime_seconds = LOCKTIME_MIN + 24 * 60 * 60;
	/* Zero, unless they set --offer-anchor or --min-anchor-confirms */
	min_confirms = 0;
	/* We only need this for involuntary close, so make it larger. */
	commit_tx_fee = 100000;
	
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<seed> <commitpubkey> <finalpubkey>\n"
			   "A test program to output openchannel on stdout.",
			   "Print this message.");
	opt_register_arg("--min-anchor-confirms",
			 opt_set_uintval, opt_show_uintval, &min_confirms,
			 "Number of anchor confirmations before channel is active");
	opt_register_arg("--locktime=<seconds>",
			 opt_set_uintval, opt_show_uintval, &locktime_seconds,
			 "Seconds to lock out our transaction redemption");
	opt_register_noarg("--offer-anchor",
			   opt_set_bool, &offer_anchor,
			   "Offer to create anchor transaction");
	opt_register_arg("--commitment-fee=<bits>",
			 opt_set_bits, opt_show_bits, &commit_tx_fee,
			 "100's of satoshi to pay for commitment");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 4)
		opt_usage_exit_fail("Expected 3 arguments");

	if (!hex_decode(argv[1], strlen(argv[1]), &seed, sizeof(seed)))
		errx(1, "Invalid seed '%s' - need 256 hex bits", argv[1]);

	if (!pubkey_from_hexstr(argv[2], &commitkey))
		errx(1, "Invalid commit key '%s'", argv[2]);

	if (!pubkey_from_hexstr(argv[3], &finalkey))
		errx(1, "Invalid final key '%s'", argv[3]);

	if (offer_anchor && min_confirms == 0)
		min_confirms = 3;

	/* Get first revocation hash. */
	shachain_from_seed(&seed, 0, &revocation_hash);
	sha256(&revocation_hash,
	       revocation_hash.u.u8, sizeof(revocation_hash.u.u8));

	pkt = open_channel_pkt(ctx, &revocation_hash, &commitkey, &finalkey,
			       locktime_seconds, offer_anchor, min_confirms,
			       commit_tx_fee);

	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}
