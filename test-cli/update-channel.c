/* My example:
 * ./update-channel <A-SEED> <my-delta-in-satoshis> A-open.pb B-open.pb anchor.tx <A-TMPKEY> > A-update-1.pb
 */
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include "lightning.pb-c.h"
#include "anchor.h"
#include "bitcoin/base58.h"
#include "pkt.h"
#include "bitcoin/script.h"
#include "permute_tx.h"
#include "bitcoin/signature.h"
#include "commit_tx.h"
#include "bitcoin/pubkey.h"
#include "find_p2sh_out.h"
#include <openssl/ec.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct sha256 seed, revocation_hash;
	struct pkt *pkt;
	unsigned long long to_them = 0, from_them = 0;
	int64_t this_delta;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<seed> [previous-updates]\n"
			   "Create a new update message",
			   "Print this message.");
	opt_register_arg("--to-them=<satoshi>",
			 opt_set_ulonglongval_si, NULL, &to_them,
			 "Amount to pay them (must use this or --from-them)");
	opt_register_arg("--from-them=<satoshi>",
			 opt_set_ulonglongval_si, NULL, &from_them,
			 "Amount to pay us (must use this or --to-them)");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (!from_them && !to_them)
		opt_usage_exit_fail("Must use --to-them or --from-them");

	if (argc < 2)
		opt_usage_exit_fail("Expected 1+ arguments");

	if (!hex_decode(argv[1], strlen(argv[1]), &seed, sizeof(seed)))
		errx(1, "Invalid seed '%s' - need 256 hex bits", argv[1]);

	this_delta = from_them - to_them;
	if (!this_delta)
		errx(1, "Delta must not be zero");
	
	/* Get next revocation hash. */
	shachain_from_seed(&seed, argc - 2 + 1, &revocation_hash);
	sha256(&revocation_hash,
	       revocation_hash.u.u8, sizeof(revocation_hash.u.u8));
	
	pkt = update_pkt(ctx, &revocation_hash, this_delta);
	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}

