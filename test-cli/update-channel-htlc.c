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
#include "permute_tx.h"
#include "bitcoin/signature.h"
#include "commit_tx.h"
#include "bitcoin/pubkey.h"
#include "find_p2sh_out.h"
#include "version.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct sha256 seed, revocation_hash, rval, rhash;
	struct pkt *pkt;
	uint64_t htlc_val;
	u32 locktime_seconds;
	unsigned update_num;
	char *endp;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<seed> <update-number> <satoshi> <r-value> <abs-locktime-seconds>\n"
			   "Create a new HTLC update message",
			   "Print this message.");
	opt_register_version();

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 6)
		opt_usage_exit_fail("Expected 5 arguments");

	if (!hex_decode(argv[1], strlen(argv[1]), &seed, sizeof(seed)))
		errx(1, "Invalid seed '%s' - need 256 hex bits", argv[1]);
	update_num = atoi(argv[2]);
	if (!update_num)
		errx(1, "Update number %s invalid", argv[2]);

	htlc_val = strtol(argv[3], &endp, 10);
	if (*endp || !htlc_val)
		errx(1, "Expected number for %s", argv[3]);

	if (!hex_decode(argv[4], strlen(argv[4]), &rval, sizeof(rval)))
		errx(1, "Invalid rvalue '%s' - need 256 hex bits", argv[4]);

	locktime_seconds = strtol(argv[5], &endp, 10);
	if (*endp || !locktime_seconds)
		errx(1, "Expected locktime for %s", argv[5]);

	/* Get next revocation hash. */
	shachain_from_seed(&seed, update_num, &revocation_hash);
	sha256(&revocation_hash,
	       revocation_hash.u.u8, sizeof(revocation_hash.u.u8));

	/* Get htlc rvalue hash. */
	sha256(&rhash, &rval, sizeof(rval));
	
	pkt = update_htlc_add_pkt(ctx, &revocation_hash, htlc_val,
				  &rhash, locktime_seconds);
	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}

