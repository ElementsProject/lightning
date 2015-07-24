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

/* Create message to reveal escape preimage to invalidate our escape txs. */
int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct sha256 escape_secret;
	struct pkt *pkt;

	err_set_progname(argv[0]);
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<our-escape-secret>\n"
			   "A test program to create an open-complete message on stdout.",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 2)
		opt_usage_exit_fail("Expected 1 argument");

	if (!hex_decode(argv[1], strlen(argv[1]), &escape_secret,
			sizeof(escape_secret)))
		errx(1, "Invalid escape hash '%s' - need 256 hex bits", argv[1]);

	pkt = open_complete_pkt(ctx, &escape_secret);

	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");
	
	tal_free(ctx);
	return 0;
}
