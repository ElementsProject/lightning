#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/structeq/structeq.h>
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
	OpenChannel *o2;
	OpenComplete *c;
	struct sha256 escape_secret, escape_hash, expect;

	err_set_progname(argv[0]);
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<our-escape-secret>\n"
			   "A test program to create an open-complete message on stdout.",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 3)
		opt_usage_exit_fail("Expected 2 arguments");

	o2 = pkt_from_file(argv[1], PKT__PKT_OPEN)->open;
	c = pkt_from_file(argv[2], PKT__PKT_OPEN_COMPLETE)->open_complete;
	proto_to_sha256(c->escape_preimage, &escape_secret);
	proto_to_sha256(o2->escape_hash, &expect);

	/* Get hash from escape secret. */
	sha256(&escape_hash, escape_secret.u.u8, sizeof(escape_secret.u.u8));
	if (!structeq(&escape_hash, &expect))
		errx(1, "Invalid escape preimage");
	
	tal_free(ctx);
	return 0;
}
