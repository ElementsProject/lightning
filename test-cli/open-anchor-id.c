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

int main(int argc, char *argv[])
{
	struct pkt *pkt;
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct bitcoin_tx *anchor;
	struct sha256_double txid;
	unsigned int i;

	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<anchor-tx-file> <change-key>\n"
			   "A test program to output open-anchor on stdout.",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 3)
		opt_usage_exit_fail("Expected 1 argument");

	anchor = bitcoin_tx_from_file(ctx, argv[1]);
	bitcoin_txid(anchor, &txid);

	/* Figure out which output is for the commit tx. */
	if (anchor->output_count != 1) {
		u8 *script;
		struct pubkey change_key;
		if (!pubkey_from_hexstr(argv[2], &change_key))
			errx(1, "Invalid change key %s", argv[2]);

		if (anchor->output_count != 2)
			errx(1, "Expected 1 or 2 outputs on anchor");

		script = scriptpubkey_p2sh(anchor,
					   bitcoin_redeem_single(anchor,
								 &change_key));
		for (i = 0; i < anchor->output_count; i++) {
			if (anchor->output[i].script_length != tal_count(script))
				continue;
			if (memcmp(anchor->output[i].script, script,
				   tal_count(script)) == 0)
				break;
		}
		if (i == anchor->output_count)
			errx(1, "No output to change found");

		/* We found change output, so we want the other one. */
		i = !i;
	} else
		i = 0;

	pkt = open_anchor_pkt(ctx, &txid, i);
	if (!write_all(STDOUT_FILENO, pkt, pkt_totlen(pkt)))
		err(1, "Writing out packet");

	tal_free(ctx);
	return 0;
}
