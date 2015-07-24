#include <ccan/crypto/shachain/shachain.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include "lightning.pb-c.h"
#include "protobuf_convert.h"
#include "pkt.h"
#include <unistd.h>

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_arr(NULL, char, 0);
	struct sha256 secret;
	Pkt *pkt;
	Sha256Hash *preimage;
	char hexstr[hex_str_size(sizeof(secret))];
	
	err_set_progname(argv[0]);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "<update-sig-or-update-complete>\n"
			   "Extract revocation preimage from message",
			   "Print this message.");

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 2)
		opt_usage_exit_fail("Expected 1 argument");

	pkt = any_pkt_from_file(argv[1]);

	switch (pkt->pkt_case) {
	case PKT__PKT_UPDATE_SIGNATURE:
		preimage = pkt->update_signature->revocation_preimage;
		break;
	case PKT__PKT_UPDATE_COMPLETE:
		preimage = pkt->update_complete->revocation_preimage;
		break;
	default:
		errx(1, "Unexpected packet type %u in %s",
		     pkt->pkt_case, argv[1]);
	}
	proto_to_sha256(preimage, &secret);

	if (!hex_encode(&secret, sizeof(secret), hexstr, sizeof(hexstr)))
		abort();

	if (!write_all(STDOUT_FILENO, hexstr, strlen(hexstr)))
		err(1, "Writing out hexstr");

	tal_free(ctx);
	return 0;
}

