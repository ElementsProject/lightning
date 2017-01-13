#include <secp256k1.h>
#include <ccan/opt/opt.h>
#include <ccan/short_types/short_types.h>
#include <string.h>
#include <ccan/str/hex/hex.h>
#include <ccan/read_write_all/read_write_all.h>
#include <err.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>

#include "daemon/sphinx.h"
#include "daemon/sphinx.c"

int main(int argc, char **argv)
{
	bool generate = false, decode = false;
	const tal_t *ctx = talz(NULL, tal_t);
	u8 assocdata[32];
	memset(assocdata, 'B', sizeof(assocdata));

	secp256k1_ctx = secp256k1_context_create(
		SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
	
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "--generate <pubkey1> <pubkey2>... OR\n"
			   "--decode <privkey>\n"
			   "Either create an onion message, or decode one step",
			   "Print this message.");
	opt_register_noarg("--generate",
			   opt_set_bool, &generate,
			   "Generate onion through the given hex pubkeys");
	opt_register_noarg("--decode",
			   opt_set_bool, &decode,
			   "Decode onion from stdin given the private key");

	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (generate) {
		int num_hops = argc - 1;
		struct pubkey *path = tal_arr(ctx, struct pubkey, num_hops);
		u8 privkeys[argc - 1][32];
		u8 sessionkey[32];

		memset(&sessionkey, 'A', sizeof(sessionkey));

		int i;
		for (i = 0; i < num_hops; i++) {
			hex_decode(argv[1 + i], 66, privkeys[i], 33);
			if (secp256k1_ec_pubkey_create(secp256k1_ctx, &path[i].pubkey, privkeys[i]) != 1)
				return 1;
		}

		struct hoppayload *hoppayloads = tal_arr(ctx, struct hoppayload, num_hops);
		for (i=0; i<num_hops; i++)
			memset(&hoppayloads[i], 'A', sizeof(hoppayloads[i]));

		struct onionpacket *res = create_onionpacket(ctx,
							     path,
							     hoppayloads,
							     sessionkey,
							     assocdata,
							     sizeof(assocdata));

		u8 *serialized = serialize_onionpacket(ctx, res);
		if (!serialized)
			errx(1, "Error serializing message.");

		char hextemp[2 * tal_count(serialized) + 1];
		hex_encode(serialized, tal_count(serialized), hextemp, sizeof(hextemp));
		printf("%s\n", hextemp);

	} else if (decode) {
		struct route_step *step;
		struct onionpacket *msg;
		struct privkey seckey;
		const tal_t *ctx = talz(NULL, tal_t);
		u8 serialized[TOTAL_PACKET_SIZE];
		char hextemp[2 * sizeof(serialized) + 1];
		memset(hextemp, 0, sizeof(hextemp));

		if (argc != 2)
			opt_usage_exit_fail("Expect a privkey with --decode");
		if (!hex_decode(argv[1], strlen(argv[1]), &seckey, sizeof(seckey)))
			errx(1, "Invalid private key hex '%s'", argv[1]);
		if (!read_all(STDIN_FILENO, hextemp, sizeof(hextemp)))
			errx(1, "Reading in onion");
		hex_decode(hextemp, sizeof(hextemp), serialized, sizeof(serialized));

		msg = parse_onionpacket(ctx, serialized, sizeof(serialized));
		if (!msg)
			errx(1, "Error parsing message.");

		step = process_onionpacket(ctx, msg, &seckey, assocdata,
					   sizeof(assocdata));

		if (!step->next)
			errx(1, "Error processing message.");

		u8 *ser = serialize_onionpacket(ctx, step->next);
		if (!ser)
			errx(1, "Error serializing message.");

		hex_encode(ser, tal_count(ser), hextemp, sizeof(hextemp));
		printf("%s\n", hextemp);
	}
	secp256k1_context_destroy(secp256k1_ctx);
	tal_free(ctx);
	return 0;
}
