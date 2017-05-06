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

#include "lightningd/sphinx.h"
#include "utils.h"

secp256k1_context *secp256k1_ctx;

static struct secret secret_from_hex(const char *hex)
{
	struct secret s;
	if (!hex_decode(hex, strlen(hex), &s, sizeof(s)))
		abort();
	return s;
}

/* Create an onionreply with the test vector parameters and check that
 * we match the test vectors and that we can also unwrap it. */
static void run_unit_tests(void)
{
	tal_t *tmpctx = tal_tmpctx(NULL);
	struct onionreply *oreply;
	u8 *reply;
	u8 *raw = tal_hexdata(tmpctx, "2002", 4);

	/* Shared secrets we already have from the forward path */
	char *secrets[] = {
	    "53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66",
	    "a6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae",
	    "3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc",
	    "21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d",
	    "b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328",
	};
	struct secret ss[] = {
		secret_from_hex(secrets[0]),
		secret_from_hex(secrets[1]),
		secret_from_hex(secrets[2]),
		secret_from_hex(secrets[3]),
		secret_from_hex(secrets[4])
	};

	int replylen = 164 * 2;

	u8 *intermediates[] = {
	    tal_hexdata(tmpctx, "500d8596f76d3045bfdbf99914b98519fe76ea130dc223"
				"38c473ab68d74378b13a06a19f891145610741c83ad40b"
				"7712aefaddec8c6baf7325d92ea4ca4d1df8bce517f7e5"
				"4554608bf2bd8071a4f52a7a2f7ffbb1413edad81eeea5"
				"785aa9d990f2865dc23b4bc3c301a94eec4eabebca66be"
				"5cf638f693ec256aec514620cc28ee4a94bd9565bc4d49"
				"62b9d3641d4278fb319ed2b84de5b665f307a2db0f7fbb"
				"757366",
			replylen),
	    tal_hexdata(tmpctx, "669478a3ddf9ba4049df8fa51f73ac712b9c20380cda43"
				"1696963a492713ebddb7dfadbb566c8dae8857add94e67"
				"02fb4c3a4de22e2e669e1ed926b04447fc73034bb730f4"
				"932acd62727b75348a648a1128744657ca6a4e713b9b64"
				"6c3ca66cac02cdab44dd3439890ef3aaf61708714f7375"
				"349b8da541b2548d452d84de7084bb95b3ac2345201d62"
				"4d31f4d52078aa0fa05a88b4e20202bd2b86ac5b52919e"
				"a305a8",
			replylen),
	    tal_hexdata(tmpctx, "6984b0ccd86f37995857363df13670acd064bfd1a540e5"
				"21cad4d71c07b1bc3dff9ac25f41addfb7466e74f81b3e"
				"545563cdd8f5524dae873de61d7bdfccd496af2584930d"
				"2b566b4f8d3881f8c043df92224f38cf094cfc09d92655"
				"989531524593ec6d6caec1863bdfaa79229b5020acc034"
				"cd6deeea1021c50586947b9b8e6faa83b81fbfa6133c0a"
				"f5d6b07c017f7158fa94f0d206baf12dda6b68f785b773"
				"b360fd",
			replylen),
	    tal_hexdata(tmpctx, "08cd44478211b8a4370ab1368b5ffe8c9c92fb830ff4ad"
				"6e3b0a316df9d24176a081bab161ea0011585323930fa5"
				"b9fae0c85770a2279ff59ec427ad1bbff9001c0cd14970"
				"04bd2a0f68b50704cf6d6a4bf3c8b6a0833399a24b3456"
				"961ba00736785112594f65b6b2d44d9f5ea4e49b5e1ec2"
				"af978cbe31c67114440ac51a62081df0ed46d4a3df295d"
				"a0b0fe25c0115019f03f15ec86fabb4c852f83449e812f"
				"141a93",

			replylen),
	    tal_hexdata(tmpctx, "69b1e5a3e05a7b5478e6529cd1749fdd8c66da6f6db420"
				"78ff8497ac4e117e91a8cb9168b58f2fd45edd73c1b0c8"
				"b33002df376801ff58aaa94000bf8a86f92620f343baef"
				"38a580102395ae3abf9128d1047a0736ff9b83d456740e"
				"bbb4aeb3aa9737f18fb4afb4aa074fb26c4d702f429688"
				"88550a3bded8c05247e045b866baef0499f079fdaeef65"
				"38f31d44deafffdfd3afa2fb4ca9082b8f1c465371a989"
				"4dd8c2",
			replylen),
	};

	reply = create_onionreply(tmpctx, &ss[4], raw);
	for (int i = 4; i >= 0; i--) {
		printf("input_packet %s\n", tal_hex(tmpctx, reply));
		reply = wrap_onionreply(tmpctx, &ss[i], reply);
		printf("obfuscated_packet %s\n", tal_hex(tmpctx, reply));
		assert(memcmp(reply, intermediates[i], tal_len(reply)) == 0);
	}

	oreply = unwrap_onionreply(tmpctx, ss, 5, reply);
	printf("unwrapped %s\n", tal_hex(tmpctx, oreply->msg));
	assert(memcmp(raw, oreply->msg, tal_len(raw)) == 0);

	tal_free(tmpctx);
}

int main(int argc, char **argv)
{
	bool generate = false, decode = false, unit = false;
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
	opt_register_noarg("--unit",
			   opt_set_bool, &unit,
			   "Run unit tests against test vectors");

	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (unit) {
		run_unit_tests();
	} else if (generate) {
		int num_hops = argc - 1;
		struct pubkey *path = tal_arr(ctx, struct pubkey, num_hops);
		u8 privkeys[argc - 1][32];
		u8 sessionkey[32];
		struct hop_data hops_data[num_hops];
		struct secret *shared_secrets;
		
		memset(&sessionkey, 'A', sizeof(sessionkey));

		int i;
		for (i = 0; i < num_hops; i++) {
			hex_decode(argv[1 + i], 66, privkeys[i], 33);
			if (secp256k1_ec_pubkey_create(secp256k1_ctx, &path[i].pubkey, privkeys[i]) != 1)
				return 1;
		}

		for (i = 0; i < num_hops; i++) {
			hops_data[i].realm = 0x00;
			memset(&hops_data[i].channel_id, i,
			       sizeof(hops_data[i].channel_id));
			hops_data[i].amt_forward = i;
			hops_data[i].outgoing_cltv = i;
		}

		struct onionpacket *res = create_onionpacket(ctx,
							     path,
							     hops_data,
							     sessionkey,
							     assocdata,
							     sizeof(assocdata),
							     &shared_secrets);

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
		u8 shared_secret[32];

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

		if (!onion_shared_secret(shared_secret, msg, &seckey))
			errx(1, "Error creating shared secret.");
		
		step = process_onionpacket(ctx, msg, shared_secret, assocdata,
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
