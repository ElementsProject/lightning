#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/short_types/short_types.h>
#include <ccan/str/hex/hex.h>
#include <common/amount.h>
#include <common/sphinx.h>
#include <common/utils.h>
#include <err.h>
#include <secp256k1.h>
#include <stdio.h>
#include <unistd.h>

static void do_generate(int argc, char **argv)
{
	const tal_t *ctx = talz(NULL, tal_t);
	int num_hops = argc - 1;
	struct pubkey *path = tal_arr(ctx, struct pubkey, num_hops);
	u8 rawpubkey[33];
	struct secret session_key;
	struct hop_data hops_data[num_hops];
	struct secret *shared_secrets;
	u8 *assocdata;
	struct sphinx_path *sp;

	assocdata = tal_arr(ctx, u8, 32);
	memset(&session_key, 'A', sizeof(struct secret));
	memset(assocdata, 'B', tal_bytelen(assocdata));

	sp = sphinx_path_new_with_key(ctx, assocdata, &session_key);

	for (int i = 0; i < num_hops; i++) {
		if (!hex_decode(argv[1 + i], 66, rawpubkey, 33)) {
			errx(1, "Invalid public key hex '%s'", argv[1 + i]);
		}

		if (secp256k1_ec_pubkey_parse(secp256k1_ctx, &path[i].pubkey,
					      rawpubkey, 33) != 1)
			errx(1, "Could not decode pubkey");

		fprintf(stderr, "Node %d pubkey %s\n", i,
			secp256k1_pubkey_to_hexstr(ctx, &path[i].pubkey));

		memset(&hops_data[i], 0, sizeof(hops_data[i]));
		hops_data[i].realm = i;
		memset(&hops_data[i].channel_id, i,
		       sizeof(hops_data[i].channel_id));
		hops_data[i].amt_forward.millisatoshis = i; /* Raw: test code */
		hops_data[i].outgoing_cltv = i;
		sphinx_add_v0_hop(sp, &path[i], &hops_data[i].channel_id, hops_data[i].amt_forward, i);
	}

	struct onionpacket *res =
		create_onionpacket(ctx, sp, &shared_secrets);

	u8 *serialized = serialize_onionpacket(ctx, res);
	if (!serialized)
		errx(1, "Error serializing message.");
	else
		printf("%s\n", tal_hex(ctx, serialized));
	tal_free(ctx);
}

static void do_decode(int argc, char **argv)
{
	struct route_step *step;
	struct onionpacket *msg;
	struct privkey seckey;
	const tal_t *ctx = talz(NULL, tal_t);
	u8 serialized[TOTAL_PACKET_SIZE];
	char hextemp[2 * sizeof(serialized) + 1];
	memset(hextemp, 0, sizeof(hextemp));
	u8 shared_secret[32];
	u8 assocdata[32];
	enum onion_type why_bad;

	memset(&assocdata, 'B', sizeof(assocdata));

	if (argc != 2)
		opt_usage_exit_fail("Expect a privkey with --decode");

	if (!hex_decode(argv[1], strlen(argv[1]), &seckey, sizeof(seckey)))
		errx(1, "Invalid private key hex '%s'", argv[1]);

	if (!read_all(STDIN_FILENO, hextemp, sizeof(hextemp)))
		errx(1, "Reading in onion");

	if (!hex_decode(hextemp, sizeof(hextemp), serialized, sizeof(serialized))) {
		errx(1, "Invalid onion hex '%s'", hextemp);
	}

	msg = parse_onionpacket(ctx, serialized, sizeof(serialized), &why_bad);

	if (!msg)
		errx(1, "Error parsing message: %s", onion_type_name(why_bad));

	if (!onion_shared_secret(shared_secret, msg, &seckey))
		errx(1, "Error creating shared secret.");

	step = process_onionpacket(ctx, msg, shared_secret, assocdata,
				   sizeof(assocdata));

	if (!step || !step->next)
		errx(1, "Error processing message.");

	u8 *ser = serialize_onionpacket(ctx, step->next);
	if (!ser)
		errx(1, "Error serializing message.");

	printf("%s\n", tal_hex(ctx, ser));
	tal_free(ctx);
}

int main(int argc, char **argv)
{
	setup_locale();

	bool generate = false, decode = false;
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
						 SECP256K1_CONTEXT_SIGN);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "--generate <pubkey1> <pubkey2>... OR\n"
			   "--decode <privkey>\n"
			   "Either create an onion message, or decode one step",
			   "Print this message.");
	opt_register_noarg("--generate", opt_set_bool, &generate,
			   "Generate onion through the given hex pubkeys");
	opt_register_noarg("--decode", opt_set_bool, &decode,
			   "Decode onion from stdin given the private key");

	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (generate)
		do_generate(argc, argv);
	else if (decode)
		do_decode(argc, argv);
	return 0;
}
