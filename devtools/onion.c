#include <assert.h>
#include <ccan/mem/mem.h>
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

#define ASSOC_DATA_SIZE 32
#define PUBKEY_LEN 33
#define PRIVKEY_LEN 32

static void do_generate(int argc, char **argv,
			const u8 assocdata[ASSOC_DATA_SIZE])
{
	const tal_t *ctx = talz(NULL, tal_t);
	int num_hops = argc - 1;
	struct pubkey *path = tal_arr(ctx, struct pubkey, num_hops);
	u8 rawpubkey[PUBKEY_LEN], rawprivkey[PRIVKEY_LEN];
	struct secret session_key;
	struct secret *shared_secrets;
	struct sphinx_path *sp;
	struct hop_data hops_data[num_hops];

	assocdata = tal_arr(ctx, u8, ASSOC_DATA_SIZE);
	memset(&session_key, 'A', sizeof(struct secret));

	sp = sphinx_path_new_with_key(ctx, assocdata, &session_key);

	for (int i = 0; i < num_hops; i++) {
		size_t klen = strcspn(argv[1 + i], "/");
		assert(klen == 2 * PUBKEY_LEN || klen == 2 * PRIVKEY_LEN);
		if (klen == 2 * PRIVKEY_LEN) {
			if (!hex_decode(argv[1 + i], klen, rawprivkey, PRIVKEY_LEN))
				errx(1, "Invalid private key hex '%s'",
				     argv[1 + i]);

			if (secp256k1_ec_pubkey_create(secp256k1_ctx,
						       &path[i].pubkey,
						       rawprivkey) != 1)
				errx(1, "Could not decode pubkey");
		} else if (klen == 2 * PUBKEY_LEN) {
			if (!hex_decode(argv[1 + i], 2 * PUBKEY_LEN, rawpubkey,
					PUBKEY_LEN)) {
				errx(1, "Invalid public key hex '%s'",
				     argv[1 + i]);
			}

			if (secp256k1_ec_pubkey_parse(secp256k1_ctx,
						      &path[i].pubkey,
						      rawpubkey, PUBKEY_LEN) != 1)
				errx(1, "Could not decode pubkey");
		} else {
			fprintf(stderr,
				"Provided key is neither a pubkey nor a "
				"privkey: %s\n",
				argv[1 + i]);
		}
		fprintf(stderr, "Node %d pubkey %s\n", i,
			secp256k1_pubkey_to_hexstr(ctx, &path[i].pubkey));

		memset(&hops_data[i], 0, sizeof(hops_data[i]));
		if (argv[1 + i][klen] != '\0') {
			/* FIXME: Generic realm support, not this hack! */
			/* FIXME: Multi hop! */
			const char *hopstr = argv[1 + i] + klen + 1;
			size_t dsize = hex_data_size(strlen(hopstr));
			be64 scid, msat;
			be32 cltv;
			u8 padding[12];
			if (dsize != 33)
				errx(1, "hopdata expected 33 bytes");
			if (!hex_decode(hopstr, 2,
					&hops_data[i].realm,
					sizeof(hops_data[i].realm))
			    || !hex_decode(hopstr + 2, 16,
					   &scid, sizeof(scid))
			    || !hex_decode(hopstr + 2 + 16, 16,
					   &msat, sizeof(msat))
			    || !hex_decode(hopstr + 2 + 16 + 16, 8,
					   &cltv, sizeof(cltv))
			    || !hex_decode(hopstr + 2 + 16 + 16 + 8, 24,
					   padding, sizeof(padding)))
				errx(1, "hopdata bad hex");
			if (hops_data[i].realm != 0)
				errx(1, "FIXME: Only realm 0 supported");
			if (!memeqzero(padding, sizeof(padding)))
				errx(1, "FIXME: Only zero padding supported");
			/* Fix endian up */
			hops_data[i].channel_id.u64
				= be64_to_cpu(scid);
			hops_data[i].amt_forward.millisatoshis /* Raw: test code */
				= be64_to_cpu(msat);
			hops_data[i].outgoing_cltv
				= be32_to_cpu(cltv);
		} else {
			hops_data[i].realm = i;
			memset(&hops_data[i].channel_id, i,
			       sizeof(hops_data[i].channel_id));
			hops_data[i].amt_forward.millisatoshis = i; /* Raw: test code */
			hops_data[i].outgoing_cltv = i;
		}
		fprintf(stderr, "Hopdata %d: %s\n", i, tal_hexstr(NULL, &hops_data[i], sizeof(hops_data[i])));
		sphinx_add_v0_hop(sp, &path[i], &hops_data[i].channel_id, hops_data[i].amt_forward, i);
	}

	struct onionpacket *res = create_onionpacket(ctx, sp, &shared_secrets);

	u8 *serialized = serialize_onionpacket(ctx, res);
	if (!serialized)
		errx(1, "Error serializing message.");
	printf("%s\n", tal_hex(ctx, serialized));
	tal_free(ctx);
}

static void do_decode(int argc, char **argv, const u8 assocdata[ASSOC_DATA_SIZE])
{
	struct route_step *step;
	struct onionpacket *msg;
	struct privkey seckey;
	const tal_t *ctx = talz(NULL, tal_t);
	u8 serialized[TOTAL_PACKET_SIZE];
	char hextemp[2 * sizeof(serialized)];
	memset(hextemp, 0, sizeof(hextemp));
	u8 shared_secret[32];
	enum onion_type why_bad;

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

	step = process_onionpacket(ctx, msg, shared_secret,
				   assocdata, ASSOC_DATA_SIZE);

	if (!step || !step->next)
		errx(1, "Error processing message.");

	printf("payload=%s\n", tal_hex(ctx, step->raw_payload));
	if (step->nextcase == ONION_FORWARD) {
		u8 *ser = serialize_onionpacket(ctx, step->next);
		if (!ser)
			errx(1, "Error serializing message.");
		printf("next=%s\n", tal_hex(ctx, ser));
	}
	tal_free(ctx);
}

static char *opt_set_ad(const char *arg, u8 *assocdata)
{
	if (!hex_decode(arg, strlen(arg), assocdata, ASSOC_DATA_SIZE))
		return "Bad hex string";
	return NULL;
}

static void opt_show_ad(char buf[OPT_SHOW_LEN], const u8 *assocdata)
{
	hex_encode(assocdata, ASSOC_DATA_SIZE, buf, OPT_SHOW_LEN);
}

int main(int argc, char **argv)
{
	setup_locale();

	bool generate = false, decode = false;
	u8 assocdata[ASSOC_DATA_SIZE];

	memset(&assocdata, 'B', sizeof(assocdata));

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
						 SECP256K1_CONTEXT_SIGN);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "--generate <pubkey1>[/hopdata] <pubkey2>[/hopdata]... OR\n"
			   "--generate <privkey1>[/hopdata] <privkey2>[/hopdata]... OR\n"
			   "--decode <privkey>\n"
			   "Either create an onion message, or decode one step",
			   "Print this message.");
	opt_register_noarg("--generate", opt_set_bool, &generate,
			   "Generate onion through the given hex pubkeys");
	opt_register_noarg("--decode", opt_set_bool, &decode,
			   "Decode onion from stdin given the private key");
	opt_register_arg("--assoc-data", opt_set_ad, opt_show_ad,
			 assocdata,
			 "Associated data (usu. payment_hash of payment)");

	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (generate)
		do_generate(argc, argv, assocdata);
	else if (decode)
		do_decode(argc, argv, assocdata);
	return 0;
}
