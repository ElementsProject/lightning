#include <assert.h>
#include <ccan/mem/mem.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/short_types/short_types.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <common/amount.h>
#include <common/json.h>
#include <common/json_helpers.h>
#include <common/sphinx.h>
#include <common/utils.h>
#include <common/version.h>
#include <err.h>
#include <secp256k1.h>
#include <stdio.h>
#include <unistd.h>

#define ASSOC_DATA_SIZE 32

static void do_generate(int argc, char **argv,
			const u8 assocdata[ASSOC_DATA_SIZE])
{
	const tal_t *ctx = talz(NULL, tal_t);
	int num_hops = argc - 2;
	struct pubkey *path = tal_arr(ctx, struct pubkey, num_hops);
	u8 rawprivkey[PRIVKEY_LEN];
	struct secret session_key;
	struct secret *shared_secrets;
	struct sphinx_path *sp;
	struct hop_data hops_data[num_hops];

	assocdata = tal_arr(ctx, u8, ASSOC_DATA_SIZE);
	memset(&session_key, 'A', sizeof(struct secret));

	sp = sphinx_path_new_with_key(ctx, assocdata, &session_key);

	for (int i = 0; i < num_hops; i++) {
		size_t klen = strcspn(argv[1 + i], "/");
		if (hex_data_size(klen) == PRIVKEY_LEN) {
			if (!hex_decode(argv[1 + i], klen, rawprivkey, PRIVKEY_LEN))
				errx(1, "Invalid private key hex '%s'",
				     argv[1 + i]);

			if (secp256k1_ec_pubkey_create(secp256k1_ctx,
						       &path[i].pubkey,
						       rawprivkey) != 1)
				errx(1, "Could not decode pubkey");
		} else if (hex_data_size(klen) == PUBKEY_CMPR_LEN) {
			if (!pubkey_from_hexstr(argv[i + 1], klen, &path[i]))
				errx(1, "Invalid public key hex '%s'",
				     argv[1 + i]);
		} else {
			errx(1,
			     "Provided key is neither a pubkey nor a privkey: "
			     "%s\n",
			     argv[1 + i]);
		}

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

static struct route_step *decode_with_privkey(const tal_t *ctx, const u8 *onion, char *hexprivkey, const u8 *assocdata)
{
	struct privkey seckey;
	struct route_step *step;
	struct onionpacket *packet;
	enum onion_type why_bad;
	u8 shared_secret[32];
	if (!hex_decode(hexprivkey, strlen(hexprivkey), &seckey, sizeof(seckey)))
		errx(1, "Invalid private key hex '%s'", hexprivkey);

	packet = parse_onionpacket(ctx, onion, TOTAL_PACKET_SIZE, &why_bad);

	if (!packet)
		errx(1, "Error parsing message: %s", onion_type_name(why_bad));

	if (!onion_shared_secret(shared_secret, packet, &seckey))
		errx(1, "Error creating shared secret.");

	step = process_onionpacket(ctx, packet, shared_secret, assocdata,
				   tal_bytelen(assocdata));
	return step;

}

static void do_decode(int argc, char **argv, const u8 assocdata[ASSOC_DATA_SIZE])
{
	const tal_t *ctx = talz(NULL, tal_t);
	u8 serialized[TOTAL_PACKET_SIZE];
	struct route_step *step;
	char hextemp[2 * sizeof(serialized)];
	memset(hextemp, 0, sizeof(hextemp));

	if (argc != 3)
		opt_usage_exit_fail("Expect a privkey with --decode");

	if (!read_all(STDIN_FILENO, hextemp, sizeof(hextemp)))
		errx(1, "Reading in onion");

	if (!hex_decode(hextemp, sizeof(hextemp), serialized, sizeof(serialized))) {
		errx(1, "Invalid onion hex '%s'", hextemp);
	}

	step = decode_with_privkey(ctx, serialized, tal_strdup(ctx, argv[2]), assocdata);

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

/**
 * Run an onion encoding/decoding unit-test from a file
 */
static void runtest(const char *filename)
{
	const tal_t *ctx = tal(NULL, u8);
	bool valid;
	char *buffer = grab_file(ctx, filename);
	const jsmntok_t *toks, *session_key_tok, *associated_data_tok, *gentok,
		*hopstok, *hop, *payloadtok, *pubkeytok, *typetok, *oniontok, *decodetok;
	const u8 *associated_data, *session_key_raw, *payload, *serialized, *onion;
	struct secret session_key, *shared_secrets;
	struct pubkey pubkey;
	struct sphinx_path *path;
	size_t i;
	enum sphinx_payload_type type;
	struct onionpacket *res;
	struct route_step *step;
	char *hexprivkey;

	toks = json_parse_input(ctx, buffer, strlen(buffer), &valid);
	if (!valid)
		errx(1, "File is not a valid JSON file.");

	gentok = json_get_member(buffer, toks, "generate");
	if (!gentok)
		errx(1, "JSON object does not contain a 'generate' key");

	/* Unpack the common parts */
	associated_data_tok = json_get_member(buffer, gentok, "associated_data");
	session_key_tok = json_get_member(buffer, gentok, "session_key");
	associated_data = json_tok_bin_from_hex(ctx, buffer, associated_data_tok);
	session_key_raw = json_tok_bin_from_hex(ctx, buffer, session_key_tok);
	memcpy(&session_key, session_key_raw, sizeof(session_key));
	path = sphinx_path_new_with_key(ctx, associated_data, &session_key);

	/* Unpack the hops and build up the path */
	hopstok = json_get_member(buffer, gentok, "hops");
	json_for_each_arr(i, hop, hopstok) {
		payloadtok = json_get_member(buffer, hop, "payload");
		typetok = json_get_member(buffer, hop, "type");
		pubkeytok = json_get_member(buffer, hop, "pubkey");
		payload = json_tok_bin_from_hex(ctx, buffer, payloadtok);
		json_to_pubkey(buffer, pubkeytok, &pubkey);
		if (!typetok || json_tok_streq(buffer, typetok, "legacy")) {
			type = SPHINX_V0_PAYLOAD;
		} else {
			type = SPHINX_RAW_PAYLOAD;
		}
		sphinx_add_raw_hop(path, &pubkey, type, payload);
	}
	res = create_onionpacket(ctx, path, &shared_secrets);
	serialized = serialize_onionpacket(ctx, res);

	if (!serialized)
		errx(1, "Error serializing message.");

	oniontok = json_get_member(buffer, toks, "onion");

	if (oniontok) {
		onion = json_tok_bin_from_hex(ctx, buffer, oniontok);
		if (!memeq(onion, tal_bytelen(onion), serialized,
			   tal_bytelen(serialized)))
			errx(1,
			     "Generated does not match the expected onion: \n"
			     "generated: %s\n"
			     "expected : %s\n",
			     tal_hex(ctx, serialized), tal_hex(ctx, onion));
	}
	printf("Generated onion: %s\n", tal_hex(ctx, serialized));

	decodetok = json_get_member(buffer, toks, "decode");

	json_for_each_arr(i, hop, decodetok) {
		hexprivkey = json_strdup(ctx, buffer, hop);
		printf("Processing at hop %zu\n", i);
		step = decode_with_privkey(ctx, serialized, hexprivkey, associated_data);
		serialized = serialize_onionpacket(ctx, step->next);
		if (!serialized)
			errx(1, "Error serializing message.");
		printf("  Type: %d\n", step->type);
		printf("  Payload: %s\n", tal_hex(ctx, step->raw_payload));
		printf("  Next onion: %s\n", tal_hex(ctx, serialized));
		printf("  Next HMAC: %s\n", tal_hexstr(ctx, step->next->mac, HMAC_SIZE));
	}

	tal_free(ctx);
}

/* Tal wrappers for opt. */
static void *opt_allocfn(size_t size)
{
	return tal_arr_label(NULL, char, size, TAL_LABEL("opt_allocfn", ""));
}

static void *tal_reallocfn(void *ptr, size_t size)
{
	if (!ptr)
		return opt_allocfn(size);
	tal_resize_(&ptr, 1, size, false);
	return ptr;
}

static void tal_freefn(void *ptr)
{
	tal_free(ptr);
}

int main(int argc, char **argv)
{
	setup_locale();
	const char *method;
	u8 assocdata[ASSOC_DATA_SIZE];
	memset(&assocdata, 'B', sizeof(assocdata));

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
						 SECP256K1_CONTEXT_SIGN);

	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);
	opt_register_arg("--assoc-data", opt_set_ad, opt_show_ad,
			 assocdata,
			 "Associated data (usu. payment_hash of payment)");
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "\n\n\tdecode <onion>\n"
			   "\tgenerate <pubkey1> <pubkey2> ...\n"
			   "\tgenerate <pubkey1>[/hopdata] <pubkey2>[/hopdata]\n"
			   "\tgenerate <privkey1>[/hopdata] <privkey2>[/hopdata]\n"
			   "\truntest <test-filename>\n\n", "Show this message");
	opt_register_version();

	opt_early_parse(argc, argv, opt_log_stderr_exit);
	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 2)
		errx(1, "You must specify a method");
	method = argv[1];

	if (streq(method, "runtest")) {
		if (argc != 3)
			errx(1, "'runtest' requires a filename argument");
		runtest(argv[2]);
	} else if (streq(method, "generate")) {
		do_generate(argc, argv, assocdata);
	} else if (streq(method, "decode")) {
		do_decode(argc, argv, assocdata);
	} else {
		errx(1, "Unrecognized method '%s'", method);
	}
	return 0;
}
