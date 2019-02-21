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

static void do_generate(int argc, char **argv)
{
	const tal_t *ctx = talz(NULL, tal_t);
	int num_hops = argc - 2;
	struct pubkey pubkey;
	struct secret session_key;
	struct secret *shared_secrets;
	u8 *assocdata;
	struct sphinx_path *sp;
	struct short_channel_id scid;
	struct amount_msat amount;

	assocdata = tal_arr(ctx, u8, 32);
	memset(&session_key, 'A', sizeof(struct secret));
	memset(assocdata, 'B', tal_bytelen(assocdata));
	sp = sphinx_path_new_with_key(ctx, assocdata, &session_key);

	for (int i = 0; i < num_hops; i++) {
		if (!pubkey_from_hexstr(argv[i+2], strlen(argv[i+2]), &pubkey))
			errx(1, "Invalid public key hex '%s'", argv[i + 2]);

		amount.millisatoshis = i; /* Raw: test code */
		memset(&scid, i, sizeof(struct short_channel_id));
		sphinx_add_v0_hop(sp, &pubkey, &scid, amount, i);
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

static void do_decode(int argc, char **argv)
{
	const tal_t *ctx = talz(NULL, tal_t);
	u8 serialized[TOTAL_PACKET_SIZE];
	char hextemp[2 * sizeof(serialized) + 1];
	u8 *assocdata = tal_arr(ctx, u8, 32);
	struct route_step *step;

	memset(assocdata, 'B', tal_bytelen(assocdata));

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

	u8 *ser = serialize_onionpacket(ctx, step->next);
	if (!ser)
		errx(1, "Error serializing message.");

	printf("%s\n", tal_hex(ctx, ser));
	tal_free(ctx);
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
		*hopstok, *hop, *payloadtok, *pubkeytok, *realmtok, *oniontok, *decodetok;
	const u8 *associated_data, *session_key_raw, *payload, *serialized, *onion;
	struct secret session_key, *shared_secrets;
	struct pubkey pubkey;
	struct sphinx_path *path;
	size_t i;
	int realm;
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
		realmtok = json_get_member(buffer, hop, "realm");
		pubkeytok = json_get_member(buffer, hop, "pubkey");
		payload = json_tok_bin_from_hex(ctx, buffer, payloadtok);
		json_to_pubkey(buffer, pubkeytok, &pubkey);
		json_to_int(buffer, realmtok, &realm);
		sphinx_add_raw_hop(path, &pubkey, realm, payload);
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

	hopstok = json_get_member(buffer, gentok, "hops");
	json_for_each_arr(i, hop, hopstok) {
		payloadtok = json_get_member(buffer, hop, "payload");
		realmtok = json_get_member(buffer, hop, "realm");
		pubkeytok = json_get_member(buffer, hop, "pubkey");
		payload = json_tok_bin_from_hex(ctx, buffer, payloadtok);
		json_to_pubkey(buffer, pubkeytok, &pubkey);
		json_to_int(buffer, realmtok, &realm);
		sphinx_add_raw_hop(path, &pubkey, realm, payload);
	}

	decodetok = json_get_member(buffer, toks, "decode");

	json_for_each_arr(i, hop, decodetok) {
		hexprivkey = json_strdup(ctx, buffer, hop);
		printf("Processing at hop %zu\n", i);
		step = decode_with_privkey(ctx, serialized, hexprivkey, associated_data);
		serialized = serialize_onionpacket(ctx, step->next);
		if (!serialized)
			errx(1, "Error serializing message.");
		printf("  Realm: %d\n", step->realm);
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

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
						 SECP256K1_CONTEXT_SIGN);

	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "decode <onion>\ngenerate <pubkey1> <pubkey2> ...\nruntest <test-filename>", "Show this message");
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
		do_generate(argc, argv);
	} else if (streq(method, "decode")) {
		do_decode(argc, argv);
	} else {
		errx(1, "Unrecognized method '%s'", method);
	}
	return 0;
}
