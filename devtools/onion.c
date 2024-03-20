#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <common/ecdh.h>
#include <common/json_parse.h>
#include <common/onion_decode.h>
#include <common/onion_encode.h>
#include <common/sphinx.h>
#include <common/version.h>
#include <err.h>

/* We don't actually use this, but common/onion needs it */
void ecdh(const struct pubkey *point, struct secret *ss)
{
	abort();
}

static void do_generate(int argc, char **argv,
			const u8 *assocdata,
			const struct node_id *rvnode_id)
{
	const tal_t *ctx = talz(NULL, tal_t);
	int num_hops = argc - 2;
	struct pubkey *path = tal_arr(ctx, struct pubkey, num_hops);
	u8 rawprivkey[PRIVKEY_LEN];
	struct secret session_key;
	struct secret *shared_secrets;
	struct sphinx_path *sp;
	struct sphinx_compressed_onion *comp;
	u8 *serialized;
	struct onionpacket *packet;

	memset(&session_key, 'A', sizeof(struct secret));

	sp = sphinx_path_new_with_key(ctx, assocdata, &session_key);
	sphinx_path_set_rendezvous(sp, rvnode_id);

	for (int i = 0; i < num_hops; i++) {
		size_t klen = strcspn(argv[2 + i], "/");
		if (hex_data_size(klen) == PRIVKEY_LEN) {
			if (!hex_decode(argv[2 + i], klen, rawprivkey, PRIVKEY_LEN))
				errx(1, "Invalid private key hex '%s'",
				     argv[2 + i]);

			if (secp256k1_ec_pubkey_create(secp256k1_ctx,
						       &path[i].pubkey,
						       rawprivkey) != 1)
				errx(1, "Could not decode pubkey");
		} else if (hex_data_size(klen) == PUBKEY_CMPR_LEN) {
			if (!pubkey_from_hexstr(argv[2 + i], klen, &path[i]))
				errx(1, "Invalid public key hex '%s'",
				     argv[2 + i]);
		} else {
			errx(1,
			     "Provided key is neither a pubkey nor a privkey: "
			     "%s\n",
			     argv[2 + i]);
		}

		/* /<hex> -> raw hopdata. /tlv -> TLV encoding. */
		if (argv[2 + i][klen] != '\0' && argv[2 + i][klen] != 't') {
			const char *hopstr = argv[2 + i] + klen + 1;
			u8 *data = tal_hexdata(ctx, hopstr, strlen(hopstr));

			if (!data)
				errx(1, "bad hex after / in %s", argv[1 + i]);
			sphinx_add_hop_has_length(sp, &path[i], data);
		} else {
			struct short_channel_id scid;
			struct amount_msat amt;

			/* FIXME: support secret and and total_msat */
			memset(&scid, i, sizeof(scid));
			amt = amount_msat(i);
			if (i == num_hops - 1)
				sphinx_add_hop_has_length(sp, &path[i],
					       take(onion_final_hop(NULL,
								    amt, i, amt,
								    NULL, NULL)));
			else
				sphinx_add_hop_has_length(sp, &path[i],
					       take(onion_nonfinal_hop(NULL,
								       &scid,
								       amt, i)));
		}
	}

	packet = create_onionpacket(ctx, sp, ROUTING_INFO_SIZE, &shared_secrets);

	if (rvnode_id != NULL) {
		comp = sphinx_compress(ctx, packet, sp);
		serialized = sphinx_compressed_onion_serialize(ctx, comp);
		printf("Rendezvous onion: %s\n", tal_hex(ctx, serialized));
	} else {
		assert(sphinx_compress(ctx, packet, sp) == NULL);
	}

	serialized = serialize_onionpacket(ctx, packet);
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
	enum onion_wire why_bad;
	struct secret shared_secret;
	if (!hex_decode(hexprivkey, strlen(hexprivkey), &seckey, sizeof(seckey)))
		errx(1, "Invalid private key hex '%s'", hexprivkey);

	packet = parse_onionpacket(tmpctx, onion, tal_bytelen(onion), &why_bad);

	if (!packet)
		errx(1, "Error parsing message: %s", onion_wire_name(why_bad));

	if (!onion_shared_secret(&shared_secret, packet, &seckey))
		errx(1, "Error creating shared secret.");

	step = process_onionpacket(ctx, packet, &shared_secret, assocdata,
				   tal_bytelen(assocdata), true);
	return step;

}

static void do_decode(int argc, char **argv, const u8 *assocdata)
{
	const tal_t *ctx = talz(NULL, tal_t);
	u8 *serialized;
	struct route_step *step;

	if (argc != 4)
		opt_usage_exit_fail("Expect an filename and privkey with 'decode' method");

	/* "-" means stdin, which is NULL for grab_file */
	char *hextemp = grab_file(ctx, streq(argv[2], "-") ? NULL : argv[2]);
	size_t hexlen = strlen(hextemp);

	// trim trailing whitespace
	while (isspace(hextemp[hexlen-1]))
		hexlen--;

	serialized = tal_hexdata(hextemp, hextemp, hexlen);
	if (!serialized) {
		errx(1, "Invalid onion hex '%s'", hextemp);
	}

	step = decode_with_privkey(ctx, serialized, tal_strdup(ctx, argv[3]), assocdata);

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

static char *opt_set_ad(const char *arg, u8 **assocdata)
{
	*assocdata = tal_hexdata(NULL, arg, strlen(arg));
	if (!*assocdata)
		return "Bad hex string";
	return NULL;
}

static bool opt_show_ad(char *buf, size_t len, u8 *const *assocdata)
{
	return hex_encode(*assocdata, tal_bytelen(*assocdata), buf, len);
}

static char *opt_set_node_id(const char *arg, struct node_id *node_id)
{
	node_id_from_hexstr(arg, strlen(arg), node_id);
	return NULL;
}

/**
 * Run an onion encoding/decoding unit-test from a file
 */
static void runtest(const char *filename)
{
	const tal_t *ctx = tal(NULL, u8);
	char *buffer = grab_file(ctx, filename);
	const jsmntok_t *toks, *session_key_tok, *associated_data_tok, *gentok,
		*hopstok, *hop, *payloadtok, *pubkeytok, *typetok, *oniontok, *decodetok;
	const u8 *associated_data, *session_key_raw, *payload, *serialized, *onion;
	struct secret session_key, *shared_secrets;
	struct pubkey pubkey;
	struct sphinx_path *path;
	size_t i;
	struct onionpacket *res;
	struct route_step *step;
	char *hexprivkey;

	toks = json_parse_simple(ctx, buffer, strlen(buffer));
	if (!toks)
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
		assert(json_tok_streq(buffer, typetok, "tlv"));
		sphinx_add_hop(path, &pubkey, take(payload));
	}
	res = create_onionpacket(ctx, path, ROUTING_INFO_SIZE, &shared_secrets);
	serialized = serialize_onionpacket(ctx, res);

	if (!serialized)
		errx(1, "Error serializing message.");

	oniontok = json_get_member(buffer, toks, "onion");

	if (oniontok) {
		onion = json_tok_bin_from_hex(ctx, buffer, oniontok);
		if (!tal_arr_eq(onion, serialized))
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
		printf("  Payload: %s\n", tal_hex(ctx, step->raw_payload));
		printf("  Next onion: %s\n", tal_hex(ctx, serialized));
		printf("  Next HMAC: %s\n",
		       tal_hexstr(ctx, step->next->hmac.bytes,
				  crypto_auth_hmacsha256_BYTES));
	}

	tal_free(ctx);
}

static void decompress(char *hexprivkey, char *hexonion)
{
	struct privkey rendezvous_key;
	size_t onionlen = hex_data_size(strlen(hexonion));
	u8 *compressed;
	struct pubkey ephkey;
	struct secret shared_secret;
	struct onionpacket *onion;
	struct sphinx_compressed_onion *tinyonion;

	if (!hex_decode(hexprivkey, strlen(hexprivkey), &rendezvous_key, sizeof(rendezvous_key)))
		errx(1, "Invalid private key hex '%s'", hexprivkey);

	compressed = tal_arr(NULL, u8, onionlen);
	if (!hex_decode(hexonion, strlen(hexonion), compressed, onionlen))
		errx(1, "Invalid onion hex '%s'", hexonion);

	if (onionlen < HMAC_SIZE + 1 + PUBKEY_SIZE)
		errx(1, "Onion is too short to contain the version, ephemeral key and HMAC");

	pubkey_from_der(compressed + 1, PUBKEY_SIZE, &ephkey);

	tinyonion = sphinx_compressed_onion_deserialize(NULL, compressed);
	if (tinyonion == NULL)
		errx(1, "Could not deserialize compressed onion");

	if (!sphinx_create_shared_secret(&shared_secret,
					 &tinyonion->ephemeralkey,
					 &rendezvous_key.secret))
		errx(1,
		     "Could not generate shared secret from ephemeral key %s "
		     "and private key %s",
		     fmt_pubkey(NULL, &ephkey), hexprivkey);

	onion = sphinx_decompress(NULL, tinyonion, &shared_secret);
	if (onion == NULL)
		errx(1, "Could not decompress compressed onion");

	printf("Decompressed Onion: %s\n", tal_hex(NULL, serialize_onionpacket(NULL, onion)));
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
	u8 *assocdata = NULL;
	struct node_id rendezvous_id;
	memset(&rendezvous_id, 0, sizeof(struct node_id));

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
						 SECP256K1_CONTEXT_SIGN);

	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);
	opt_register_arg("--assoc-data", opt_set_ad, opt_show_ad, &assocdata,
			 "Associated data (usu. payment_hash of payment)");
	opt_register_arg("--rendezvous-id", opt_set_node_id, NULL,
			 &rendezvous_id, "Node ID of the rendez-vous node");
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "\n\n\tdecode <onion_file> <privkey>\n"
			   "\tgenerate <pubkey1> <pubkey2> ...\n"
			   "\tgenerate <pubkey1>[/hopdata|/tlv] <pubkey2>[/hopdata|/tlv]\n"
			   "\tgenerate <privkey1>[/hopdata|/tlv] <privkey2>[/hopdata|/tlv]\n"
			   "\truntest <test-filename>\n\n", "Show this message\n\n"
			   "\texample:\n"
			   "\t> onion generate 02c18e7ff9a319983e85094b8c957da5c1230ecb328c1f1c7e88029f1fec2046f8/00000000000000000000000000000f424000000138000000000000000000000000 --assoc-data 44ee26f01e54665937b892f6afbfdfb88df74bcca52d563f088668cf4490aacd > onion.dat\n"
			   "\t> onion decode onion.dat 78302c8edb1b94e662464e99af721054b6ab9d577d3189f933abde57709c5cb8 --assoc-data 44ee26f01e54665937b892f6afbfdfb88df74bcca52d563f088668cf4490aacd\n");
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
		if (memeqzero(&rendezvous_id, sizeof(rendezvous_id)))
			do_generate(argc, argv, assocdata, NULL);
		else
			do_generate(argc, argv, assocdata, &rendezvous_id);
	} else if (streq(method, "decompress")) {
		if (argc != 4) {
			errx(2,
			     "'%s decompress' requires a private key and a "
			     "compressed onion",
			     argv[0]);
		}

		decompress(argv[2], argv[3]);
	} else if (streq(method, "decode")) {
		do_decode(argc, argv, assocdata);
	} else {
		errx(1, "Unrecognized method '%s'", method);
	}
	return 0;
}
