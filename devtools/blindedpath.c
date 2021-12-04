#include "config.h"
#include <assert.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>
#include <common/blinding.h>
#include <common/ecdh.h>
#include <common/setup.h>
#include <common/sphinx.h>
#include <common/type_to_string.h>
#include <common/version.h>
#include <secp256k1_ecdh.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <stdio.h>

static bool simpleout = false;

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

/* We don't actually use this, but common/onion needs it */
void ecdh(const struct pubkey *point, struct secret *ss)
{
	abort();
}

int main(int argc, char **argv)
{
	bool first = false;

	common_setup(argv[0]);

	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "\n\n\tcreate <nodeid>[/<scid>]...\n"
			   "\tunwrap <privkey> <onion> <blinding>\n",
			   "Show this message");
	opt_register_noarg("--first-node", opt_set_bool, &first,
			   "Don't try to tweak key to unwrap onion");
	opt_register_noarg("--simple-output", opt_set_bool, &simpleout,
			   "Output values without prefixes, one per line");
	opt_register_version();

	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc < 2)
		errx(1, "You must specify create or unwrap");
	if (streq(argv[1], "create")) {
		struct privkey e;
		struct pubkey *pk_e, *b, *nodes;
		struct short_channel_id **scids;
		struct secret *rho;
		size_t num = argc - 2;

		if (argc < 3)
			errx(1, "create requires at least one nodeid");

		/* P(i) */
		nodes = tal_arr(tmpctx, struct pubkey, num);
		/* E(i) */
		pk_e = tal_arr(tmpctx, struct pubkey, num);
		/* B(i) */
		b = tal_arr(tmpctx, struct pubkey, num);
		/* rho(i) */
		rho = tal_arr(tmpctx, struct secret, num);

		scids = tal_arr(tmpctx, struct short_channel_id *, num);
		/* Randomness, chosen with a fair dice roll! */
		memset(&e, 6, sizeof(e));
		if (!pubkey_from_privkey(&e, &pk_e[0]))
			abort();

		for (size_t i = 0; i < num; i++) {
			struct secret ss;
			struct secret hmac;
			struct sha256 h;
			const char *slash;

			if (!pubkey_from_hexstr(argv[2+i],
						strcspn(argv[2+i], "/"),
						&nodes[i]))
				errx(1, "%s not a valid pubkey", argv[2+i]);

			slash = strchr(argv[2+i], '/');
			if (slash) {
				scids[i] = tal(scids, struct short_channel_id);
				if (!short_channel_id_from_str(slash+1,
							       strlen(slash+1),
							       scids[i]))
					errx(1, "%s is not a valid scids",
					     slash + 1);
			} else
				scids[i] = NULL;
			if (secp256k1_ecdh(secp256k1_ctx, ss.data,
					   &nodes[i].pubkey, e.secret.data, NULL, NULL) != 1)
				abort();

			subkey_from_hmac("blinded_node_id", &ss, &hmac);
			b[i] = nodes[i];
			if (i != 0) {
				if (secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx,
					  &b[i].pubkey, hmac.data) != 1)
					abort();
			}
			subkey_from_hmac("rho", &ss, &rho[i]);
			blinding_hash_e_and_ss(&pk_e[i], &ss, &h);
			if (i != num-1)
				blinding_next_pubkey(&pk_e[i], &h,
						     &pk_e[i+1]);
			blinding_next_privkey(&e, &h, &e);
		}

		/* Print initial blinding factor */
		if (simpleout)
			printf("%s\n",
			       type_to_string(tmpctx, struct pubkey, &pk_e[0]));
		else
			printf("Blinding: %s\n",
			       type_to_string(tmpctx, struct pubkey, &pk_e[0]));

		for (size_t i = 0; i < num - 1; i++) {
			u8 *p;
			u8 buf[BIGSIZE_MAX_LEN];
			const unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			struct tlv_obs2_onionmsg_payload *outer;
			struct tlv_obs2_encmsg_tlvs *inner;
			int ret;

			/* Inner is encrypted */
			inner = tlv_obs2_encmsg_tlvs_new(tmpctx);
			inner->next_node_id = tal_dup(inner, struct pubkey, &nodes[i+1]);
			p = tal_arr(tmpctx, u8, 0);
			towire_obs2_encmsg_tlvs(&p, inner);

			outer = tlv_obs2_onionmsg_payload_new(tmpctx);
			outer->enctlv = tal_arr(outer, u8, tal_count(p)
				      + crypto_aead_chacha20poly1305_ietf_ABYTES);
			ret = crypto_aead_chacha20poly1305_ietf_encrypt(outer->enctlv, NULL,
									p,
									tal_bytelen(p),
									NULL, 0,
									NULL, npub,
									rho[i].data);
			assert(ret == 0);

			p = tal_arr(tmpctx, u8, 0);
			towire_obs2_onionmsg_payload(&p, outer);
			ret = bigsize_put(buf, tal_bytelen(p));

			if (simpleout) {
				printf("%s\n%s\n",
				       type_to_string(tmpctx, struct pubkey,
						      &b[i]),
				       tal_hex(tmpctx, outer->enctlv));
			} else {
				/* devtools/onion wants length explicitly prepended */
				printf("%s/%.*s%s ",
				       type_to_string(tmpctx, struct pubkey,
						      &b[i]),
				       ret * 2,
				       tal_hexstr(tmpctx, buf, ret),
				       tal_hex(tmpctx, p));
			}
		}
		/* No payload for last node */
		if (simpleout)
			printf("%s\n",
			       type_to_string(tmpctx, struct pubkey, &b[num-1]));
		else
			printf("%s/00\n",
			       type_to_string(tmpctx, struct pubkey, &b[num-1]));
	} else if (streq(argv[1], "unwrap")) {
		struct privkey privkey;
		struct pubkey blinding;
		u8 onion[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)], *dec;
		struct onionpacket *op;
		struct secret ss, onion_ss;
		struct secret hmac, rho;
		struct route_step *rs;
		const u8 *cursor;
		struct tlv_obs2_onionmsg_payload *outer;
		size_t max, len;
		struct pubkey res;
		struct sha256 h;
		int ret;
		enum onion_wire failcode;
		const unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

		if (argc != 5)
			errx(1, "unwrap requires privkey, onion and blinding");

		if (!hex_decode(argv[2], strlen(argv[2]), &privkey,
				sizeof(privkey)))
			errx(1, "Invalid private key hex '%s'", argv[2]);

		if (!hex_decode(argv[3], strlen(argv[3]), onion,
				sizeof(onion)))
			errx(1, "Invalid onion %s", argv[3]);

		if (!pubkey_from_hexstr(argv[4], strlen(argv[4]), &blinding))
			errx(1, "Invalid blinding %s", argv[4]);

		op = parse_onionpacket(tmpctx, onion, sizeof(onion), &failcode);
		if (!op)
			errx(1, "Unparsable onion");

		/*   ss(r) = H(k(r) * E(r)) */
		if (secp256k1_ecdh(secp256k1_ctx, ss.data, &blinding.pubkey,
				   privkey.secret.data, NULL, NULL) != 1)
			abort();

		subkey_from_hmac("rho", &ss, &rho);

		/* b(i) = HMAC256("blinded_node_id", ss(i)) * k(i) */
		subkey_from_hmac("blinded_node_id", &ss, &hmac);

		/* We instead tweak the *ephemeral* key from the onion
		 * and use our raw privkey: this models how lightningd
		 * will do it, since hsmd knows only how to ECDH with
		 * our real key */
		res = op->ephemeralkey;
		if (!first) {
			if (secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx,
							  &res.pubkey,
							  hmac.data) != 1)
				abort();
		}

		if (secp256k1_ecdh(secp256k1_ctx, onion_ss.data,
				   &res.pubkey,
				   privkey.secret.data, NULL, NULL) != 1)
			abort();

		rs = process_onionpacket(tmpctx, op, &onion_ss, NULL, 0, false);
		if (!rs)
			errx(1, "Could not process onionpacket");

		cursor = rs->raw_payload;
		max = tal_bytelen(cursor);
		len = fromwire_bigsize(&cursor, &max);

		/* Always true since we're non-legacy */
		assert(len == max);
		outer = tlv_obs2_onionmsg_payload_new(tmpctx);
		if (!fromwire_obs2_onionmsg_payload(&cursor, &max, outer))
			errx(1, "Invalid payload %s",
			     tal_hex(tmpctx, rs->raw_payload));

		if (rs->nextcase == ONION_END) {
			printf("TERMINAL\n");
			return 0;
		}

		/* Look for enctlv */
		if (!outer->enctlv)
			errx(1, "No encrypted_recipient_data field");

		if (tal_bytelen(outer->enctlv)
		    < crypto_aead_chacha20poly1305_ietf_ABYTES)
			errx(1, "encrypted_recipient_data field too short");

		dec = tal_arr(tmpctx, u8,
			      tal_bytelen(outer->enctlv)
			      - crypto_aead_chacha20poly1305_ietf_ABYTES);
		ret = crypto_aead_chacha20poly1305_ietf_decrypt(dec, NULL,
								NULL,
								outer->enctlv,
								tal_bytelen(outer->enctlv),
								NULL, 0,
								npub,
								rho.data);
		if (ret != 0)
			errx(1, "Failed to decrypt encrypted_recipient_data field");

		printf("Contents: %s\n", tal_hex(tmpctx, dec));

		/* E(i-1) = H(E(i) || ss(i)) * E(i) */
		blinding_hash_e_and_ss(&blinding, &ss, &h);
		blinding_next_pubkey(&blinding, &h, &res);
		printf("Next blinding: %s\n",
		       type_to_string(tmpctx, struct pubkey, &res));
		printf("Next onion: %s\n", tal_hex(tmpctx, serialize_onionpacket(tmpctx, rs->next)));
	} else
		errx(1, "Either create or unwrap!");

	common_shutdown();
}
