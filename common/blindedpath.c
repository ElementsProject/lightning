#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <ccan/cast/cast.h>
#include <common/blindedpath.h>
#include <common/blinding.h>
#include <common/bolt11.h>
#include <common/hmac.h>
#include <common/node_id.h>
#include <common/utils.h>
#include <secp256k1_ecdh.h>
#include <sodium.h>
#include <wire/onion_wire.h>

/* FIXME: Pad with dummy nodes, but make sure to check them on recv! */
struct onionmsg_path **make_blindedpath(const tal_t *ctx,
					const struct pubkey *route,
					struct pubkey *initial_blinding,
					struct pubkey *final_blinding)
{
	struct privkey e;
	struct pubkey *pk_e, *b;
	struct secret *rho;
	struct onionmsg_path **path;
	size_t num = tal_count(route);

	if (!num)
		abort();

	/* E(i) */
	pk_e = tal_arr(tmpctx, struct pubkey, num);
	/* B(i) */
	b = tal_arr(tmpctx, struct pubkey, num);
	/* rho(i) */
	rho = tal_arr(tmpctx, struct secret, num);

	randombytes_buf(&e, sizeof(e));
	if (!pubkey_from_privkey(&e, &pk_e[0]))
		abort();

	for (size_t i = 0; i < num; i++) {
		struct secret ss;
		struct secret hmac;
		struct sha256 h;

		if (secp256k1_ecdh(secp256k1_ctx, ss.data,
				   &route[i].pubkey, e.secret.data,
				   NULL, NULL) != 1)
				abort();

		subkey_from_hmac("blinded_node_id", &ss, &hmac);
		b[i] = route[i];
		if (i != 0) {
			if (secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx,
					  &b[i].pubkey, hmac.data) != 1)
				abort();
		}
		subkey_from_hmac("rho", &ss, &rho[i]);
		blinding_hash_e_and_ss(&pk_e[i], &ss, &h);
		if (i != num-1)
			blinding_next_pubkey(&pk_e[i], &h, &pk_e[i+1]);
		blinding_next_privkey(&e, &h, &e);
	}

	*initial_blinding = pk_e[0];
	*final_blinding = pk_e[num-1];

	path = tal_arr(ctx, struct onionmsg_path *, num);
	for (size_t i = 0; i < num; i++) {
		path[i] = tal(path, struct onionmsg_path);
		path[i]->node_id = b[i];
	}

	for (size_t i = 0; i < num - 1; i++) {
		const unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		struct tlv_onionmsg_payload *inner;
		int ret;

		/* Inner is encrypted */
		inner = tlv_onionmsg_payload_new(tmpctx);
		/* FIXME: We could support scids, too */
		inner->next_node_id = cast_const(struct pubkey *, &route[i+1]);

		path[i]->enctlv = tal_arr(path, u8, 0);
		towire_encmsg_tlvs(&path[i]->enctlv, inner);
		towire_pad(&path[i]->enctlv,
			   crypto_aead_chacha20poly1305_ietf_ABYTES);

		ret = crypto_aead_chacha20poly1305_ietf_encrypt(path[i]->enctlv, NULL,
								path[i]->enctlv,
								tal_bytelen(path[i]->enctlv) - crypto_aead_chacha20poly1305_ietf_ABYTES,
								NULL, 0,
								NULL, npub,
								rho[i].data);
		assert(ret == 0);
	}

	/* Final one has no enctlv */
	path[num-1]->enctlv = NULL;

	return path;
}
