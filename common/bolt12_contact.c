#include "config.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/tal/tal.h>
#include <common/bolt12_contact.h>
#include <common/utils.h>
#include <wire/bolt12_wiregen.h>
#include <wire/onion_wiregen.h>

/* bLIP 42:
 * contact_secret = SHA256("blip42_contact_secret" || shared_key)
 * where shared_key = local_offer_privkey * remote_offer_node_id
 * serialized as a compressed pubkey (33 bytes).
 *
 * This matches the LDK reference implementation which uses
 * `offer_node_id.mul_tweak(&secp, &scalar)` then `.serialize()`.
 */
bool bolt12_contact_secret(const struct privkey *local_offer_privkey,
			   const struct pubkey *remote_offer_node_id,
			   struct sha256 *contact_secret)
{
	secp256k1_pubkey shared_point;
	u8 compressed[33];
	size_t compressed_len = sizeof(compressed);
	struct sha256_ctx sctx;
	static const char tag[] = "blip42_contact_secret";

	/* EC point multiplication: shared_point = privkey * pubkey */
	shared_point = remote_offer_node_id->pubkey;
	if (secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx, &shared_point,
					  local_offer_privkey->secret.data) != 1)
		return false;

	/* Serialize as compressed point (33 bytes) */
	secp256k1_ec_pubkey_serialize(secp256k1_ctx, compressed,
				      &compressed_len, &shared_point,
				      SECP256K1_EC_COMPRESSED);

	sha256_init(&sctx);
	sha256_update(&sctx, tag, strlen(tag));
	sha256_update(&sctx, compressed, compressed_len);
	sha256_done(&sctx, contact_secret);
	return true;
}

bool offer_contact_node_id(const struct tlv_offer *offer,
			   struct pubkey *node_id)
{
	/* bLIP 42:
	 * - offer_issuer_id if present, otherwise
	 * - the last blinded_node_id of the first blinded path.
	 */
	if (offer->offer_issuer_id) {
		*node_id = *offer->offer_issuer_id;
		return true;
	}

	if (offer->offer_paths && tal_count(offer->offer_paths) > 0) {
		struct blinded_path *first_path = offer->offer_paths[0];
		size_t num_hops = tal_count(first_path->path);
		if (num_hops > 0) {
			*node_id = first_path->path[num_hops - 1]->blinded_node_id;
			return true;
		}
	}
	return false;
}
