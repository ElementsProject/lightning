#ifndef LIGHTNING_COMMON_BOLT12_CONTACT_H
#define LIGHTNING_COMMON_BOLT12_CONTACT_H
#include "config.h"
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <ccan/crypto/sha256/sha256.h>

/**
 * bolt12_contact_secret - Derive the bLIP-42 contact_secret for a pair of offers.
 * @local_offer_privkey: our offer's private key (offer_issuer_id privkey,
 *                       or last blinded path privkey).
 * @remote_offer_node_id: the remote offer's public key (offer_issuer_id,
 *                        or last blinded_node_id of first path).
 * @contact_secret: (out) the derived 32-byte contact secret.
 *
 * Computes:
 *   shared_key = ECDH(local_offer_privkey, remote_offer_node_id)
 *   contact_secret = SHA256("blip42_contact_secret" || shared_key)
 *
 * Returns false on ECDH failure.
 */
bool bolt12_contact_secret(const struct privkey *local_offer_privkey,
			   const struct pubkey *remote_offer_node_id,
			   struct sha256 *contact_secret);

/**
 * offer_node_id - Extract the node_id to use for contact derivation from an offer.
 * @offer: the decoded offer TLV.
 * @node_id: (out) the extracted public key.
 *
 * Per bLIP 42, this is:
 *   - offer_issuer_id if present, otherwise
 *   - the last blinded_node_id of the first blinded path.
 *
 * Returns false if neither is available.
 */
struct tlv_offer;
bool offer_contact_node_id(const struct tlv_offer *offer,
			   struct pubkey *node_id);

#endif /* LIGHTNING_COMMON_BOLT12_CONTACT_H */
