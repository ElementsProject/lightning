#ifndef LIGHTNING_COMMON_ONION_ENCODE_H
#define LIGHTNING_COMMON_ONION_ENCODE_H
#include "config.h"
#include <bitcoin/privkey.h>
#include <common/amount.h>

struct route_step;
struct tlv_encrypted_data_tlv_payment_relay;

enum onion_payload_type {
	ONION_V0_PAYLOAD = 0,
	ONION_TLV_PAYLOAD = 1,
};

struct onion_payload {
	enum onion_payload_type type;
	/* Is this the final hop? */
	bool final;

	struct amount_msat amt_to_forward;
	u32 outgoing_cltv;
	struct amount_msat *total_msat;

	/* One of these is set */
	struct short_channel_id *forward_channel;
	struct pubkey *forward_node_id;

	struct secret *payment_secret;
	u8 *payment_metadata;

	/* If path_key is set, blinding_ss is the shared secret.*/
	struct pubkey *path_key;
	struct secret blinding_ss;

	/* The raw TLVs contained in the payload. */
	struct tlv_payload *tlv;
};

u8 *onion_nonfinal_hop(const tal_t *ctx,
		       const struct short_channel_id *scid,
		       struct amount_msat forward,
		       u32 outgoing_cltv);

/* Note that this can fail if we supply payment_secret or payment_metadata and !use_tlv! */
u8 *onion_final_hop(const tal_t *ctx,
		    struct amount_msat forward,
		    u32 outgoing_cltv,
		    struct amount_msat total_msat,
		    const struct secret *payment_secret,
		    const u8 *payment_metadata);

/* Blinding has more complex rules on what fields are encoded: this is the
 * generic interface, as used by blindedpay.h */
u8 *onion_blinded_hop(const tal_t *ctx,
		      const struct amount_msat *amt_to_forward,
		      const struct amount_msat *total_amount_msat,
		      const u32 *outgoing_cltv_value,
		      const u8 *enctlv,
		      const struct pubkey *blinding)
	NON_NULL_ARGS(5);
#endif /* LIGHTNING_COMMON_ONION_ENCODE_H */
