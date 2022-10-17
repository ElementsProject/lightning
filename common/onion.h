#ifndef LIGHTNING_COMMON_ONION_H
#define LIGHTNING_COMMON_ONION_H
#include "config.h"
#include <bitcoin/privkey.h>
#include <common/amount.h>

struct route_step;
struct tlv_encrypted_data_tlv_payment_relay;

struct onion_payload {
	struct amount_msat amt_to_forward;
	u32 outgoing_cltv;
	struct amount_msat *total_msat;
	struct short_channel_id *forward_channel;
	struct secret *payment_secret;
	u8 *payment_metadata;

	/* If blinding is set, blinding_ss is the shared secret.*/
	struct pubkey *blinding;
	struct secret blinding_ss;

	/* The raw TLVs contained in the payload. */
	struct tlv_tlv_payload *tlv;
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
		      const u32 *outgoing_cltv_value,
		      const u8 *enctlv,
		      const struct pubkey *blinding)
	NON_NULL_ARGS(4);

/**
 * onion_decode: decode payload from a decrypted onion.
 * @ctx: context to allocate onion_contents off.
 * @blinding_support: --experimental-route-blinding?
 * @rs: the route_step, whose raw_payload is of at least length
 *       onion_payload_length().
 * @blinding: the optional incoming blinding point.
 * @accepted_extra_tlvs: Allow these types to be in the TLV without failing
 * @amount_in: Incoming HTLC amount
 * @cltv_expiry: Incoming HTLC cltv_expiry
 * @failtlvtype: (out) the tlv type which failed to parse.
 * @failtlvpos: (out) the offset in the tlv which failed to parse.
 *
 * If the payload is not valid, returns NULL.
 */
struct onion_payload *onion_decode(const tal_t *ctx,
				   bool blinding_support,
				   const struct route_step *rs,
				   const struct pubkey *blinding,
				   const u64 *accepted_extra_tlvs,
				   struct amount_msat amount_in,
				   u32 cltv_expiry,
				   u64 *failtlvtype,
				   size_t *failtlvpos);
#endif /* LIGHTNING_COMMON_ONION_H */
