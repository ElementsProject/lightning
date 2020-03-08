#ifndef LIGHTNING_COMMON_ONION_H
#define LIGHTNING_COMMON_ONION_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <common/amount.h>

struct route_step;

enum onion_payload_type {
	ONION_V0_PAYLOAD = 0,
	ONION_TLV_PAYLOAD = 1,
};

struct onion_payload {
	enum onion_payload_type type;

	struct amount_msat amt_to_forward;
	u32 outgoing_cltv;
	struct amount_msat *total_msat;
	struct short_channel_id *forward_channel;
	struct secret *payment_secret;
};

u8 *onion_nonfinal_hop(const tal_t *ctx,
		       bool use_tlv,
		       const struct short_channel_id *scid,
		       struct amount_msat forward,
		       u32 outgoing_cltv);

/* Note that this can fail if we supply payment_secret and !use_tlv! */
u8 *onion_final_hop(const tal_t *ctx,
		    bool use_tlv,
		    struct amount_msat forward,
		    u32 outgoing_cltv,
		    struct amount_msat total_msat,
		    const struct secret *payment_secret);

/**
 * onion_payload_length: measure payload length in decrypted onion.
 * @raw_payload: payload to look at.
 * @len: length of @raw_payload in bytes.
 * @valid: set to true if it is valid, false otherwise.
 * @type: if non-NULL, set to type of payload if *@valid is true.
 *
 * If @valid is set, there is room for the HMAC immediately following,
 * as the return value is <= ROUTING_INFO_SIZE - HMAC_SIZE.  Otherwise,
 * the return value is @len (i.e. the entire payload).
 */
size_t onion_payload_length(const u8 *raw_payload, size_t len,
			    bool *valid,
			    enum onion_payload_type *type);

/**
 * onion_decode: decode payload from a decrypted onion.
 * @ctx: context to allocate onion_contents off.
 * @rs: the route_step, whose raw_payload is of at least length
 *       onion_payload_length().
 *
 * If the payload is not valid, returns NULL.
 */
struct onion_payload *onion_decode(const tal_t *ctx,
				   const struct route_step *rs,
				   u64 *failtlvtype,
				   size_t *failtlvpos);

#endif /* LIGHTNING_COMMON_ONION_H */
