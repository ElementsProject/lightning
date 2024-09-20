#ifndef LIGHTNING_COMMON_ONION_DECODE_H
#define LIGHTNING_COMMON_ONION_DECODE_H
#include "config.h"
#include <bitcoin/privkey.h>
#include <common/amount.h>
#include <common/onion_encode.h>

/**
 * onion_decode: decode payload from a decrypted onion.
 * @ctx: context to allocate onion_contents off.
 * @rs: the route_step, whose raw_payload is of at least length
 *       onion_payload_length().
 * @path_key: the optional incoming path_key point.
 * @accepted_extra_tlvs: Allow these types to be in the TLV without failing
 * @amount_in: Incoming HTLC amount
 * @cltv_expiry: Incoming HTLC cltv_expiry
 * @failtlvtype: (out) the tlv type which failed to parse.
 * @failtlvpos: (out) the offset in the tlv which failed to parse.
 *
 * If the payload is not valid, returns NULL.
 */
struct onion_payload *onion_decode(const tal_t *ctx,
				   const struct route_step *rs,
				   const struct pubkey *path_key,
				   const u64 *accepted_extra_tlvs,
				   struct amount_msat amount_in,
				   u32 cltv_expiry,
				   u64 *failtlvtype,
				   size_t *failtlvpos);
#endif /* LIGHTNING_COMMON_ONION_DECODE_H */
