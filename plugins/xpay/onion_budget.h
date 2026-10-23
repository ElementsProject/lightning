#ifndef LIGHTNING_PLUGINS_XPAY_ONION_BUDGET_H
#define LIGHTNING_PLUGINS_XPAY_ONION_BUDGET_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <common/amount.h>
#include <common/onion_encode.h>
#include <common/sphinx.h>
#include <common/utils.h>

struct blinded_path;
struct secret;
struct short_channel_id;

/* Payload for a forwarding node. */
static inline u8 *onion_forward_payload(const tal_t *ctx,
					const struct short_channel_id *scid,
					struct amount_msat amount_out,
					u32 outgoing_cltv)
{
	return onion_nonfinal_hop(ctx, scid, amount_out, outgoing_cltv);
}

/* Payload for the final node. */
u8 *onion_final_payload(const tal_t *ctx,
			struct amount_msat deliver,
			u32 final_cltv,
			struct amount_msat total_msat,
			const struct secret *payment_secret,
			const u8 *payment_metadata,
			const u8 *extra_tlvs);

/* Payload for the i-th node in a blinded path. */
u8 *onion_blinded_payload(const tal_t *ctx,
			  const struct blinded_path *path,
			  size_t i,
			  const struct amount_msat *deliver,
			  const struct amount_msat *total_msat,
			  const u32 *final_cltv);

/* Bytes (payload + HMAC) a forwarding hop takes.  The encoding of amounts
 * and cltvs is truncated, so it never shrinks as the values grow: pass
 * upper bounds to get a worst case. */
size_t onion_forward_hop_size(struct amount_msat amount_out, u32 outgoing_cltv);

/* Bytes (payloads + HMACs) of the tail. */
size_t onion_final_hop_size(struct amount_msat deliver,
			    u32 final_cltv,
			    struct amount_msat total_msat,
			    const struct secret *payment_secret,
			    const u8 *payment_metadata,
			    const u8 *extra_tlvs);

/* Bytes (payloads + HMACs) of the tail. */
size_t onion_blinded_tail_size(const struct blinded_path *path,
			       struct amount_msat deliver,
			       struct amount_msat total_msat,
			       u32 final_cltv);

/* How many forwarding hops we can afford to encode in a payment onion packet.
 * This number depends slightly on the payment amount blockheight, but mostly on
 * the contents of the tail, either a final node (bolt11) or a blinded path
 * (bolt12).  xpay uses injectpaymentonion primitive therefore down the line
 * this means usually that the sender is included.
 *
 * eg. for n=3:
 * (sender) -> (node 1) -> (node 2) -> (final node)
 * or
 * (sender) -> (node 1) -> (node 2) -> (first node in blinded path) -> ...
 *
 * eg. for n=0
 * (sender = final node) // we could pay ourselves using injectpaymentonion
 * or
 * (sender = first node in blinded path) -> ...
 *
 * errors:
 * If the tail packet is too big to fit ROUTING_INFO_SIZE this returns
 * UINT32_MAX.
 * */
u32 onion_budget(struct amount_msat amount,
		 struct amount_msat maxfee,
		 u32 blockheight,
		 u32 maxdelay,
		 const struct blinded_path *blinded_path,
		 const struct secret *payment_secret,
		 const u8 *payment_metadata,
		 const u8 *extra_tlvs,
		 size_t *tail_size);

/* Exactly what sphinx_hop_size() counts for each hop. */
static inline size_t onion_hop_size(const u8 *payload TAKES)
{
	size_t len = tal_bytelen(payload) + HMAC_SIZE;
	tal_free_if_taken(payload);
	return len;
}

#endif /* LIGHTNING_PLUGINS_XPAY_ONION_BUDGET_H */
