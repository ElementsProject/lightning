#include <lightningd/htlc_wire.h>
#include <wire/wire.h>

/* FIXME: We could adapt tools/generate-wire.py to generate structures
 * and code like this. */
void towire_added_htlc(u8 **pptr, const struct added_htlc *added)
{
	towire_u64(pptr, added->id);
	towire_u64(pptr, added->amount_msat);
 	towire_sha256(pptr, &added->payment_hash);
	towire_u32(pptr, added->cltv_expiry);
	towire(pptr, added->onion_routing_packet,
	       sizeof(added->onion_routing_packet));
}

void towire_fulfilled_htlc(u8 **pptr, const struct fulfilled_htlc *fulfilled)
{
	towire_u64(pptr, fulfilled->id);
	towire_preimage(pptr, &fulfilled->payment_preimage);
}

void towire_failed_htlc(u8 **pptr, const struct failed_htlc *failed)
{
	towire_u64(pptr, failed->id);
	towire_u16(pptr, failed->malformed);
	towire_u16(pptr, tal_count(failed->failreason));
	towire_u8_array(pptr, failed->failreason, tal_count(failed->failreason));
}

void towire_htlc_state(u8 **pptr, const enum htlc_state *hstate)
{
	towire_u8(pptr, *hstate);
}

void towire_changed_htlc(u8 **pptr, const struct changed_htlc *changed)
{
	towire_htlc_state(pptr, &changed->newstate);
	towire_u64(pptr, changed->id);
}

void towire_side(u8 **pptr, const enum side *side)
{
	towire_u8(pptr, *side);
}

void fromwire_added_htlc(const u8 **cursor, size_t *max,
			 struct added_htlc *added)
{
	added->id = fromwire_u64(cursor, max);
	added->amount_msat = fromwire_u64(cursor, max);
	fromwire_sha256(cursor, max, &added->payment_hash);
	added->cltv_expiry = fromwire_u32(cursor, max);
	fromwire(cursor, max, added->onion_routing_packet,
		 sizeof(added->onion_routing_packet));
}

void fromwire_fulfilled_htlc(const u8 **cursor, size_t *max,
			     struct fulfilled_htlc *fulfilled)
{
	fulfilled->id = fromwire_u64(cursor, max);
	fromwire_preimage(cursor, max, &fulfilled->payment_preimage);
}

void fromwire_failed_htlc(const tal_t *ctx, const u8 **cursor, size_t *max,
			  struct failed_htlc *failed)
{
	u16 failreason_len;

	failed->id = fromwire_u64(cursor, max);
	failed->malformed = fromwire_u16(cursor, max);
	failreason_len = fromwire_u16(cursor, max);
	failed->failreason = tal_arr(ctx, u8, failreason_len);
	fromwire_u8_array(cursor, max, failed->failreason, failreason_len);
}

void fromwire_htlc_state(const u8 **cursor, size_t *max,
			 enum htlc_state *hstate)
{
	*hstate = fromwire_u8(cursor, max);
	if (*hstate >= HTLC_STATE_INVALID) {
		*hstate = HTLC_STATE_INVALID;
		fromwire_fail(cursor, max);
	}
}

void fromwire_changed_htlc(const u8 **cursor, size_t *max,
			   struct changed_htlc *changed)
{
	fromwire_htlc_state(cursor, max, &changed->newstate);
	changed->id = fromwire_u64(cursor, max);
}

void fromwire_side(const u8 **cursor, size_t *max, enum side *side)
{
	*side = fromwire_u8(cursor, max);
	if (*side >= NUM_SIDES) {
		*side = NUM_SIDES;
		fromwire_fail(cursor, max);
	}
}
