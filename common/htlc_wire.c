#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/shachain/shachain.h>
#include <common/htlc_wire.h>
#include <common/memleak.h>
#include <common/onionreply.h>
#include <wire/wire.h>

/* FIXME: We could adapt tools/generate-wire.py to generate structures
 * and code like this. */
void towire_added_htlc(u8 **pptr, const struct added_htlc *added)
{
	towire_u64(pptr, added->id);
	towire_amount_msat(pptr, added->amount);
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
	/* Only one can be set. */
	if (failed->sha256_of_onion) {
		assert(!failed->onion);
		assert(failed->badonion & BADONION);
		towire_u16(pptr, failed->badonion);
		towire_sha256(pptr, failed->sha256_of_onion);
	} else {
		towire_u16(pptr, 0);
		towire_onionreply(pptr, failed->onion);
	}
}

void towire_htlc_state(u8 **pptr, const enum htlc_state hstate)
{
	towire_u8(pptr, hstate);
}

void towire_changed_htlc(u8 **pptr, const struct changed_htlc *changed)
{
	towire_htlc_state(pptr, changed->newstate);
	towire_u64(pptr, changed->id);
}

void towire_side(u8 **pptr, const enum side side)
{
	towire_u8(pptr, side);
}

void towire_shachain(u8 **pptr, const struct shachain *shachain)
{
	size_t i;

	towire_u64(pptr, shachain->min_index);
	towire_u32(pptr, shachain->num_valid);

	for (i = 0; i < shachain->num_valid; i++) {
		towire_u64(pptr, shachain->known[i].index);
		towire_sha256(pptr, &shachain->known[i].hash);
	}
}

void fromwire_added_htlc(const u8 **cursor, size_t *max,
			 struct added_htlc *added)
{
	added->id = fromwire_u64(cursor, max);
	added->amount = fromwire_amount_msat(cursor, max);
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

struct failed_htlc *fromwire_failed_htlc(const tal_t *ctx, const u8 **cursor, size_t *max)
{
	struct failed_htlc *failed = tal(ctx, struct failed_htlc);
	enum onion_type badonion;

	failed->id = fromwire_u64(cursor, max);
	badonion = fromwire_u16(cursor, max);
	if (badonion) {
		failed->onion = NULL;
		if (!(badonion & BADONION))
			return tal_free(failed);
		failed->badonion = badonion;
		failed->sha256_of_onion = tal(failed, struct sha256);
		fromwire_sha256(cursor, max, failed->sha256_of_onion);
	} else {
		failed->sha256_of_onion = NULL;
		failed->onion = fromwire_onionreply(failed, cursor, max);
	}

	return failed;
}

enum htlc_state fromwire_htlc_state(const u8 **cursor, size_t *max)
{
	enum htlc_state hstate = fromwire_u8(cursor, max);
	if (hstate >= HTLC_STATE_INVALID) {
		hstate = HTLC_STATE_INVALID;
		fromwire_fail(cursor, max);
	}
	return hstate;
}

void fromwire_changed_htlc(const u8 **cursor, size_t *max,
			   struct changed_htlc *changed)
{
	changed->newstate = fromwire_htlc_state(cursor, max);
	changed->id = fromwire_u64(cursor, max);
}

enum side fromwire_side(const u8 **cursor, size_t *max)
{
	enum side side = fromwire_u8(cursor, max);
	if (side >= NUM_SIDES) {
		side = NUM_SIDES;
		fromwire_fail(cursor, max);
	}
	return side;
}

void fromwire_shachain(const u8 **cursor, size_t *max,
		       struct shachain *shachain)
{
	size_t i;

	shachain->min_index = fromwire_u64(cursor, max);
	shachain->num_valid = fromwire_u32(cursor, max);
	if (shachain->num_valid > ARRAY_SIZE(shachain->known)) {
		fromwire_fail(cursor, max);
		return;
	}
	for (i = 0; i < shachain->num_valid; i++) {
		shachain->known[i].index = fromwire_u64(cursor, max);
		fromwire_sha256(cursor, max, &shachain->known[i].hash);
	}
}
