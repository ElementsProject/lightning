#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/crypto/shachain/shachain.h>
#include <common/htlc_wire.h>
#include <common/memleak.h>
#include <common/onionreply.h>
#include <wire/wire.h>

struct failed_htlc *failed_htlc_dup(const tal_t *ctx,
				    const struct failed_htlc *f TAKES)
{
	struct failed_htlc *newf;

	if (taken(f))
		return cast_const(struct failed_htlc *, tal_steal(ctx, f));
	newf = tal(ctx, struct failed_htlc);
	newf->id = f->id;
	if (f->sha256_of_onion)
		newf->sha256_of_onion = tal_dup(newf, struct sha256, f->sha256_of_onion);
	else
		newf->sha256_of_onion = NULL;
	newf->badonion = f->badonion;
	if (f->onion)
		newf->onion = dup_onionreply(newf, f->onion);
	else
		newf->onion = NULL;
	return newf;
}

struct existing_htlc *new_existing_htlc(const tal_t *ctx,
					u64 id,
					enum htlc_state state,
					struct amount_msat amount,
					const struct sha256 *payment_hash,
					u32 cltv_expiry,
					const u8 onion_routing_packet[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)],
					const struct pubkey *blinding TAKES,
					const struct preimage *preimage TAKES,
					const struct failed_htlc *failed TAKES)
{
	struct existing_htlc *existing = tal(ctx, struct existing_htlc);

	existing->id = id;
	existing->state = state;
	existing->amount = amount;
	existing->cltv_expiry = cltv_expiry;
	existing->payment_hash = *payment_hash;
	memcpy(existing->onion_routing_packet, onion_routing_packet,
	       sizeof(existing->onion_routing_packet));
	if (blinding)
		existing->blinding = tal_dup(existing, struct pubkey, blinding);
	else
		existing->blinding = NULL;
	if (preimage)
		existing->payment_preimage
			= tal_dup(existing, struct preimage, preimage);
	else
		existing->payment_preimage = NULL;
	if (failed)
		existing->failed = failed_htlc_dup(existing, failed);
	else
		existing->failed = NULL;

	return existing;
}

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
	if (added->blinding) {
		towire_bool(pptr, true);
		towire_pubkey(pptr, added->blinding);
		towire_secret(pptr, &added->blinding_ss);
	} else
		towire_bool(pptr, false);
}

void towire_existing_htlc(u8 **pptr, const struct existing_htlc *existing)
{
	towire_u8(pptr, existing->state);
	towire_u64(pptr, existing->id);
	towire_amount_msat(pptr, existing->amount);
 	towire_sha256(pptr, &existing->payment_hash);
	towire_u32(pptr, existing->cltv_expiry);
	towire(pptr, existing->onion_routing_packet,
	       sizeof(existing->onion_routing_packet));
	if (existing->payment_preimage) {
		towire_bool(pptr, true);
		towire_preimage(pptr, existing->payment_preimage);
	} else
		towire_bool(pptr, false);
	if (existing->failed) {
		towire_bool(pptr, true);
		towire_failed_htlc(pptr, existing->failed);
	} else
		towire_bool(pptr, false);
	if (existing->blinding) {
		towire_bool(pptr, true);
		towire_pubkey(pptr, existing->blinding);
	} else
		towire_bool(pptr, false);
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
	if (fromwire_bool(cursor, max)) {
		added->blinding = tal(added, struct pubkey);
		fromwire_pubkey(cursor, max, added->blinding);
		fromwire_secret(cursor, max, &added->blinding_ss);
	} else
		added->blinding = NULL;
}

struct existing_htlc *fromwire_existing_htlc(const tal_t *ctx,
					     const u8 **cursor, size_t *max)
{
	struct existing_htlc *existing = tal(ctx, struct existing_htlc);

	existing->state = fromwire_u8(cursor, max);
	existing->id = fromwire_u64(cursor, max);
	existing->amount = fromwire_amount_msat(cursor, max);
	fromwire_sha256(cursor, max, &existing->payment_hash);
	existing->cltv_expiry = fromwire_u32(cursor, max);
	fromwire(cursor, max, existing->onion_routing_packet,
		 sizeof(existing->onion_routing_packet));
	if (fromwire_bool(cursor, max)) {
		existing->payment_preimage = tal(existing, struct preimage);
		fromwire_preimage(cursor, max, existing->payment_preimage);
	} else
		existing->payment_preimage = NULL;
	if (fromwire_bool(cursor, max))
		existing->failed = fromwire_failed_htlc(existing, cursor, max);
	else
		existing->failed = NULL;
	if (fromwire_bool(cursor, max)) {
		existing->blinding = tal(existing, struct pubkey);
		fromwire_pubkey(cursor, max, existing->blinding);
	} else
		existing->blinding = NULL;
	return existing;
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
	enum onion_wire badonion;

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
	u8 side = fromwire_u8(cursor, max);
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
