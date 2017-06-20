#ifndef LIGHTNING_LIGHTNINGD_HTLC_WIRE_H
#define LIGHTNING_LIGHTNINGD_HTLC_WIRE_H
#include "config.h"
#include <bitcoin/preimage.h>
#include <ccan/short_types/short_types.h>
#include <daemon/htlc.h>
#include <lightningd/sphinx.h>
#include <wire/gen_onion_wire.h>

/* These are how we communicate about HTLC state to the master daemon */
struct added_htlc {
	u64 id;
	u64 amount_msat;
	struct sha256 payment_hash;
	u32 cltv_expiry;
	u8 onion_routing_packet[TOTAL_PACKET_SIZE];
};

struct fulfilled_htlc {
	u64 id;
	struct preimage payment_preimage;
};

struct failed_htlc {
	u64 id;
	enum onion_type malformed;
	u8 *failreason;
};

struct changed_htlc {
	enum htlc_state newstate;
	u64 id;
};

void towire_added_htlc(u8 **pptr, const struct added_htlc *added);
void towire_fulfilled_htlc(u8 **pptr, const struct fulfilled_htlc *fulfilled);
void towire_failed_htlc(u8 **pptr, const struct failed_htlc *failed);
void towire_changed_htlc(u8 **pptr, const struct changed_htlc *changed);
void towire_htlc_state(u8 **pptr, const enum htlc_state *hstate);
void towire_side(u8 **pptr, const enum side *side);

void fromwire_added_htlc(const u8 **cursor, size_t *max,
			 struct added_htlc *added);
void fromwire_fulfilled_htlc(const u8 **cursor, size_t *max,
			     struct fulfilled_htlc *fulfilled);
void fromwire_failed_htlc(const tal_t *ctx, const u8 **cursor, size_t *max,
			  struct failed_htlc *failed);
void fromwire_changed_htlc(const u8 **cursor, size_t *max,
			   struct changed_htlc *changed);
void fromwire_htlc_state(const u8 **cursor, size_t *max,
			 enum htlc_state *hstate);
void fromwire_side(const u8 **cursor, size_t *max, enum side *side);
#endif /* LIGHTNING_LIGHTNINGD_HTLC_WIRE_H */
