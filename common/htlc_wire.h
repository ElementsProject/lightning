#ifndef LIGHTNING_COMMON_HTLC_WIRE_H
#define LIGHTNING_COMMON_HTLC_WIRE_H
#include "config.h"
#include <bitcoin/preimage.h>
#include <ccan/short_types/short_types.h>
#include <common/htlc.h>
#include <common/sphinx.h>
#include <wire/gen_onion_wire.h>

struct bitcoin_tx;
struct shachain;

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
	/* Either this is 0 and failreason non-NULL, or vice versa. */
	enum onion_type failcode;
	u8 *failreason;
	/* Non-NULL if failcode & UPDATE */
	struct short_channel_id *scid;
};

struct changed_htlc {
	enum htlc_state newstate;
	u64 id;
};

void towire_added_htlc(u8 **pptr, const struct added_htlc *added);
void towire_fulfilled_htlc(u8 **pptr, const struct fulfilled_htlc *fulfilled);
void towire_failed_htlc(u8 **pptr, const struct failed_htlc *failed);
void towire_changed_htlc(u8 **pptr, const struct changed_htlc *changed);
void towire_htlc_state(u8 **pptr, const enum htlc_state hstate);
void towire_side(u8 **pptr, const enum side side);
void towire_shachain(u8 **pptr, const struct shachain *shachain);

void fromwire_added_htlc(const u8 **cursor, size_t *max,
			 struct added_htlc *added);
void fromwire_fulfilled_htlc(const u8 **cursor, size_t *max,
			     struct fulfilled_htlc *fulfilled);
struct failed_htlc *fromwire_failed_htlc(const tal_t *ctx, const u8 **cursor,
					 size_t *max);
void fromwire_changed_htlc(const u8 **cursor, size_t *max,
			   struct changed_htlc *changed);
enum htlc_state fromwire_htlc_state(const u8 **cursor, size_t *max);
enum side fromwire_side(const u8 **cursor, size_t *max);
void fromwire_shachain(const u8 **cursor, size_t *max,
		       struct shachain *shachain);
#endif /* LIGHTNING_COMMON_HTLC_WIRE_H */
