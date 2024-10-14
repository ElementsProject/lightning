#ifndef LIGHTNING_COMMON_HTLC_WIRE_H
#define LIGHTNING_COMMON_HTLC_WIRE_H
#include "config.h"
#include <bitcoin/preimage.h>
#include <common/htlc.h>
#include <common/sphinx.h>

struct bitcoin_tx;
struct shachain;

/* These are how we communicate about HTLC state to the master daemon */
struct added_htlc {
	u64 id;
	struct amount_msat amount;
	struct sha256 payment_hash;
	u32 cltv_expiry;
	u8 onion_routing_packet[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)];
	bool fail_immediate;
	struct pubkey *path_key;
};

/* This is how lightningd tells us about HTLCs which already exist at startup */
struct existing_htlc {
	u64 id;
	enum htlc_state state;
	struct amount_msat amount;
	struct sha256 payment_hash;
	u32 cltv_expiry;
	u8 onion_routing_packet[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)];
	/* If this is non-NULL, this is path_key to send with (outgoing) HTLC */
	struct pubkey *path_key;
	/* If fulfilled, this is non-NULL */
	struct preimage *payment_preimage;
	/* If failed, this is set */
	const struct failed_htlc *failed;
};

struct fulfilled_htlc {
	u64 id;
	struct preimage payment_preimage;
};

struct failed_htlc {
	u64 id;

	/* If this is non-NULL, then the onion was malformed and this is the
	 * SHA256 of what we got: send update_fail_malformed_htlc, using
	 * failcode. */
	struct sha256 *sha256_of_onion;
	/* WIRE_INVALID_ONION_VERSION, WIRE_INVALID_ONION_KEY or
	 * WIRE_INVALID_ONION_HMAC (ie. must have BADONION) */
	enum onion_wire badonion;

	/* Otherwise, this is the onion ready to send to them. */
	const struct onionreply *onion;
};

struct changed_htlc {
	enum htlc_state newstate;
	u64 id;
};

/* For signing interfaces */
struct simple_htlc {
	enum side side;
	struct amount_msat amount;
	struct sha256 payment_hash;
	u32 cltv_expiry;
};

struct existing_htlc *new_existing_htlc(const tal_t *ctx,
					u64 id,
					enum htlc_state state,
					struct amount_msat amount,
					const struct sha256 *payment_hash,
					u32 cltv_expiry,
					const u8 onion_routing_packet[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)],
					const struct pubkey *path_key TAKES,
					const struct preimage *preimage TAKES,
					const struct failed_htlc *failed TAKES);

struct simple_htlc *new_simple_htlc(const tal_t *ctx,
				    enum side side,
				    struct amount_msat amount,
				    const struct sha256 *payment_hash,
				    u32 cltv_expiry);

void towire_added_htlc(u8 **pptr, const struct added_htlc *added);
void towire_existing_htlc(u8 **pptr, const struct existing_htlc *existing);
void towire_simple_htlc(u8 **pptr, const struct simple_htlc *simple);
void towire_fulfilled_htlc(u8 **pptr, const struct fulfilled_htlc *fulfilled);
void towire_failed_htlc(u8 **pptr, const struct failed_htlc *failed);
void towire_changed_htlc(u8 **pptr, const struct changed_htlc *changed);
void towire_side(u8 **pptr, const enum side side);
void towire_shachain(u8 **pptr, const struct shachain *shachain);

void fromwire_added_htlc(const u8 **cursor, size_t *max,
			 struct added_htlc *added);
struct existing_htlc *fromwire_existing_htlc(const tal_t *ctx,
					     const u8 **cursor, size_t *max);
struct simple_htlc *fromwire_simple_htlc(const tal_t *ctx,
					 const u8 **cursor, size_t *max);
void fromwire_fulfilled_htlc(const u8 **cursor, size_t *max,
			     struct fulfilled_htlc *fulfilled);
struct failed_htlc *fromwire_failed_htlc(const tal_t *ctx, const u8 **cursor,
					 size_t *max);
void fromwire_changed_htlc(const u8 **cursor, size_t *max,
			   struct changed_htlc *changed);
enum side fromwire_side(const u8 **cursor, size_t *max);
void fromwire_shachain(const u8 **cursor, size_t *max,
		       struct shachain *shachain);
#endif /* LIGHTNING_COMMON_HTLC_WIRE_H */
