#ifndef LIGHTNING_LIGHTNINGD_BOLT11_H
#define LIGHTNING_LIGHTNINGD_BOLT11_H
#include "config.h"

#include <bitcoin/pubkey.h>
#include <bitcoin/short_channel_id.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <common/hash_u5.h>

struct lightningd;

/* We only have 10 bits for the field length, meaning < 640 bytes */
#define BOLT11_FIELD_BYTE_LIMIT ((1 << 10) * 5 / 8)

struct bolt11_field {
	struct list_node list;

	char tag;
	u5 *data;
};

/* BOLT #11:
 *   * `pubkey` (264 bits)
 *   * `short_channel_id` (64 bits)
 *   * `fee` (64 bits, big-endian)
 *   * `cltv_expiry_delta` (16 bits, big-endian)
 */

struct route_info {
	struct pubkey pubkey;
	struct short_channel_id short_channel_id;
	u64 fee;
	u16 cltv_expiry_delta;
};

struct bolt11 {
	const struct chainparams *chain;
	u64 timestamp;
	u64 *msatoshi; /* NULL if not specified. */

	struct sha256 payment_hash;
	struct pubkey receiver_id;

	/* description_hash valid iff description is NULL. */
	const char *description;
	struct sha256 *description_hash;

	/* How many seconds to pay from @timestamp above. */
	u64 expiry;

	/* How many blocks final hop requires. */
	u32 min_final_cltv_expiry;

	/* If non-NULL, indicates a fallback address to pay to. */
	const u8 *fallback;

	/* If non-NULL: array of route arrays */
	struct route_info **routes;

	/* signature of sha256 of entire thing. */
	secp256k1_ecdsa_signature sig;

	struct list_head extra_fields;
};

/* Decodes and checks signature; returns NULL on error; description is
 * (optional) out-of-band description of payment, for `h` field. */
struct bolt11 *bolt11_decode(const tal_t *ctx, const char *str,
			     const char *description, char **fail);

/* Initialize an empty bolt11 struct with optional amount */
struct bolt11 *new_bolt11(const tal_t *ctx, u64 *msatoshi);

/* Encodes and signs, even if it's nonsense. */
char *bolt11_encode(const tal_t *ctx,
                    struct lightningd *ld,
                    const struct bolt11 *b11, bool n_field);

/**
 * bolt11_out_check - check a bolt11 struct for validity and consistency
 * @bolt11: the bolt11
 * @abortstr: the location to print on aborting, or NULL.
 *
 * Note this does not apply to bolt11's we decoded, which may not be spec
 * compliant.
 *
 * If @abortstr is non-NULL, that will be printed in a diagnostic if the bolt11
 * is invalid, and the function will abort.
 *
 * Returns @bolt11 if all OK, NULL if not (it can never return NULL if
 * @abortstr is set).
 */
struct bolt11 *bolt11_out_check(const struct bolt11 *bolt11,
				const char *abortstr);
#endif /* LIGHTNING_LIGHTNINGD_BOLT11_H */
