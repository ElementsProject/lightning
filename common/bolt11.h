#ifndef LIGHTNING_COMMON_BOLT11_H
#define LIGHTNING_COMMON_BOLT11_H
#include "config.h"

#include <bitcoin/short_channel_id.h>
#include <ccan/list/list.h>
#include <common/hash_u5.h>
#include <common/node_id.h>
#include <secp256k1_recovery.h>

/* We only have 10 bits for the field length, meaning < 640 bytes */
#define BOLT11_FIELD_BYTE_LIMIT ((1 << 10) * 5 / 8)

/* BOLT #11:
 * * `c` (24): `data_length` variable.
 *    `min_final_cltv_expiry_delta` to use for the last HTLC in the route.
 *    Default is 18 if not specified.
 */
#define DEFAULT_FINAL_CLTV_DELTA 18

struct feature_set;

struct bolt11_field {
	struct list_node list;

	char tag;
	u5 *data;
};

/* BOLT #11:
 *   * `pubkey` (264 bits)
 *   * `short_channel_id` (64 bits)
 *   * `fee_base_msat` (32 bits, big-endian)
 *   * `fee_proportional_millionths` (32 bits, big-endian)
 *   * `cltv_expiry_delta` (16 bits, big-endian)
 */

struct route_info {
	/* This is 33 bytes, so we pack cltv_expiry_delta next to it */
	struct node_id pubkey;
	u16 cltv_expiry_delta;
	struct short_channel_id short_channel_id;
	u32 fee_base_msat, fee_proportional_millionths;
};

struct bolt11 {
	const struct chainparams *chain;
	u64 timestamp;
	struct amount_msat *msat; /* NULL if not specified. */

	struct sha256 payment_hash;
	struct node_id receiver_id;

	/* description_hash valid if and only if description is NULL. */
	const char *description;
	struct sha256 *description_hash;

	/* How many seconds to pay from @timestamp above. */
	u64 expiry;

	/* How many blocks final hop requires. */
	u32 min_final_cltv_expiry;

	/* If non-NULL, indicates fallback addresses to pay to. */
	const u8 **fallbacks;

	/* If non-NULL: array of route arrays */
	struct route_info **routes;

	/* signature of sha256 of entire thing. */
	secp256k1_ecdsa_signature sig;

	/* payment secret, if any. */
	struct secret *payment_secret;

	/* Features bitmap, if any. */
	u8 *features;

	/* Optional metadata to send with payment. */
	u8 *metadata;

	struct list_head extra_fields;
};

/* Decodes and checks signature; returns NULL on error; description is
 * (optional) out-of-band description of payment, for `h` field.
 * fset is NULL to accept any features (usually not desirable!).
 *
 * if @must_be_chain is not NULL, fails unless it's this chain.
 */
struct bolt11 *bolt11_decode(const tal_t *ctx, const char *str,
			     const struct feature_set *our_features,
			     const char *description,
			     const struct chainparams *must_be_chain,
			     char **fail);

/* Extracts signature but does not check it. */
struct bolt11 *bolt11_decode_nosig(const tal_t *ctx, const char *str,
				   const struct feature_set *our_features,
				   const char *description,
				   const struct chainparams *must_be_chain,
				   struct sha256 *hash,
				   const u5 **sig,
				   bool *have_n,
				   char **fail);

/* Initialize an empty bolt11 struct with optional amount */
struct bolt11 *new_bolt11(const tal_t *ctx,
			  const struct amount_msat *msat TAKES);

/* Encodes and signs, even if it's nonsense. */
char *bolt11_encode_(const tal_t *ctx,
		     const struct bolt11 *b11, bool n_field,
		     bool (*sign)(const u5 *u5bytes,
				  const u8 *hrpu8,
				  secp256k1_ecdsa_recoverable_signature *rsig,
				  void *arg),
		     void *arg);

#define bolt11_encode(ctx, b11, n_field, sign, arg)		\
	bolt11_encode_((ctx), (b11), (n_field),			\
		       typesafe_cb_preargs(bool, void *, (sign), (arg), \
				const u5 *,			\
				const u8 *,			\
				secp256k1_ecdsa_recoverable_signature *rsig), \
		       (arg))

/** to_canonical_invstr - return a canonical string where the following constrains are follow:
 * - There is no `lightning:` prefix;
 * - all the string is in lower case.
 */
const char *to_canonical_invstr(const tal_t *ctx, const char *invstring);

/* Flags to tweak generation to match test vectors */
extern bool dev_bolt11_old_order;
extern bool dev_bolt11_omit_c_value;

#endif /* LIGHTNING_COMMON_BOLT11_H */
