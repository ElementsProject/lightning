#ifndef LIGHTNING_LIGHTNINGD_HTLC_SET_H
#define LIGHTNING_LIGHTNINGD_HTLC_SET_H
#include "config.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <common/amount.h>
#include <common/pseudorand.h>
#include <common/utils.h>
#include <wire/onion_wire.h>

struct htlc_in;
struct lightningd;

/* Set of incoming HTLCs for multi-part-payments */
struct htlc_set {
	struct lightningd *ld;
	struct amount_msat total_msat, so_far;
	struct sha256 payment_hash;
	struct htlc_in **htlcs;
	struct oneshot *timeout;
};

static inline const struct sha256 *keyof_htlc_set(const struct htlc_set *set)
{
	return &set->payment_hash;
}

static inline size_t hash_payment_hash(const struct sha256 *payment_hash)
{
	return siphash24(siphash_seed(), payment_hash, sizeof(&payment_hash));
}

static inline bool htlc_set_eq(const struct htlc_set *set,
			       const struct sha256 *payment_hash)
{
	return sha256_eq(payment_hash, &set->payment_hash);
}

HTABLE_DEFINE_TYPE(struct htlc_set,
		   keyof_htlc_set,
		   hash_payment_hash,
		   htlc_set_eq,
		   htlc_set_map);

/* Handles hin: if it completes a set, hands that to invoice_try_pay */
void htlc_set_add(struct lightningd *ld,
		  struct htlc_in *hin,
		  struct amount_msat total_msat,
		  const struct secret *payment_secret);

/* Fail every htlc in the set: frees set.  If failmsg is NULL/zero-length,
 * it sends each one a WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS. */
#define htlc_set_fail(set, failmsg)				\
	htlc_set_fail_((set), (failmsg), __FILE__, __LINE__)
void htlc_set_fail_(struct htlc_set *set, const u8 *failmsg TAKES,
		    const char *file, int line);

/* Fulfill every htlc in the set: frees set */
void htlc_set_fulfill(struct htlc_set *set, const struct preimage *preimage);
#endif /* LIGHTNING_LIGHTNINGD_HTLC_SET_H */
