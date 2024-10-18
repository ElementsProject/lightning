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

struct lightningd;
struct logger;

/* Could be an incoming HTLC, could be a local payment */
struct incoming_payment {
	/* Where to log */
	struct logger *log;
	/* Amount of this payment */
	struct amount_msat msat;
	/* If it fails */
	void (*fail)(void *arg, const u8 *failmsg TAKES);
	/* If it succeeded: here's the preimage. */
	void (*succeeded)(void *arg, const struct preimage *preimage);
	void *arg;
};

/* Set of incoming HTLCs for multi-part-payments */
struct htlc_set {
	struct lightningd *ld;
	struct amount_msat total_msat, so_far;
	struct sha256 payment_hash;
	struct incoming_payment **inpays;
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

/* Handles arg: if it completes a set, calls invoice_try_pay */
void htlc_set_add_(struct lightningd *ld,
		   struct logger *log,
		   struct amount_msat msat,
		   struct amount_msat total_msat,
		   const struct sha256 *payment_hash,
		   const struct secret *payment_secret,
		   void (*fail)(void *, const u8 *),
		   void (*succeeded)(void *, const struct preimage *),
		   void *arg);

#define htlc_set_add(ld, log, msat, total_msat, payment_hash, payment_secret, \
		     fail, succeeded, arg)				\
	htlc_set_add_((ld), (log), (msat), (total_msat), (payment_hash), \
		      (payment_secret),					\
		      typesafe_cb_postargs(void, void *,		\
					   (fail), (arg),		\
					   const u8 *),			\
		      typesafe_cb_postargs(void, void *,		\
					   (succeeded), (arg),		\
					   const struct preimage *),	\
		      (arg))

/* Fail every htlc in the set: frees set.  If failmsg is NULL/zero-length,
 * it sends each one a WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS. */
#define htlc_set_fail(set, failmsg)				\
	htlc_set_fail_((set), (failmsg), __FILE__, __LINE__)
void htlc_set_fail_(struct htlc_set *set, const u8 *failmsg TAKES,
		    const char *file, int line);

/* Fulfill every htlc in the set: frees set */
void htlc_set_fulfill(struct htlc_set *set, const struct preimage *preimage);
#endif /* LIGHTNING_LIGHTNINGD_HTLC_SET_H */
