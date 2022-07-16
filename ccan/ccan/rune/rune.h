/* MIT (BSD) license - see LICENSE file for details */
#ifndef CCAN_RUNE_RUNE_H
#define CCAN_RUNE_RUNE_H
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <ccan/tal/tal.h>
#include <ccan/short_types/short_types.h>

/* A rune is a series of restrictions. */
struct rune {
	/* unique_id (if any) */
	const char *unique_id;
	/* Version (if any) */
	const char *version;

	/* SHA-2 256 of restrictions so far. */
	struct sha256_ctx shactx;
	/* Length given by tal_count() */
	struct rune_restr **restrs;
};

/* A restriction is one or more alternatives (altern) */
struct rune_restr {
	/* Length given by tal_count() */
	struct rune_altern **alterns;
};

enum rune_condition {
	RUNE_COND_IF_MISSING = '!',
	RUNE_COND_EQUAL = '=',
	RUNE_COND_NOT_EQUAL = '/',
	RUNE_COND_BEGINS = '^',
	RUNE_COND_ENDS = '$',
	RUNE_COND_CONTAINS = '~',
	RUNE_COND_INT_LESS = '<',
	RUNE_COND_INT_GREATER = '>',
	RUNE_COND_LEXO_BEFORE = '{',
	RUNE_COND_LEXO_AFTER = '}',
	RUNE_COND_COMMENT = '#',
};

/* An alternative is a utf-8 fieldname, a condition, and a value */
struct rune_altern {
	enum rune_condition condition;
	/* Strings. */
	const char *fieldname, *value;
};

/**
 * rune_new - Create an unrestricted rune from this secret.
 * @ctx: tal context, or NULL.  Freeing @ctx will free the returned rune.
 * @secret: secret bytes.
 * @secret_len: number of @secret bytes (must be 55 bytes or less)
 * @version: if non-NULL, sets a version for this rune.
 *
 * This allocates a new, unrestricted rune (sometimes called a master rune).
 *
 * Setting a version allows for different interpretations of a rune if
 * things change in future, at cost of some space when it's used.
 *
 * Example:
 *  u8 secret[16];
 *  struct rune *master;
 *
 *  // A secret determined with a fair die roll!
 *  memset(secret, 5, sizeof(secret));
 *  master = rune_new(NULL, secret, sizeof(secret), NULL);
 *  assert(master);
 */
struct rune *rune_new(const tal_t *ctx, const u8 *secret, size_t secret_len,
		      const char *version);

/**
 * rune_derive_start - Copy master rune, add a unique id.
 * @ctx: context to allocate rune off
 * @master: master rune.
 * @unique_id: unique id; can be NULL, but that's not recommended.
 *
 * It's usually recommended to assign each rune a unique_id, so that
 * specific runes can be blacklisted later (otherwise you need to disable
 * all runes).  This enlarges the rune string by '=<unique_id>' however.
 *
 * The rune version will be the same as the master: if that's non-zero,
 * you *must* set unique_id.
 *
 * @unique_id cannot contain '-'.
 *
 * Example:
 *  struct rune *rune;
 *  // In reality, some global incrementing variable.
 *  const char *id = "1";
 *  rune = rune_derive_start(NULL, master, id);
 *  assert(rune);
 */
struct rune *rune_derive_start(const tal_t *ctx,
			       const struct rune *master,
			       const char *unique_id);

/**
 * rune_dup - Copy a rune.
 * @ctx: tal context, or NULL.
 * @altern: the altern to copy.
 *
 * If @altern is take(), then simply returns it, otherwise copies.
 */
struct rune *rune_dup(const tal_t *ctx, const struct rune *rune TAKES);

/**
 * rune_altern_new - Create a new alternative.
 * @ctx: tal context, or NULL.  Freeing @ctx will free the returned altern.
 * @fieldname: the UTF-8 field for the altern.  You can only have
 *             alphanumerics, '.', '-' and '_' here.
 * @condition: the condition, defined above.
 * @value: the value for comparison; use "" if you don't care.  Any UTF-8 value
 *         is allowed.
 *
 * An altern is the basis of rune restrictions (technically, a restriction
 * is one or more alterns, but it's often just one).
 *
 * Example:
 *  struct rune_altern *a1, *a2;
 *  a1 = rune_altern_new(NULL, "val", RUNE_COND_EQUAL, "7");
 *  a2 = rune_altern_new(NULL, "val2", '>', "-1");
 *  assert(a1 && a2);
 */
struct rune_altern *rune_altern_new(const tal_t *ctx,
				    const char *fieldname TAKES,
				    enum rune_condition condition,
				    const char *value TAKES);

/**
 * rune_altern_dup - copy an alternative.
 * @ctx: tal context, or NULL.
 * @altern: the altern to copy.
 *
 * If @altern is take(), then simply returns it, otherwise copies.
 */
struct rune_altern *rune_altern_dup(const tal_t *ctx,
				    const struct rune_altern *altern TAKES);

/**
 * rune_restr_new - Create a new (empty) restriction.
 * @ctx: tal context, or NULL.  Freeing @ctx will free the returned restriction.
 *
 * Example:
 *  struct rune_restr *restr = rune_restr_new(NULL);
 *  assert(restr);
 */
struct rune_restr *rune_restr_new(const tal_t *ctx);

/**
 * rune_restr_dup - copy a restr.
 * @ctx: tal context, or NULL.
 * @restr: the restr to copy.
 *
 * If @resttr is take(), then simply returns it, otherwise copies.
 */
struct rune_restr *rune_restr_dup(const tal_t *ctx,
				  const struct rune_restr *restr TAKES);

/**
 * rune_restr_add_altern - add an altern to this restriction
 * @restr: the restriction to add to
 * @alt: the altern.
 *
 * If the alt is take(alt) then the alt will be owned by the restriction,
 * otherwise it's copied.
 *
 * Example:
 *  rune_restr_add_altern(restr, take(a1));
 *  rune_restr_add_altern(restr, take(a2));
 */
void rune_restr_add_altern(struct rune_restr *restr,
			   const struct rune_altern *alt TAKES);

/**
 * rune_add_restr - add a restriction to this rune
 * @rune: the rune to add to.
 * @restr: the (non-empty) restriction.
 *
 * If the alt is take(alt) then the alt will be owned by the restr,
 * otherwise it's copied (and all its children are copied!).
 *
 * This fails (and returns false) if restr tries to set unique_id/version
 * and is not the first restriction, or has more than one alternative,
 * or uses a non '=' condition.
 *
 * Example:
 *  rune_add_restr(rune, take(restr));
 */
bool rune_add_restr(struct rune *rune,
		    const struct rune_restr *restr TAKES);

/**
 * rune_altern_eq - are two rune_altern equivalent?
 * @alt1: the first
 * @alt2: the second
 */
bool rune_altern_eq(const struct rune_altern *alt1,
		    const struct rune_altern *alt2);

/**
 * rune_restr_eq - are two rune_restr equivalent?
 * @rest1: the first
 * @rest2: the second
 */
bool rune_restr_eq(const struct rune_restr *rest1,
		   const struct rune_restr *rest2);

/**
 * rune_eq - are two runes equivalent?
 * @rest1: the first
 * @rest2: the second
 */
bool rune_eq(const struct rune *rune1, const struct rune *rune2);

/**
 * rune_alt_single_str - helper to implement check().
 * @ctx: context to allocate any error return from.
 * @alt: alternative to test.
 * @fieldval_str: field value as a string.
 * @fieldval_strlen: length of @fieldval_str
 */
const char *rune_alt_single_str(const tal_t *ctx,
				const struct rune_altern *alt,
				const char *fieldval_str,
				size_t fieldval_strlen);

/**
 * rune_alt_single_int - helper to implement check().
 * @ctx: context to allocate any error return from.
 * @alt: alternative to test.
 * @fieldval_int: field value as an integer.
 */
const char *rune_alt_single_int(const tal_t *ctx,
				const struct rune_altern *alt,
				s64 fieldval_int);

/**
 * rune_alt_single_missing - helper to implement check().
 * @ctx: context to allocate any error return from.
 * @alt: alternative to test.
 *
 * Use this if alt->fieldname is unknown (it could still pass, if
 * the test is that the fieldname is missing).
 */
const char *rune_alt_single_missing(const tal_t *ctx,
				    const struct rune_altern *alt);


/**
 * rune_is_derived - is a rune derived from this other rune?
 * @source: the base rune (usually the master rune)
 * @rune: the rune to check.
 *
 * This is the first part of "is this rune valid?": does the cryptography
 * check out, such that they validly made the rune from this source rune?
 *
 * It also checks that the versions match: if you want to allow more than
 * one version, see rune_is_derived_anyversion.
 */
const char *rune_is_derived(const struct rune *source, const struct rune *rune);

/**
 * rune_is_derived_anyversion - is a rune derived from this other rune?
 * @source: the base rune (usually the master rune)
 * @rune: the rune to check.
 *
 * This does not check source->version against rune->version: if you issue
 * different rune versions you will need to check that yourself.
 */
const char *rune_is_derived_anyversion(const struct rune *source,
				       const struct rune *rune);

/**
 * rune_meets_criteria - do we meet the criteria specified by the rune?
 * @ctx: the tal context to allocate the returned error off.
 * @rune: the rune to check.
 * @check: the callback to check values
 * @arg: data to hand to @check
 *
 * This is the second part of "is this rune valid?".
 */
const char *rune_meets_criteria_(const tal_t *ctx,
				 const struct rune *rune,
				 const char *(*check)(const tal_t *ctx,
						      const struct rune *rune,
						      const struct rune_altern *alt,
						      void *arg),
				 void *arg);

/* Typesafe wrapper */
#define rune_meets_criteria(ctx, rune, check, arg)			\
	rune_meets_criteria_(typesafe_cb_preargs(const char *, void *,	\
						 (ctx), (rune),		\
						 (check), (arg),	\
						 const tal_t *,		\
						 const struct rune *,	\
						 const struct rune_altern *), \
			     (arg))

/**
 * rune_test - is a rune authorized?
 * @ctx: the tal context to allocate @errstr off.
 * @master: the master rune created from secret.
 * @rune: the rune to check.
 * @errstr: if non-NULL, descriptive string of failure.
 * @get: the callback to get values
 * @arg: data to hand to callback
 *
 * Simple call for rune_is_derived() and rune_meets_criteria().  If
 * it's not OK, returns non-NULL.
 */
const char *rune_test_(const tal_t *ctx,
		       const struct rune *master,
		       const struct rune *rune,
		       const char *(*check)(const tal_t *ctx,
					    const struct rune *rune,
					    const struct rune_altern *alt,
					    void *arg),
		       void *arg);

/* Typesafe wrapper */
#define rune_test(ctx_, master_, rune_, check_, arg_)			\
	rune_test_((ctx_), (master_), (rune_),				\
		   typesafe_cb_preargs(const char *, void *,		\
				       (check_), (arg_),		\
				       const tal_t *,			\
				       const struct rune *,		\
				       const struct rune_altern *),	\
		   (arg_))


/**
 * rune_from_base64 - convert base64 string to rune.
 * @ctx: context to allocate rune off.
 * @str: base64 string.
 *
 * Returns NULL if it's malformed.
 */
struct rune *rune_from_base64(const tal_t *ctx, const char *str);

/**
 * rune_from_base64n - convert base64 string to rune.
 * @ctx: context to allocate rune off.
 * @str: base64 string.
 * @len: length of @str.
 *
 * Returns NULL if it's malformed.
 */
struct rune *rune_from_base64n(const tal_t *ctx, const char *str, size_t len);

/**
 * rune_to_base64 - convert run to base64 string.
 * @ctx: context to allocate rune off.
 * @rune: the rune.
 *
 * Only returns NULL if you've allowed tal allocations to return NULL.
 */
char *rune_to_base64(const tal_t *ctx, const struct rune *rune);

/**
 * This is a much more convenient working form.
 */
struct rune *rune_from_string(const tal_t *ctx, const char *str);
char *rune_to_string(const tal_t *ctx, const struct rune *rune);

/**
 * rune_restr_from_string - convenience routine to parse a single restriction.
 * @ctx: context to allocate rune off.
 * @str: the string of form "<field><cond><val>[|<field><cond><val>]*"
 * @len: the length of @str.
 *
 * This is useful for writing simple tests and making simple runes.
 */
struct rune_restr *rune_restr_from_string(const tal_t *ctx,
					  const char *str,
					  size_t len);
#endif /* CCAN_RUNE_RUNE_H */
