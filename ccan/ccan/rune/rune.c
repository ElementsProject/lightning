/* MIT (BSD) license - see LICENSE file for details */
#include "config.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <ccan/rune/rune.h>
#include <ccan/rune/internal.h>

/* Helper to produce an id field */
static struct rune_restr *unique_id_restr(const tal_t *ctx,
					  const char *unique_id,
					  const char *version)
{
	const char *id;
	struct rune_restr *restr;

	assert(!strchr(unique_id, '-'));
	if (version)
		id = tal_fmt(NULL, "%s-%s", unique_id, version);
	else
		id = tal_strdup(NULL, unique_id);

	restr = rune_restr_new(ctx);
        /* We use the empty field for this, since it's always present. */
	rune_restr_add_altern(restr,
			      take(rune_altern_new(NULL, "", '=', take(id))));
	return restr;
}

/* We pad between fields with something identical to the SHA end marker */
void rune_sha256_endmarker(struct sha256_ctx *shactx)
{
	static const unsigned char pad[64] = {0x80};
	be64 sizedesc;

	sizedesc = cpu_to_be64((uint64_t)shactx->bytes << 3);
	/* Add '1' bit to terminate, then all 0 bits, up to next block - 8. */
	sha256_update(shactx, pad, 1 + ((128 - 8 - (shactx->bytes % 64) - 1) % 64));
	/* Add number of bits of data (big endian) */
	sha256_update(shactx, &sizedesc, 8);
}

struct rune *rune_new(const tal_t *ctx, const u8 *secret, size_t secret_len,
		      const char *version)
{
	struct rune *rune = tal(ctx, struct rune);
        assert(secret_len + 1 + 8 <= 64);

	if (version)
		rune->version = tal_strdup(rune, version);
	else
		rune->version = NULL;
	rune->unique_id = NULL;
	sha256_init(&rune->shactx);
	sha256_update(&rune->shactx, secret, secret_len);
	rune_sha256_endmarker(&rune->shactx);
	rune->restrs = tal_arr(rune, struct rune_restr *, 0);
	return rune;
}

struct rune *rune_dup(const tal_t *ctx, const struct rune *rune TAKES)
{
	struct rune *dup;

	if (taken(rune))
		return tal_steal(ctx, (struct rune *)rune);

	dup = tal_dup(ctx, struct rune, rune);
	dup->restrs = tal_arr(dup, struct rune_restr *, tal_count(rune->restrs));
	for (size_t i = 0; i < tal_count(rune->restrs); i++) {
		dup->restrs[i] = rune_restr_dup(dup->restrs,
						rune->restrs[i]);
	}
	return dup;
}

struct rune *rune_derive_start(const tal_t *ctx,
			       const struct rune *master,
			       const char *unique_id TAKES)
{
	struct rune *rune = rune_dup(ctx, master);

        /* If they provide a unique_id, it goes first. */
	if (unique_id) {
		if (taken(unique_id))
			rune->unique_id = tal_steal(rune, unique_id);
		else
			rune->unique_id = tal_strdup(rune, unique_id);
		
		rune_add_restr(rune, take(unique_id_restr(NULL,
							  rune->unique_id,
							  rune->version)));
	} else {
		assert(!rune->version);
	}
	return rune;
}

struct rune_altern *rune_altern_new(const tal_t *ctx,
				    const char *fieldname TAKES,
				    enum rune_condition condition,
				    const char *value TAKES)
{
	struct rune_altern *altern = tal(ctx, struct rune_altern);
	altern->condition = condition;
	altern->fieldname = tal_strdup(altern, fieldname);
	altern->value = tal_strdup(altern, value);
	return altern;
}

struct rune_altern *rune_altern_dup(const tal_t *ctx,
				    const struct rune_altern *altern TAKES)
{
	struct rune_altern *dup;

	if (taken(altern))
		return tal_steal(ctx, (struct rune_altern *)altern);
	dup = tal(ctx, struct rune_altern);
	dup->condition = altern->condition;
	dup->fieldname = tal_strdup(dup, altern->fieldname);
	dup->value = tal_strdup(dup, altern->value);
	return dup;
}

struct rune_restr *rune_restr_dup(const tal_t *ctx,
				  const struct rune_restr *restr TAKES)
{
	struct rune_restr *dup;
	size_t num_altern;

	if (taken(restr))
		return tal_steal(ctx, (struct rune_restr *)restr);

	num_altern = tal_count(restr->alterns);
	dup = tal(ctx, struct rune_restr);
	dup->alterns = tal_arr(dup, struct rune_altern *, num_altern);
	for (size_t i = 0; i < num_altern; i++) {
		dup->alterns[i] = rune_altern_dup(dup->alterns,
						  restr->alterns[i]);
	}
	return dup;
}

struct rune_restr *rune_restr_new(const tal_t *ctx)
{
	struct rune_restr *restr = tal(ctx, struct rune_restr);
	restr->alterns = tal_arr(restr, struct rune_altern *, 0);
	return restr;
}

void rune_restr_add_altern(struct rune_restr *restr,
			   const struct rune_altern *alt TAKES)
{
	size_t num = tal_count(restr->alterns);

	tal_resize(&restr->alterns, num+1);
	restr->alterns[num] = rune_altern_dup(restr->alterns, alt);
}

static bool is_unique_id(const struct rune_altern *alt)
{
	return streq(alt->fieldname, "");
}
	
/* Return unique_id if valid, and sets *version */
static const char *extract_unique_id(const tal_t *ctx,
				     const struct rune_altern *alt,
				     const char **version)
{
	size_t len;
	/* Condition must be '='! */
	if (alt->condition != '=')
		return NULL;

	len = strcspn(alt->value, "-");
	if (alt->value[len])
		*version = tal_strdup(ctx, alt->value + len + 1);
	else
		*version = NULL;
	return tal_strndup(ctx, alt->value, len);
}

bool rune_add_restr(struct rune *rune,
		    const struct rune_restr *restr TAKES)
{
	size_t num = tal_count(rune->restrs);

	/* An empty fieldname is additional correctness checks */
	for (size_t i = 0; i < tal_count(restr->alterns); i++) {
		if (!is_unique_id(restr->alterns[i]))
			continue;

		/* Must be the only alternative */
		if (tal_count(restr->alterns) != 1)
			goto fail;
		/* Must be the first restriction */
		if (num != 0)
			goto fail;

		rune->unique_id = extract_unique_id(rune,
						    restr->alterns[i],
						    &rune->version);
		if (!rune->unique_id)
			goto fail;
	}

	tal_resize(&rune->restrs, num+1);
	rune->restrs[num] = rune_restr_dup(rune->restrs, restr);

	rune_sha256_add_restr(&rune->shactx, rune->restrs[num]);
	return true;

fail:
	if (taken(restr))
		tal_free(restr);
	return false;
}

static const char *rune_restr_test(const tal_t *ctx,
				   const struct rune *rune,
				   const struct rune_restr *restr,
				   const char *(*check)(const tal_t *ctx,
							const struct rune *rune,
							const struct rune_altern *alt,
							void *arg),
				   void *arg)
{
	size_t num = tal_count(restr->alterns);
	const char **errs = tal_arr(NULL, const char *, num);
	char *err;

	/* Only one alternative has to pass! */
	for (size_t i = 0; i < num; i++) {
		errs[i] = check(errs, rune, restr->alterns[i], arg);
		if (!errs[i]) {
			tal_free(errs);
			return NULL;
		}
	}

	err = tal_fmt(ctx, "%s", errs[0]);
	for (size_t i = 1; i < num; i++)
		tal_append_fmt(&err, " AND %s", errs[i]);
	tal_free(errs);
	return err;
}

static const char *cond_test(const tal_t *ctx,
			     const struct rune_altern *alt,
			     const char *complaint,
			     bool cond)
{
	if (cond)
		return NULL;

	return tal_fmt(ctx, "%s %s %s", alt->fieldname, complaint, alt->value);
}

static const char *integer_compare_valid(const tal_t *ctx,
					 const s64 *fieldval_int,
					 const struct rune_altern *alt,
					 s64 *runeval_int)
{
	long l;
	char *p;

	if (!fieldval_int)
		return tal_fmt(ctx, "%s is not an integer field",
			       alt->fieldname);

	errno = 0;
	l = strtol(alt->value, &p, 10);
	if (p == alt->value
	    || *p
	    || ((l == LONG_MIN || l == LONG_MAX) && errno == ERANGE))
		return tal_fmt(ctx, "%s is not a valid integer", alt->value);

	*runeval_int = l;
	return NULL;
}

static int lexo_order(const char *fieldval_str,
		      size_t fieldval_strlen,
		      const char *alt)
{
	int ret = strncmp(fieldval_str, alt, fieldval_strlen);

	/* If alt is same but longer, fieldval is < */
	if (ret == 0 && strlen(alt) > fieldval_strlen)
		ret = -1;
	return ret;
}

static const char *rune_alt_single(const tal_t *ctx,
				   const struct rune_altern *alt,
				   const char *fieldval_str,
				   size_t fieldval_strlen,
				   const s64 *fieldval_int)
{
	char strfield[STR_MAX_CHARS(s64) + 1];
	s64 runeval_int = 0 /* gcc v9.4.0 gets upset with uninitiaized var at -O3 */;
	const char *err;

	/* Caller can't set both! */
	if (fieldval_int) {
		assert(!fieldval_str);
		sprintf(strfield, "%"PRIi64, *fieldval_int);
		fieldval_str = strfield;
		fieldval_strlen = strlen(strfield);
	}

	switch (alt->condition) {
	case RUNE_COND_IF_MISSING:
		if (!fieldval_str)
			return NULL;
		return tal_fmt(ctx, "%s is present", alt->fieldname);
	case RUNE_COND_EQUAL:
		if (!fieldval_str)
			return tal_fmt(ctx, "%s not present", alt->fieldname);
		return cond_test(ctx, alt, "is not equal to",
				 memeqstr(fieldval_str, fieldval_strlen, alt->value));
	case RUNE_COND_NOT_EQUAL:
		if (!fieldval_str)
			return tal_fmt(ctx, "%s not present", alt->fieldname);
		return cond_test(ctx, alt, "is equal to",
				 !memeqstr(fieldval_str, fieldval_strlen, alt->value));
	case RUNE_COND_BEGINS:
		if (!fieldval_str)
			return tal_fmt(ctx, "%s not present", alt->fieldname);
		return cond_test(ctx, alt, "does not start with",
				 memstarts_str(fieldval_str, fieldval_strlen, alt->value));
	case RUNE_COND_ENDS:
		if (!fieldval_str)
			return tal_fmt(ctx, "%s not present", alt->fieldname);
		return cond_test(ctx, alt, "does not end with",
				 memends_str(fieldval_str, fieldval_strlen, alt->value));
	case RUNE_COND_CONTAINS:
		if (!fieldval_str)
			return tal_fmt(ctx, "%s not present", alt->fieldname);
		return cond_test(ctx, alt, "does not contain",
				 memmem(fieldval_str, fieldval_strlen,
					alt->value, strlen(alt->value)));
	case RUNE_COND_INT_LESS:
		if (!fieldval_str && !fieldval_int)
			return tal_fmt(ctx, "%s not present", alt->fieldname);
		err = integer_compare_valid(ctx, fieldval_int,
					    alt, &runeval_int);
		if (err)
			return err;
		return cond_test(ctx, alt, "is greater or equal to",
				 *fieldval_int < runeval_int);
	case RUNE_COND_INT_GREATER:
		if (!fieldval_str && !fieldval_int)
			return tal_fmt(ctx, "%s not present", alt->fieldname);
		err = integer_compare_valid(ctx, fieldval_int,
					    alt, &runeval_int);
		if (err)
			return err;
		return cond_test(ctx, alt, "is less or equal to",
				 *fieldval_int > runeval_int);
	case RUNE_COND_LEXO_BEFORE:
		if (!fieldval_str)
			return tal_fmt(ctx, "%s not present", alt->fieldname);
		return cond_test(ctx, alt, "is equal to or ordered after",
				 lexo_order(fieldval_str, fieldval_strlen, alt->value) < 0);
	case RUNE_COND_LEXO_AFTER:
		if (!fieldval_str)
			return tal_fmt(ctx, "%s not present", alt->fieldname);
		return cond_test(ctx, alt, "is equal to or ordered before",
				 lexo_order(fieldval_str, fieldval_strlen, alt->value) > 0);
	case RUNE_COND_COMMENT:
		return NULL;
	}
	/* We should never create any other values! */
	abort();
}

const char *rune_alt_single_str(const tal_t *ctx,
				const struct rune_altern *alt,
				const char *fieldval_str,
				size_t fieldval_strlen)
{
	return rune_alt_single(ctx, alt, fieldval_str, fieldval_strlen, NULL);
}

const char *rune_alt_single_int(const tal_t *ctx,
				const struct rune_altern *alt,
				s64 fieldval_int)
{
	return rune_alt_single(ctx, alt, NULL, 0, &fieldval_int);
}

const char *rune_alt_single_missing(const tal_t *ctx,
				    const struct rune_altern *alt)
{
	return rune_alt_single(ctx, alt, NULL, 0, NULL);
}

const char *rune_meets_criteria_(const tal_t *ctx,
				 const struct rune *rune,
				 const char *(*check)(const tal_t *ctx,
						      const struct rune *rune,
						      const struct rune_altern *alt,
						      void *arg),
				 void *arg)
{
	for (size_t i = 0; i < tal_count(rune->restrs); i++) {
		const char *err;

		/* Don't "check" unique id */
		if (i == 0 && is_unique_id(rune->restrs[i]->alterns[0]))
			continue;
		
		err = rune_restr_test(ctx, rune, rune->restrs[i], check, arg);
		if (err)
			return err;
	}
	return NULL;
}

const char *rune_test_(const tal_t *ctx,
		       const struct rune *master,
		       const struct rune *rune,
		       const char *(*check)(const tal_t *ctx,
					    const struct rune *rune,
					    const struct rune_altern *alt,
					    void *arg),
		       void *arg)
{
	const char *err;

	err = rune_is_derived(master, rune);
	if (err)
		return err;
	return rune_meets_criteria_(ctx, rune, check, arg);
}

bool rune_altern_eq(const struct rune_altern *alt1,
		    const struct rune_altern *alt2)
{
	return alt1->condition == alt2->condition
		&& streq(alt1->fieldname, alt2->fieldname)
		&& streq(alt1->value, alt2->value);
}

bool rune_restr_eq(const struct rune_restr *rest1,
		   const struct rune_restr *rest2)
{
	if (tal_count(rest1->alterns) != tal_count(rest2->alterns))
		return false;

	for (size_t i = 0; i < tal_count(rest1->alterns); i++)
		if (!rune_altern_eq(rest1->alterns[i], rest2->alterns[i]))
			return false;
	return true;
}

/* Equal, as in both NULL, or both non-NULL and matching */
bool runestr_eq(const char *a, const char *b)
{
	if (a) {
		if (!b)
			return false;
		return streq(a, b);
	} else
		return b == NULL;
}

bool rune_eq(const struct rune *rune1, const struct rune *rune2)
{
	if (!runestr_eq(rune1->unique_id, rune2->unique_id))
		return false;
	if (!runestr_eq(rune1->version, rune2->version))
		return false;

	if (memcmp(rune1->shactx.s, rune2->shactx.s, sizeof(rune1->shactx.s)))
		return false;
	if (rune1->shactx.bytes != rune2->shactx.bytes)
		return false;
	if (memcmp(rune1->shactx.buf.u8, rune2->shactx.buf.u8,
		   rune1->shactx.bytes % 64))
		return false;

	if (tal_count(rune1->restrs) != tal_count(rune2->restrs))
		return false;

	for (size_t i = 0; i < tal_count(rune1->restrs); i++)
		if (!rune_restr_eq(rune1->restrs[i], rune2->restrs[i]))
			return false;
	return true;
}
