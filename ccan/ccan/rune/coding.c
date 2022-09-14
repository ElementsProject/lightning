/* MIT (BSD) license - see LICENSE file for details */
/* Routines to encode / decode a rune */
#include <ccan/rune/rune.h>
#include <ccan/rune/internal.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <ccan/base64/base64.h>
#include <ccan/endian/endian.h>
#include <errno.h>

/* From Python base64.urlsafe_b64encode:
 *
 * The alphabet uses '-' instead of '+' and '_' instead of '/'.
 */
static const base64_maps_t base64_maps_urlsafe = {
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",

  "\xff\xff\xff\xff\xff" /* 0 */
  "\xff\xff\xff\xff\xff" /* 5 */
  "\xff\xff\xff\xff\xff" /* 10 */
  "\xff\xff\xff\xff\xff" /* 15 */
  "\xff\xff\xff\xff\xff" /* 20 */
  "\xff\xff\xff\xff\xff" /* 25 */
  "\xff\xff\xff\xff\xff" /* 30 */
  "\xff\xff\xff\xff\xff" /* 35 */
  "\xff\xff\xff\xff\xff" /* 40 */
  "\x3e\xff\xff\x34\x35" /* 45 */
  "\x36\x37\x38\x39\x3a" /* 50 */
  "\x3b\x3c\x3d\xff\xff" /* 55 */
  "\xff\xff\xff\xff\xff" /* 60 */
  "\x00\x01\x02\x03\x04" /* 65 A */
  "\x05\x06\x07\x08\x09" /* 70 */
  "\x0a\x0b\x0c\x0d\x0e" /* 75 */
  "\x0f\x10\x11\x12\x13" /* 80 */
  "\x14\x15\x16\x17\x18" /* 85 */
  "\x19\xff\xff\xff\xff" /* 90 */
  "\x3f\xff\x1a\x1b\x1c" /* 95 */
  "\x1d\x1e\x1f\x20\x21" /* 100 */
  "\x22\x23\x24\x25\x26" /* 105 */
  "\x27\x28\x29\x2a\x2b" /* 110 */
  "\x2c\x2d\x2e\x2f\x30" /* 115 */
  "\x31\x32\x33\xff\xff" /* 120 */
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 125 */
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 135 */
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 145 */
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 155 */
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 165 */
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 175 */
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 185 */
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 195 */
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 205 */
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 215 */
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 225 */
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 235 */
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 245 */
};

/* For encoding as a string */
struct wbuf {
	size_t off, len;
	char *buf;
};

static void to_wbuf(const char *s, size_t len, void *vwbuf)
{
	struct wbuf *wbuf = vwbuf;

	while (wbuf->off + len > wbuf->len)
		tal_resize(&wbuf->buf, wbuf->len *= 2);
	memcpy(wbuf->buf + wbuf->off, s, len);
	wbuf->off += len;
}

/* For adding to sha256 */
static void to_sha256(const char *s, size_t len, void *vshactx)
{
	struct sha256_ctx *shactx = vshactx;
	sha256_update(shactx, s, len);
}

static void rune_altern_encode(const struct rune_altern *altern,
			       void (*cb)(const char *s, size_t len,
					  void *arg),
			       void *arg)
{
	char cond = altern->condition;
	const char *p;

	cb(altern->fieldname, strlen(altern->fieldname), arg);
	cb(&cond, 1, arg);

	p = altern->value;
	for (;;) {
		char esc[2] = { '\\' };
		size_t len = strcspn(p, "\\|&");
		cb(p, len, arg);
		if (!p[len])
			break;
		esc[1] = p[len];
		cb(esc, 2, arg);
		p += len + 1;
	}
}

static void rune_restr_encode(const struct rune_restr *restr,
			      void (*cb)(const char *s, size_t len,
					 void *arg),
			      void *arg)
{
	for (size_t i = 0; i < tal_count(restr->alterns); i++) {
		if (i != 0)
			cb("|", 1, arg);
		rune_altern_encode(restr->alterns[i], cb, arg);
	}
}

void rune_sha256_add_restr(struct sha256_ctx *shactx,
			   struct rune_restr *restr)
{
	rune_restr_encode(restr, to_sha256, shactx);
	rune_sha256_endmarker(shactx);
}

const char *rune_is_derived(const struct rune *source, const struct rune *rune)
{
	if (!runestr_eq(source->version, rune->version))
		return "Version mismatch";

	return rune_is_derived_anyversion(source, rune);
}
	
const char *rune_is_derived_anyversion(const struct rune *source,
				       const struct rune *rune)
{
	struct sha256_ctx shactx;
	size_t i;

	if (tal_count(rune->restrs) < tal_count(source->restrs))
		return "Fewer restrictions than master";

	/* If we add the same restrictions to source rune, do we match? */
	shactx = source->shactx;
	for (i = 0; i < tal_count(rune->restrs); i++) {
		/* First restrictions must be identical */
		if (i < tal_count(source->restrs)) {
			if (!rune_restr_eq(source->restrs[i], rune->restrs[i]))
				return "Does not match master restrictions";
		} else
			rune_sha256_add_restr(&shactx, rune->restrs[i]);
	}

	if (memcmp(shactx.s, rune->shactx.s, sizeof(shactx.s)) != 0)
		return "Not derived from master";
	return NULL;
}

static bool peek_char(const char *data, size_t len, char *c)
{
	if (len == 0)
		return false;
	*c = *data;
	return true;
}

static void drop_char(const char **data, size_t *len)
{
	(*data)++;
	(*len)--;
}

static void pull_invalid(const char **data, size_t *len)
{
	*data = NULL;
	*len = 0;
}

static bool pull_char(const char **data, size_t *len, char *c)
{
	if (!peek_char(*data, *len, c)) {
		pull_invalid(data, len);
		return false;
	}
	drop_char(data, len);
	return true;
}

bool rune_condition_is_valid(enum rune_condition cond)
{
	switch (cond) {
	case RUNE_COND_IF_MISSING:
	case RUNE_COND_EQUAL:
	case RUNE_COND_NOT_EQUAL:
	case RUNE_COND_BEGINS:
	case RUNE_COND_ENDS:
	case RUNE_COND_CONTAINS:
	case RUNE_COND_INT_LESS:
	case RUNE_COND_INT_GREATER:
	case RUNE_COND_LEXO_BEFORE:
	case RUNE_COND_LEXO_AFTER:
	case RUNE_COND_COMMENT:
		return true;
	}
	return false;
}

size_t rune_altern_fieldname_len(const char *alternstr, size_t alternstrlen)
{
	for (size_t i = 0; i < alternstrlen; i++) {
		if (cispunct(alternstr[i]))
			return i;
	}
	return alternstrlen;
}

/* Sets *more on success: true if another altern follows */
static struct rune_altern *rune_altern_decode(const tal_t *ctx,
					      const char **data, size_t *len,
					      bool *more)
{
	struct rune_altern *alt = tal(ctx, struct rune_altern);
	char *value;
	size_t strlen;
	char c;

        /* Swallow field up to possible conditional */
	strlen = rune_altern_fieldname_len(*data, *len);
	alt->fieldname = tal_strndup(alt, *data, strlen);
	*data += strlen;
	*len -= strlen;

	/* Grab conditional */
	if (!pull_char(data, len, &c) || !rune_condition_is_valid(c))
		return tal_free(alt);

	alt->condition = c;

	/* Assign worst case. */
	value = tal_arr(alt, char, *len + 1);
	strlen = 0;
	*more = false;
	while (*len && pull_char(data, len, &c)) {
		if (c == '|') {
			*more = true;
			break;
		}
		if (c == '&')
			break;

		if (c == '\\' && !pull_char(data, len, &c))
			return tal_free(alt);
		value[strlen++] = c;
	}
	value[strlen] = '\0';
	tal_resize(&value, strlen + 1);
	alt->value = value;
	return alt;
}

static struct rune_restr *rune_restr_decode(const tal_t *ctx,
					    const char **data, size_t *len)
{
	struct rune_restr *restr = tal(ctx, struct rune_restr);
	size_t num_alts = 0;
	bool more;

	/* Must have at least one! */
	restr->alterns = tal_arr(restr, struct rune_altern *, 0);
	do {
		struct rune_altern *alt;

		alt = rune_altern_decode(restr, data, len, &more);
		if (!alt)
			return tal_free(restr);
		tal_resize(&restr->alterns, num_alts+1);
		restr->alterns[num_alts++] = alt;
	} while (more);
	return restr;
}

static struct rune *from_string(const tal_t *ctx,
				const char *str,
				const u8 *hash32)
{
	size_t len = strlen(str);
	struct rune *rune = tal(ctx, struct rune);

	/* Now count up how many bytes we should have hashed: secret uses
	 * first block. */
	rune->shactx.bytes = 64;

	rune->restrs = tal_arr(rune, struct rune_restr *, 0);
	rune->unique_id = NULL;
	rune->version = NULL;

	while (len) {
		struct rune_restr *restr;
		restr = rune_restr_decode(rune, &str, &len);
		if (!restr)
			return tal_free(rune);
		if (!rune_add_restr(rune, restr))
			return tal_free(rune);
	}

	/* Now we replace with canned hash state */
	memcpy(rune->shactx.s, hash32, 32);
	for (size_t i = 0; i < 8; i++)
		rune->shactx.s[i] = be32_to_cpu(rune->shactx.s[i]);

	return rune;
}

struct rune_restr *rune_restr_from_string(const tal_t *ctx,
					  const char *str,
					  size_t len)
{
	struct rune_restr *restr;

	restr = rune_restr_decode(NULL, &str, &len);
	/* Don't allow trailing chars */
	if (restr && len != 0)
		restr = tal_free(restr);
	return tal_steal(ctx, restr);
}

static void to_string(struct wbuf *wbuf, const struct rune *rune, u8 *hash32)
{
	/* Copy hash in big-endian */
	for (size_t i = 0; i < 8; i++) {
		be32 v = cpu_to_be32(rune->shactx.s[i]);
		memcpy(hash32 + i*4, &v, sizeof(v));
	}

	for (size_t i = 0; i < tal_count(rune->restrs); i++) {
		if (i != 0)
			to_wbuf("&", 1, wbuf);
		rune_restr_encode(rune->restrs[i], to_wbuf, wbuf);
	}
	to_wbuf("", 1, wbuf);
}

struct rune *rune_from_base64n(const tal_t *ctx, const char *str, size_t len)
{
	size_t blen;
	u8 *data;
	struct rune *rune;

	data = tal_arr(NULL, u8, base64_decoded_length(len) + 1);

	blen = base64_decode_using_maps(&base64_maps_urlsafe,
				       (char *)data, tal_bytelen(data),
				       str, len);
	if (blen == -1)
		goto fail;

	if (blen < 32)
		goto fail;

	data[blen] = '\0';
	/* Sanity check that it's a valid string! */
	if (strlen((char *)data + 32) != blen - 32)
		goto fail;

	rune = from_string(ctx, (const char *)data + 32, data);
	tal_free(data);
	return rune;

fail:
	tal_free(data);
	return NULL;
}

struct rune *rune_from_base64(const tal_t *ctx, const char *str)
{
	return rune_from_base64n(ctx, str, strlen(str));
}

char *rune_to_base64(const tal_t *ctx, const struct rune *rune)
{
	u8 hash32[32];
	char *ret;
	size_t ret_len;
	struct wbuf wbuf;

	/* We're going to prepend hash */
	wbuf.off = sizeof(hash32);
	wbuf.len = 64;
	wbuf.buf = tal_arr(NULL, char, wbuf.len);

	to_string(&wbuf, rune, hash32);
	/* Prepend hash */
	memcpy(wbuf.buf, hash32, sizeof(hash32));

	ret = tal_arr(ctx, char, base64_encoded_length(wbuf.off) + 1);
	ret_len = base64_encode_using_maps(&base64_maps_urlsafe,
					   ret, tal_bytelen(ret),
					   wbuf.buf, wbuf.off - 1);
	ret[ret_len] = '\0';
	tal_free(wbuf.buf);
	return ret;
}

struct rune *rune_from_string(const tal_t *ctx, const char *str)
{
	u8 hash[32];
	if (!hex_decode(str, 64, hash, sizeof(hash)))
		return NULL;
	if (str[64] != ':')
		return NULL;
	return from_string(ctx, str + 65, hash);
}

char *rune_to_string(const tal_t *ctx, const struct rune *rune)
{
	u8 hash32[32];
	struct wbuf wbuf;

	/* We're going to prepend hash (in hex), plus colon */
	wbuf.off = sizeof(hash32) * 2 + 1;
	wbuf.len = 128;
	wbuf.buf = tal_arr(ctx, char, wbuf.len);

	to_string(&wbuf, rune, hash32);
	hex_encode(hash32, sizeof(hash32), wbuf.buf, sizeof(hash32) * 2 + 1);
	wbuf.buf[sizeof(hash32) * 2] = ':';
	return wbuf.buf;
}
