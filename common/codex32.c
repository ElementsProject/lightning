/* Implementation of BIP-93 "codex32: Checksummed SSSS-aware BIP32 seeds".
 *
 * There are two representations, short and long:
 *
 *   CODEX32 := HRP "1" SHORT-DATA | LONG-DATA
 *   HRP := "ms" | "MS"
 *   SHORT-DATA := THRESHOLD IDENTIFIER SHAREINDEX SHORT-PAYLOAD SHORT-CHECKSUM
 *   LONG-DATA := THRESHOLD IDENTIFIER SHAREINDEX LONG-PAYLOAD LONG-CHECKSUM
 *
 *   THRESHOLD = "0" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"
 *   IDENTIFER := BECH32*4
 *   SHAREINDEX := BECH32
 *
 *   SHORT-PAYLOAD := BECH32 [0 - 74 times]
 *   SHORT-CHECKSUM := BECH32*13
 *
 *   LONG-PAYLOAD := BECH32 [75 - 103 times]
 *   LONG-CHECKSUM := BECH32*15
 *
 * Thus, a short codex32 string has 22 bytes of non-payload, so 22 to 96 characters long.
 * A long codex32 string has 24 bytes of non-payload, so 99 to 127 characters.
 */
#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/bech32_util.h>
#include <common/bolt12.h>
#include <common/bolt12_merkle.h>
#include <common/codex32.h>
#include <common/configdir.h>
#include <common/features.h>
#include <common/utils.h>
#include <math.h>
#include <secp256k1_schnorrsig.h>
#include <string.h>
#include <time.h>

struct checksum_engine {
	u8 generator[15];
	u8 residue[15];
	u8 target[15];
	size_t len;
	size_t max_payload_len;
};

static const struct checksum_engine initial_engine_csum[] = {
	/* Short Codex32 Engine */
	{
		{
			25, 27, 17, 8, 0, 25,
			25, 25,	31, 27, 24, 16,
			16,
		},
		{
			0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0,
			1,
		},
		{
			16, 25,	24, 3, 25, 11,
			16, 23,	29, 3, 25, 17,
			10,
		},
		13,
		74,
	},
	/* Long Codex32 Engine */
	{
		{
			15, 10, 25, 26,	9, 25,
			21, 6,	23, 21,	6, 5,
			22, 4, 23
		},
		{
			0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0,
			0, 0, 1
		},
		{
			16, 25,	24, 3, 25, 11,
			16, 23,	29, 3, 25, 17,
			10, 25,	6
		},
		15,
		103,
	}
};

static const uint8_t logi[32] =
{
     0,  0,  1, 14,  2, 28, 15, 22,
     3,  5, 29, 26, 16,  7, 23, 11,
     4, 25,  6, 10, 30, 13, 27, 21,
    17, 18,  8, 19, 24,  9, 12, 20,
};

static const uint8_t log_inv[31] =
{
     1,  2,  4,  8, 16,  9, 18, 13,
    26, 29, 19, 15, 30, 21,  3,  6,
    12, 24, 25, 27, 31, 23,  7, 14,
    28, 17, 11, 22,  5, 10, 20,
};

static void addition_gf32(uint8_t *x, uint8_t y)
{
	*x = *x ^ y;
	return;
}

static void multiply_gf32(uint8_t *x, uint8_t y)
{
	if (*x == 0 || y == 0) {
		*x = 0;
	} else {
		*x = log_inv[(logi[*x] + logi[y]) % 31];
	}
	return;
}

/* Helper to input a single field element in the checksum engine. */
static void input_fe(const u8 *generator, u8 *residue, uint8_t e, size_t len)
{
	size_t res_len = len;
	u8 xn = residue[0];

	for(size_t i = 1; i < res_len; i++) {
		residue[i - 1] = residue[i];
	}

	residue[res_len - 1] = e;

	for(size_t i = 0; i < res_len; i++) {
		u8 x = generator[i];
		multiply_gf32(&x, xn);
		addition_gf32(&residue[i], x);
	}
}

/* Helper to input the HRP of codex32 string into the checksum engine */
static void input_hrp(const u8 *generator, u8 *residue, const char *hrp, size_t len)
{
	size_t i = 0;
	for (i = 0; i < strlen(hrp); i++) {
		input_fe(generator, residue, hrp[i] >> 5, len);
	}
	input_fe(generator, residue, hrp[i] >> 0, len);
	for (i = 0; i < strlen(hrp); i++) {
		input_fe(generator, residue, hrp[i] & 0x1f, len);
	}
	return;
}

/* Helper to input data strong of codex32 into the checksum engine. */
static void input_data_str(u8 *generator, u8 *residue, const char *datastr, size_t len)
{
	size_t i = 0;

	for (i = 0; i < strlen(datastr); i++) {
		input_fe(generator, residue, bech32_charset_rev[(int)datastr[i]], len);
	}

	return;
}

static void input_own_target(const u8 *generator, u8 *residue, const u8 *target, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		input_fe(generator, residue, target[i], len);
	}
}

/* Helper to verify codex32 checksum */
static bool checksum_verify(const char *hrp, const char *codex_datastr,
			    const struct checksum_engine *initial_engine)
{
	struct checksum_engine engine = *initial_engine;

	input_hrp(engine.generator, engine.residue ,hrp, engine.len);
	input_data_str(engine.generator, engine.residue, codex_datastr, engine.len);

	return memcmp(engine.target, engine.residue, engine.len) == 0;
}

static void calculate_checksum(const char *hrp, char *csum, const char *codex_datastr,
		      	     const struct checksum_engine *initial_engine)
{
	struct checksum_engine engine = *initial_engine;

	input_hrp(engine.generator, engine.residue, hrp, engine.len);
	input_data_str(engine.generator, engine.residue, codex_datastr, engine.len);
	input_own_target(engine.generator, engine.residue, engine.target, engine.len);

	for (size_t i = 0; i < engine.len; i++)
		csum[i] = bech32_charset[engine.residue[i]];
}

/* Pull len chars from cursor into dst. */
static bool pull_chars(char *dst, size_t len, const char **cursor, size_t *max)
{
	if (*max < len)
		return false;
	memcpy(dst, *cursor, len);
	*cursor += len;
	*max -= len;
	return true;
}

/* Truncate length of *cursor (i.e. trim from end) */
static bool trim_chars(size_t len, const char **cursor, size_t *max)
{
	if (*max < len)
		return false;
	*max -= len;
	return true;
}

/* Helper to fetch data from payload as a valid hex buffer */
static const u8 *decode_payload(const tal_t *ctx, const char *payload, size_t payload_len)
{
	u8 *ret = tal_arr(ctx, u8, (payload_len * 5 + 7) / 8);
	uint8_t next_byte = 0;
	uint8_t rem = 0;
	size_t j = 0;

	/* We have already checked this is a valid bech32 string! */
	for (size_t i = 0; i < payload_len; i++) {
		int ch = payload[i];
		uint8_t fe = bech32_charset_rev[ch];

		if (rem < 3) {
			// If we are within 3 bits of the start we can fit the whole next char in
			next_byte |= fe << (3 - rem);
		}
		else if (rem == 3) {
			// If we are exactly 3 bits from the start then this char fills in the byte
			ret[j++] = next_byte | fe;
			next_byte = 0;
		}
		else { // rem > 3
			// Otherwise we have to break it in two
			u8 overshoot = rem - 3;
			assert(overshoot > 0);
			ret[j++] = next_byte | (fe >> overshoot);
			next_byte = fe << (8 - overshoot);
		}

		rem = (rem + 5) % 8;
	}

	/* BIP-93:
	 * Any incomplete group at the end MUST be 4 bits or less, and is discarded.
	 */
	if (rem > 4)
		return tal_free(ret);

	/* As a result, we often don't use the final byte */
	tal_resize(&ret, j);
	return ret;
}

/* Checks case inconsistency, and for non-bech32 chars. */
static const char *bech32_case_fixup(const tal_t *ctx,
				     const char *codex32str,
				     const char **sep)
{
	size_t str_len = strlen(codex32str);
	char *was_upper_str;

	*sep = NULL;

	/* If first is upper, lower-case the rest */
	if (cisupper(codex32str[0])) {
		/* We need a non-const str var, and a flag */
		was_upper_str = tal_strdup(ctx, codex32str);
		codex32str = was_upper_str;
	} else {
		was_upper_str = NULL;
	}

	for (size_t i = 0; i < str_len; i++) {
		int c = codex32str[i];
		if (c == '1') {
			/* Two separators? */
			if (*sep)
				goto fail;
			*sep = codex32str + i;
			continue;
		}
		if (c < 0 || c > 128)
			goto fail;
		if (was_upper_str) {
			/* Mixed case not allowed! */
			if (cislower(c))
				goto fail;
			was_upper_str[i] = c = tolower(c);
		} else {
			if (cisupper(c))
				goto fail;
		}
		if (bech32_charset_rev[c] == -1)
			goto fail;
	}

	return codex32str;

fail:
	return tal_free(was_upper_str);
}

/* Return NULL if the codex32 is invalid */
struct codex32 *codex32_decode(const tal_t *ctx,
			       const char *hrp,
			       const char *codex32str,
			       char **fail)
{
	struct codex32 *parts = tal(ctx, struct codex32);
	const char *sep, *codex_datastr;
	char threshold_char;
	size_t maxlen;
	const struct checksum_engine *csum_engine;

	/* Lowercase it all, iff it's all uppercase. */
	codex32str = bech32_case_fixup(tmpctx, codex32str, &sep);
	if (!codex32str) {
		*fail = tal_fmt(ctx, "Not a valid bech32 string!");
		return tal_free(parts);
	}

	if (!sep) {
		*fail = tal_fmt(ctx, "Separator doesn't exist!");
		return tal_free(parts);
	}

	parts->hrp = tal_strndup(parts, codex32str, sep - codex32str);
	if (hrp && !streq(parts->hrp, hrp)) {
		*fail = tal_fmt(ctx, "Invalid hrp %s!", parts->hrp);
		return tal_free(parts);
	}

	codex_datastr = sep + 1;
	maxlen = strlen(codex_datastr);

	/* If it's short, use short checksum engine.  If it's invalid,
	 * use short checksum and we'll fail when payload is too long. */
	csum_engine = &initial_engine_csum[maxlen >= 96];
	if (!checksum_verify(parts->hrp, codex_datastr, csum_engine)) {
		*fail = tal_fmt(ctx, "Invalid checksum!");
		return tal_free(parts);
	}

	/* Pull fixed parts and discard checksum */
	if (!pull_chars(&threshold_char, 1, &codex_datastr, &maxlen)
	    || !pull_chars(parts->id, ARRAY_SIZE(parts->id) - 1, &codex_datastr, &maxlen)
	    || !pull_chars(&parts->share_idx, 1, &codex_datastr, &maxlen)
	    || !trim_chars(csum_engine->len, &codex_datastr, &maxlen)) {
		*fail = tal_fmt(ctx, "Too short!");
		return tal_free(parts);
	}
	parts->id[ARRAY_SIZE(parts->id)-1] = 0;
	/* Is payload too long for this checksum? */
	if (maxlen > csum_engine->max_payload_len) {
		*fail = tal_fmt(ctx, "Invalid length!");
		return tal_free(parts);
	}

	parts->payload = decode_payload(parts, codex_datastr, maxlen);
	if (!parts->payload) {
		*fail = tal_fmt(ctx, "Invalid payload!");
		return tal_free(parts);
	}

	if (parts->share_idx == 's') {
		parts->type = CODEX32_ENCODING_SECRET;
	} else {
		parts->type = CODEX32_ENCODING_SHARE;
	}

	parts->threshold = threshold_char - '0';
	if (parts->threshold > 9 ||
	    parts->threshold < 0 ||
	    /* Can't happen because bech32 `1` is invalid, but worth noting */
	    parts->threshold == 1) {
		*fail = tal_fmt(ctx, "Invalid threshold!");
		return tal_free(parts);
	}

	if (parts->threshold == 0 && parts->type != CODEX32_ENCODING_SECRET) {
		*fail = tal_fmt(ctx, "Expected share index s for threshold 0!");
		return tal_free(parts);
	}

	return parts;
}

/* Returns Codex32 encoded secret of the seed provided. */
const char *codex32_secret_encode(const tal_t *ctx,
				  const char *hrp,
				  const char *id,
				  const u32 threshold,
				  const u8 *seed,
				  size_t seedlen,
				  char **bip93)
{
	const struct checksum_engine *csum_engine;

	/* FIXME: Our code assumes a two-letter HRP!  Larger won't allow a
	 * 128-bit secret in a "standard billfold metal wallet" acording to
	 * Russell O'Connor */
	assert(strlen(hrp) == 2);

	if (threshold > 9 || threshold < 0 || threshold == 1)
		return tal_fmt(ctx, "Invalid threshold %u", threshold);

	if (strlen(id) != 4)
		return tal_fmt(ctx, "Invalid id: must be 4 characters");

	for (size_t i = 0; id[i]; i++) {
		s8 rev;

		if (id[i] & 0x80)
			return tal_fmt(ctx, "Invalid id: must be ASCII");

		rev = bech32_charset_rev[(int)id[i]];
		if (rev == -1)
			return tal_fmt(ctx, "Invalid id: must be valid bech32 string");
		if (bech32_charset[rev] != id[i])
			return tal_fmt(ctx, "Invalid id: must be lower-case");
	}

	/* Every codex32 has hrp `ms` and since we are generating a
	 * secret it's share index would be `s` and threshold given by user. */
	*bip93 = tal_fmt(ctx, "%s1%d%ss", hrp, threshold, id);

	uint8_t next_u5 = 0, rem = 0;

        for (size_t i = 0; i < seedlen; i++) {
            /* Each byte provides at least one u5. Push that. */
            uint8_t u5 = (next_u5 << (5 - rem)) | seed[i] >> (3 + rem);

	    tal_append_fmt(bip93, "%c", bech32_charset[u5]);
            next_u5 = seed[i] & ((1 << (3 + rem)) - 1);

            /* If there were 2 or more bits from the last iteration, then
             * this iteration will push *two* u5s. */
            if(rem >= 2) {
	        tal_append_fmt(bip93, "%c", bech32_charset[next_u5 >> (rem - 2)]);
                next_u5 &= (1 << (rem - 2)) - 1;
            }
            rem = (rem + 8) % 5;
        }
        if(rem > 0) {
	    tal_append_fmt(bip93, "%c", bech32_charset[next_u5 << (5 - rem)]);
        }

	csum_engine = &initial_engine_csum[seedlen >= 51];
	char csum[csum_engine->len];
	calculate_checksum(hrp, csum, *bip93 + 3, csum_engine);
	tal_append_fmt(bip93, "%.*s", (int)csum_engine->len, csum);
	return NULL;
}
