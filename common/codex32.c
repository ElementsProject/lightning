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
#include <math.h>
#include <secp256k1_schnorrsig.h>
#include <string.h>
#include <time.h>

struct checksum_engine {
	u8 generator[15];
	u8 residue[15];
	u8 target[15];
	size_t len;
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
static void input_fe(const u8 *generator, u8 *residue, uint8_t e, int len)
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
static void input_hrp(const u8 *generator, u8 *residue, const char *hrp, int len)
{
	size_t i = 0;
	for (i = 0; i < strlen(hrp); i++) {
		input_fe(generator, residue, tolower(hrp[i]) >> 5, len);
	}
	input_fe(generator, residue, tolower(hrp[i]) >> 0, len);
	for (i = 0; i < strlen(hrp); i++) {
		input_fe(generator, residue, tolower(hrp[i]) & 0x1f, len);
	}
	return;
}

/* Helper to input data strong of codex32 into the checksum engine. */
static void input_data_str(u8 *generator, u8 *residue, const char *datastr, int len)
{
	size_t i = 0;

	for (i = 0; i < strlen(datastr); i++) {
		input_fe(generator, residue, bech32_charset_rev[(int)datastr[i]], len);
	}

	return;
}

/* Helper to verify codex32 checksum */
static bool checksum_verify (const char *hrp, const char *codex_datastr, bool codexl)
{
	struct checksum_engine engine =  initial_engine_csum[codexl];

	input_hrp((&engine)->generator, (&engine)->residue ,hrp, engine.len);
	input_data_str((&engine)->generator, (&engine)->residue, codex_datastr, engine.len);

	if (memcmp((&engine)->target, (&engine)->residue,
		     engine.len) != 0) {
			return false;
	}
	return true;
}

/* Helper to sanity check the codex32 string parts */
static char *sanity_check (const tal_t *ctx,
			   const struct codex32 *parts)
{
	if (!streq(parts->hrp, "ms") && !streq(parts->hrp, "MS")) {
		return tal_fmt(ctx, "Invalid HRP!");
	}
	if (parts->threshold > 9 ||
	    parts->threshold < 0 ||
	    parts->threshold == 1) {
		return tal_fmt(ctx, "Invalid threshold!");;
	}
	if (strlen(parts->id) != 4) {
		return tal_fmt(ctx, "Invalid ID!");;
	}
	if ((parts->threshold == 0 && !(*(parts->share_idx) == 'S' || *(parts->share_idx) == 's')))
	{
		return tal_fmt(ctx, "Expected share index S for threshold 0!");;
	}
	if((strlen(parts->payload) * 5) % 8 > 4) {
		return tal_fmt(ctx, "Incomplete group exist in payload!");;
	}

	return NULL;
}

/* Pull `len` bytes from the front. */
static const char *pull_front_bytes(const tal_t *ctx, const char **cursor, size_t len)
{
	const char *ret;
	if (strlen(*cursor) < len)
		return NULL;
	ret = tal_strndup(ctx, *cursor, len);
	*cursor += len;
	return ret;
}

/* Pull all bytes except for `leave` at the end. */
static const char *pull_remaining_bytes(const tal_t *ctx, const char **cursor, size_t leave)
{
	size_t slen = strlen(*cursor);
	if (slen < leave)
		return NULL;
	slen -= leave;
	return pull_front_bytes(ctx, cursor, slen);
}

/* Helper to fetch data from payload as a valid hex buffer */
const u8 *codex32_decode_payload(const tal_t *ctx,
				 const struct codex32 *parts)
{
	if (!parts->payload) {
		return NULL;
	}

	// FIXME: Make sure the size of array is correct, because the documentation has 1 extra byte...
	u8 *ret = tal_arr(ctx, u8, ((strlen(parts->payload) * 5 + 7) / 8) - 1);

	uint8_t next_byte = 0;
	uint8_t rem = 0;
	size_t i = 0, j = 0;
	while (parts->payload[i] != '\0') {
		char ch = parts->payload[i++];
		uint8_t fe = bech32_charset_rev[(int)ch];

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
	assert(rem <= 4); // checked when parsing the string
	return ret;
}

/* Checks case inconsistency */
static bool case_check(const char *codex32str)
{
	bool have_lower = false, have_upper = false;
	size_t str_len = strlen(codex32str);
	for (size_t i = 0; i < str_len; i++) {
		if (codex32str[i] >= 'a' && codex32str[i] <= 'z') {
            		have_lower = true;
		} else if (codex32str[i] >= 'A' && codex32str[i] <= 'Z') {
			have_upper = true;
		}
	}
	if (have_lower && have_upper) {
		return false;
	}
	return true;
}

/* Return NULL if the codex32 is invalid */
struct codex32 *codex32_decode(const tal_t *ctx,
		    		     const char *codex32str,
		    		     char **fail)
{
	struct codex32 *parts = tal(ctx, struct codex32);
	size_t checksum_len;
	const char *sep = strchr(codex32str, '1');
	size_t codex32str_len = strlen(codex32str);

	// Separator `1` doesn't exist, Invalid codex string!
	if (!sep) {
		*fail = tal_fmt(ctx, "Separator doesn't exist!");
		return tal_free(parts);
	}

	if (!case_check(codex32str)) {
		*fail = tal_fmt(ctx, "Case inconsistency!");
		return tal_free(parts);
	}

	const char *hrp = tal_strndup(parts, codex32str, sep - codex32str),
	           *codex_datastr = tal_strndup(parts,
		   			        sep + 1,
					        strlen(sep + 1));


	if (!(streq(hrp, "ms") || streq(hrp, "MS"))) {
		*fail = tal_fmt(ctx, "Invalid HRP!");
		return tal_free(parts);
	}

	for (size_t i = 0; i < strlen(codex_datastr); i++) {
		int c = codex_datastr[i];
		if (c < 0 || c > 128) {
			*fail = tal_fmt(ctx,
					"Expected bech32 characters only");
			return tal_free(parts);
		}
		if (bech32_charset_rev[c] == -1) {
			*fail = tal_fmt(ctx,
					"Expected bech32 characters only");
			return tal_free(parts);
		}
	}

	/* FIXME: Confirm if the numbers are correct. */
	if (codex32str_len >= 48 && codex32str_len < 94) {
		parts->codexl = 0;
	} else if (codex32str_len >= 125 && codex32str_len < 128) {
		parts->codexl = 1;
	} else {
		*fail = tal_fmt(ctx, "Invalid length!");
		return tal_free(parts);
	}

	if (strlen(codex_datastr) > 93) {
		checksum_len = 15;
	} else {
		checksum_len = 13;
	}

	if(!checksum_verify(hrp, codex_datastr, parts->codexl)) {
		*fail = tal_fmt(ctx, "Invalid checksum!");
		return tal_free(parts);
	}

	parts->hrp = hrp;
	parts->threshold = *pull_front_bytes(parts, &codex_datastr, 1) - '0';
	parts->id = pull_front_bytes(parts, &codex_datastr, 4);
	parts->share_idx = pull_front_bytes(parts, &codex_datastr, 1);
	parts->payload = pull_remaining_bytes(parts, &codex_datastr, checksum_len);
	parts->checksum = pull_front_bytes(parts, &codex_datastr, checksum_len);

	if (*(parts->share_idx) == 's' || *(parts->share_idx) == 'S') {
		parts->type = CODEX32_ENCODING_SECRET;
	} else {
		parts->type = CODEX32_ENCODING_SHARE;
	}

	char *chk = sanity_check(parts, parts);
	if(chk) {
		*fail = tal_strdup(ctx, chk);
		return tal_free(parts);
	}

	return parts;
}
