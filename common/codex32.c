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
