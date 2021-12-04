/* MIT (BSD) license - see LICENSE file for details */
#ifndef CCAN_UTF8_H
#define CCAN_UTF8_H
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

/* Unicode is limited to 21 bits. */
#define UTF8_MAX_LEN	4

struct utf8_state {
	/* How many characters we are expecting as part of this Unicode point */
	uint16_t total_len;
	/* How many characters we've already seen. */
	uint16_t used_len;
	/* Compound character, aka Unicode point. */
	uint32_t c;
};

#define UTF8_STATE_INIT { 0, 0, 0 }

static inline void utf8_state_init(struct utf8_state *utf8_state)
{
	memset(utf8_state, 0, sizeof(*utf8_state));
}

/**
 * utf8_decode - continue UTF8 decoding with this character.
 * @utf8_state - initialized UTF8 state.
 * @c - the character.
 *
 * Returns false if it needs another character to give results.
 * Otherwise returns true, @utf8_state can be reused without initializeation,
 * and sets errno:
 * 0: success
 * EINVAL: bad encoding (including a NUL character).
 * EFBIG: not a minimal encoding.
 * ERANGE: encoding of invalid character.
 *
 * You can extract the character from @utf8_state->c; @utf8_state->used_len
 * indicates how many characters have been consumed.
 */
bool utf8_decode(struct utf8_state *utf8_state, char c);

/**
 * utf8_encode - encode a point into UTF8.
 * @point - Unicode point to include.
 * @dest - buffer to fill.
 *
 * Returns 0 if point was invalid, otherwise bytes of dest used.
 * Sets errno to ERANGE if point was invalid.
 */
size_t utf8_encode(uint32_t point, char dest[UTF8_MAX_LEN]);
#endif /* CCAN_UTF8_H */
