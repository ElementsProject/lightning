/* MIT (BSD) license - see LICENSE file for details */
#include <ccan/utf8/utf8.h>
#include <errno.h>
#include <stdlib.h>

/* I loved this table, so I stole it: */
/*
 * Copyright (c) 2017 Christian Hansen <chansen@cpan.org>
 * <https://github.com/chansen/c-utf8-valid>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 *    UTF-8 Encoding Form
 *
 *    U+0000..U+007F       0xxxxxxx				<= 7 bits
 *    U+0080..U+07FF       110xxxxx 10xxxxxx			<= 11 bits
 *    U+0800..U+FFFF       1110xxxx 10xxxxxx 10xxxxxx		<= 16 bits
 *   U+10000..U+10FFFF     11110xxx 10xxxxxx 10xxxxxx 10xxxxxx	<= 21 bits
 *
 *
 *    U+0000..U+007F       00..7F
 *                      N  C0..C1  80..BF                   1100000x 10xxxxxx
 *    U+0080..U+07FF       C2..DF  80..BF
 *                      N  E0      80..9F  80..BF           11100000 100xxxxx
 *    U+0800..U+0FFF       E0      A0..BF  80..BF
 *    U+1000..U+CFFF       E1..EC  80..BF  80..BF
 *    U+D000..U+D7FF       ED      80..9F  80..BF
 *                      S  ED      A0..BF  80..BF           11101101 101xxxxx
 *    U+E000..U+FFFF       EE..EF  80..BF  80..BF
 *                      N  F0      80..8F  80..BF  80..BF   11110000 1000xxxx
 *   U+10000..U+3FFFF      F0      90..BF  80..BF  80..BF
 *   U+40000..U+FFFFF      F1..F3  80..BF  80..BF  80..BF
 *  U+100000..U+10FFFF     F4      80..8F  80..BF  80..BF   11110100 1000xxxx
 *
 *  Legend:
 *    N = Non-shortest form
 *    S = Surrogates
 */
bool utf8_decode(struct utf8_state *utf8_state, char c)
{
	if (utf8_state->used_len == utf8_state->total_len) {
		utf8_state->used_len = 1;
		/* First character in sequence. */
		if (((unsigned char)c & 0x80) == 0) {
			/* ASCII, easy. */
			if (c == 0)
				goto bad_encoding;
			utf8_state->total_len = 1;
			utf8_state->c = c;
			goto finished_decoding;
		} else if (((unsigned char)c & 0xE0) == 0xC0) {
			utf8_state->total_len = 2;
			utf8_state->c = ((unsigned char)c & 0x1F);
			return false;
		} else if (((unsigned char)c & 0xF0) == 0xE0) {
			utf8_state->total_len = 3;
			utf8_state->c = ((unsigned char)c & 0x0F);
			return false;
		} else if (((unsigned char)c & 0xF8) == 0xF0) {
			utf8_state->total_len = 4;
			utf8_state->c = ((unsigned char)c & 0x07);
			return false;
		}
		goto bad_encoding;
	}

	if (((unsigned char)c & 0xC0) != 0x80)
		goto bad_encoding;

	utf8_state->c <<= 6;
	utf8_state->c |= ((unsigned char)c & 0x3F);
	
	utf8_state->used_len++;
	if (utf8_state->used_len == utf8_state->total_len)
		goto finished_decoding;
	return false;

finished_decoding:
	if (utf8_state->c == 0 || utf8_state->c > 0x10FFFF)
		errno = ERANGE;
	/* The UTF-16 "surrogate range": illegal in UTF-8 */
	else if (utf8_state->total_len == 3
		 && (utf8_state->c & 0xFFFFF800) == 0x0000D800)
		errno = ERANGE;
	else {
		int min_bits;
		switch (utf8_state->total_len) {
		case 1:
			min_bits = 0;
			break;
		case 2:
			min_bits = 7;
			break;
		case 3:
			min_bits = 11;
			break;
		case 4:
			min_bits = 16;
			break;
		default:
			abort();
		}
		if ((utf8_state->c >> min_bits) == 0)
			errno = EFBIG;
		else
			errno = 0;
	}
	return true;

bad_encoding:
	utf8_state->total_len = utf8_state->used_len;
	errno = EINVAL;
	return true;
}

size_t utf8_encode(uint32_t point, char dest[UTF8_MAX_LEN])
{
	if ((point >> 7) == 0) {
		if (point == 0) {
			errno = ERANGE;
			return 0;
		}
		/* 0xxxxxxx */
		dest[0] = point;
		return 1;
	}

	if ((point >> 11) == 0) {
		/* 110xxxxx 10xxxxxx */
		dest[1] = 0x80 | (point & 0x3F);
		dest[0] = 0xC0 | (point >> 6);
		return 2;
	}

	if ((point >> 16) == 0) {
		if (point >= 0xD800 && point <= 0xDFFF) {
			errno = ERANGE;
			return 0;
		}
		/* 1110xxxx 10xxxxxx 10xxxxxx */
		dest[2] = 0x80 | (point & 0x3F);
		dest[1] = 0x80 | ((point >> 6) & 0x3F);
		dest[0] = 0xE0 | (point >> 12);
		return 3;
	}

	if (point > 0x10FFFF) {
		errno = ERANGE;
		return 0;
	}

	/* 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
	dest[3] = 0x80 | (point & 0x3F);
	dest[2] = 0x80 | ((point >> 6) & 0x3F);
	dest[1] = 0x80 | ((point >> 12) & 0x3F);
	dest[0] = 0xF0 | (point >> 18);
	return 4;
}
