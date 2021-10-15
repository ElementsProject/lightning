/* Licensed under BSD-MIT - see LICENSE file for details */
#include "base64.h"

#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

/**
 * sixbit_to_b64 - maps a 6-bit value to the base64 alphabet
 * @param map A base 64 map (see base64_init_map)
 * @param sixbit Six-bit value to map
 * @return a base 64 character
 */
static char sixbit_to_b64(const base64_maps_t *maps, const uint8_t sixbit)
{
	assert(sixbit <= 63);

	return maps->encode_map[(unsigned char)sixbit];
}

/**
 * sixbit_from_b64 - maps a base64-alphabet character to its 6-bit value
 * @param maps A base 64 maps structure (see base64_init_maps)
 * @param sixbit Six-bit value to map
 * @return a six-bit value
 */
static int8_t sixbit_from_b64(const base64_maps_t *maps,
			      const unsigned char b64letter)
{
	int8_t ret;

	ret = maps->decode_map[(unsigned char)b64letter];
	if (ret == (char)0xff) {
		errno = EDOM;
		return -1;
	}

	return ret;
}

bool base64_char_in_alphabet(const base64_maps_t *maps, const char b64char)
{
	return (maps->decode_map[(const unsigned char)b64char] != (char)0xff);
}

void base64_init_maps(base64_maps_t *dest, const char src[64])
{
	unsigned char i;

	memcpy(dest->encode_map,src,64);
	memset(dest->decode_map,0xff,256);
	for (i=0; i<64; i++) {
		dest->decode_map[(unsigned char)src[i]] = i;
	}
}

size_t base64_encoded_length(size_t srclen)
{
	return ((srclen + 2) / 3) * 4;
}

void base64_encode_triplet_using_maps(const base64_maps_t *maps,
				      char dest[4], const char src[3])
{
	char a = src[0];
	char b = src[1];
	char c = src[2];

	dest[0] = sixbit_to_b64(maps, (a & 0xfc) >> 2);
	dest[1] = sixbit_to_b64(maps, ((a & 0x3) << 4) | ((b & 0xf0) >> 4));
	dest[2] = sixbit_to_b64(maps, ((c & 0xc0) >> 6) | ((b & 0xf) << 2));
	dest[3] = sixbit_to_b64(maps, c & 0x3f);
}

void base64_encode_tail_using_maps(const base64_maps_t *maps, char dest[4],
				   const char *src, const size_t srclen)
{
	char longsrc[3] = { 0 };

	assert(srclen <= 3);

	memcpy(longsrc, src, srclen);
	base64_encode_triplet_using_maps(maps, dest, longsrc);
	memset(dest+1+srclen, '=', 3-srclen);
}

ssize_t base64_encode_using_maps(const base64_maps_t *maps,
				 char *dest, const size_t destlen,
				 const char *src, const size_t srclen)
{
	size_t src_offset = 0;
	size_t dest_offset = 0;

	if (destlen < base64_encoded_length(srclen)) {
		errno = EOVERFLOW;
		return -1;
	}

	while (srclen - src_offset >= 3) {
		base64_encode_triplet_using_maps(maps, &dest[dest_offset], &src[src_offset]);
		src_offset += 3;
		dest_offset += 4;
	}

	if (src_offset < srclen) {
		base64_encode_tail_using_maps(maps, &dest[dest_offset], &src[src_offset], srclen-src_offset);
		dest_offset += 4;
	}

	memset(&dest[dest_offset], '\0', destlen-dest_offset);

	return dest_offset;
}

size_t base64_decoded_length(size_t srclen)
{
	return ((srclen+3)/4*3);
}

int base64_decode_quartet_using_maps(const base64_maps_t *maps, char dest[3],
				     const char src[4])
{
	signed char a;
	signed char b;
	signed char c;
	signed char d;

	a = sixbit_from_b64(maps, src[0]);
	b = sixbit_from_b64(maps, src[1]);
	c = sixbit_from_b64(maps, src[2]);
	d = sixbit_from_b64(maps, src[3]);

	if ((a == -1) || (b == -1) || (c == -1) || (d == -1)) {
		return -1;
	}

	dest[0] = (a << 2) | (b >> 4);
	dest[1] = ((b & 0xf) << 4) | (c >> 2);
	dest[2] = ((c & 0x3) << 6) | d;

	return 0;
}


int base64_decode_tail_using_maps(const base64_maps_t *maps, char dest[3],
				  const char * src, const size_t srclen)
{
	char longsrc[4];
	int quartet_result;
	size_t insize = srclen;

	while (insize != 0 &&
	       src[insize-1] == '=') { /* throw away padding symbols */
		insize--;
	}
	if (insize == 0) {
		return 0;
	}
	if (insize == 1) {
		/* the input is malformed.... */
		errno = EINVAL;
		return -1;
	}
	memcpy(longsrc, src, insize);
	memset(longsrc+insize, 'A', 4-insize);
	quartet_result = base64_decode_quartet_using_maps(maps, dest, longsrc);
	if (quartet_result == -1) {
		return -1;
	}

	return insize - 1;
}

ssize_t base64_decode_using_maps(const base64_maps_t *maps,
				 char *dest, const size_t destlen,
				 const char *src, const size_t srclen)
{
	ssize_t dest_offset = 0;
	ssize_t i;
	size_t more;

	if (destlen < base64_decoded_length(srclen)) {
		errno = EOVERFLOW;
		return -1;
	}

	for(i=0; srclen - i > 4; i+=4) {
		if (base64_decode_quartet_using_maps(maps, &dest[dest_offset], &src[i]) == -1) {
			return -1;
		}
		dest_offset += 3;
	}

	more = base64_decode_tail_using_maps(maps, &dest[dest_offset], &src[i], srclen - i);
	if (more == -1) {
		return -1;
	}
	dest_offset += more;

	memset(&dest[dest_offset], '\0', destlen-dest_offset);

	return dest_offset;
}




/**
 * base64_maps_rfc4648 - pregenerated maps struct for rfc4648
 */
const base64_maps_t base64_maps_rfc4648 = {
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",

  "\xff\xff\xff\xff\xff" /* 0 */					\
  "\xff\xff\xff\xff\xff" /* 5 */					\
  "\xff\xff\xff\xff\xff" /* 10 */					\
  "\xff\xff\xff\xff\xff" /* 15 */					\
  "\xff\xff\xff\xff\xff" /* 20 */					\
  "\xff\xff\xff\xff\xff" /* 25 */					\
  "\xff\xff\xff\xff\xff" /* 30 */					\
  "\xff\xff\xff\xff\xff" /* 35 */					\
  "\xff\xff\xff\x3e\xff" /* 40 */					\
  "\xff\xff\x3f\x34\x35" /* 45 */					\
  "\x36\x37\x38\x39\x3a" /* 50 */					\
  "\x3b\x3c\x3d\xff\xff" /* 55 */					\
  "\xff\xff\xff\xff\xff" /* 60 */					\
  "\x00\x01\x02\x03\x04" /* 65 A */					\
  "\x05\x06\x07\x08\x09" /* 70 */					\
  "\x0a\x0b\x0c\x0d\x0e" /* 75 */					\
  "\x0f\x10\x11\x12\x13" /* 80 */					\
  "\x14\x15\x16\x17\x18" /* 85 */					\
  "\x19\xff\xff\xff\xff" /* 90 */					\
  "\xff\xff\x1a\x1b\x1c" /* 95 */					\
  "\x1d\x1e\x1f\x20\x21" /* 100 */					\
  "\x22\x23\x24\x25\x26" /* 105 */					\
  "\x27\x28\x29\x2a\x2b" /* 110 */					\
  "\x2c\x2d\x2e\x2f\x30" /* 115 */					\
  "\x31\x32\x33\xff\xff" /* 120 */					\
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 125 */			\
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"				\
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"				\
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 155 */			\
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"				\
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"				\
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 185 */			\
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"				\
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"				\
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 215 */			\
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"				\
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"				\
  "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" /* 245 */
};
