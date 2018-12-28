/* CC0 (Public domain) - see LICENSE file for details */
#ifndef CCAN_STR_BASE32_H
#define CCAN_STR_BASE32_H
#include "config.h"
#include <stdbool.h>
#include <stdlib.h>

/**
 * base32_decode - Unpack a base32 string.
 * @str: the base32 string
 * @slen: the length of @str
 * @buf: the buffer to write the data into
 * @bufsize: the length of @buf
 *
 * Returns false if there are any characters which aren't valid encodings
 * or the string wasn't the right length for @bufsize.
 *
 * Example:
 *	unsigned char data[20];
 *
 *	if (!base32_decode(argv[1], strlen(argv[1]), data, 20))
 *		printf("String is malformed!\n");
 */
bool base32_decode(const char *str, size_t slen, void *buf, size_t bufsize);

/**
 * base32_encode - Create a nul-terminated base32 string
 * @buf: the buffer to read the data from
 * @bufsize: the length of @buf
 * @dest: the string to fill
 * @destsize: the max size of the string
 *
 * Returns true if the string, including terminator, fits in @destsize;
 *
 * Example:
 *	unsigned char buf[] = { 'f', 'o' };
 *	char str[9];
 *
 *	if (!base32_encode(buf, sizeof(buf), str, sizeof(str)))
 *		abort();
 */
bool base32_encode(const void *buf, size_t bufsize, char *dest, size_t destsize);

/**
 * base32_str_size - Calculate how big a nul-terminated base32 string is
 * @bytes: bytes of data to represent
 *
 * Example:
 *	unsigned char buf[] = { 'f', 'o' };
 *	char str[base32_str_size(sizeof(buf))];
 *
 *	base32_encode(buf, sizeof(buf), str, sizeof(str));
 */
size_t base32_str_size(size_t bytes);

/**
 * base32_data_size - Calculate how many bytes of data in a base32 string
 * @str: the string
 * @strlen: the length of str to examine.
 *
 * Example:
 *	const char str[] = "MZXQ====";
 *	unsigned char buf[base32_data_size(str, strlen(str))];
 *
 *	base32_decode(str, strlen(str), buf, sizeof(buf));
 */
size_t base32_data_size(const char *str, size_t strlen);

/**
 * base32_chars - the encoding/decoding array to use.
 *
 * It must be at least 33 characters long, representing 32 values and
 * the pad value.  The default array is "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=".
 */
extern const char *base32_chars;

#endif /* CCAN_STR_BASE32_H */
