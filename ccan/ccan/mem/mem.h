/* CC0 (Public domain) - see LICENSE file for details */
#ifndef CCAN_MEM_H
#define CCAN_MEM_H

#include "config.h"
#include <ccan/compiler/compiler.h>

#include <string.h>
#include <stdbool.h>

#if !HAVE_MEMMEM
PURE_FUNCTION
void *memmem(const void *haystack, size_t haystacklen,
	     const void *needle, size_t needlelen);
#endif

#if !HAVE_MEMRCHR
PURE_FUNCTION
void *memrchr(const void *s, int c, size_t n);
#endif

/**
 * mempbrkm - locates the first occurrence in @data of any bytes in @accept
 * @data: where we search
 * @len: length of data in bytes
 * @accept: array of bytes we search for
 * @accept_len: # of bytes in accept
 *
 * Returns a pointer to the byte in @data that matches one of the bytes in
 * @accept, or NULL if no such byte is found.
 *
 * Example:
 *	char otherbytes[] = "Hello \0world";
 *	size_t otherbytes_len = sizeof(otherbytes) - 1;
 *	char *r = mempbrkm(otherbytes, otherbytes_len, "\0b", 2);
 *	if (r) {
 *		printf("Found %c\n", *r);
 *	} else {
 *		printf("Nada\n");
 *	}
 *
 */
PURE_FUNCTION
void *mempbrkm(const void *data, size_t len, const void *accept, size_t accept_len);

/**
 * mempbrk - locates the first occurrence in @data of any bytes in @accept
 * @data: where we search
 * @len: length of data in bytes
 * @accept: NUL terminated string containing the bytes we search for
 *
 * Returns a pointer to the byte in @data that matches one of the bytes in
 * @accept, or NULL if no such byte is found.
 *
 * Example:
 *
 *	r = mempbrk(otherbytes, otherbytes_len, "abcde");
 *	if (r) {
 *		printf("Found %c\n", *r);
 *	} else {
 *		printf("Nada\n");
 *	}
 */
PURE_FUNCTION
static inline char *mempbrk(const void *data, size_t len, const char *accept)
{
	return mempbrkm(data, len, accept, strlen(accept));
}

/**
 * memcchr - scan memory until a character does _not_ match @c
 * @data: pointer to memory to scan
 * @data_len: length of data
 * @c: character to scan for
 *
 * The complement of memchr().
 *
 * Returns a pointer to the first character which is _not_ @c. If all memory in
 * @data is @c, returns NULL.
 *
 * Example:
 *	char somebytes[] = "HI By\0e";
 *	size_t bytes_len = sizeof(somebytes) - 1;
 *	r = memcchr(somebytes, ' ', bytes_len);
 *	if (r) {
 *		printf("Found %c after trimming spaces\n", *r);
 *	}
 */
PURE_FUNCTION
void *memcchr(void const *data, int c, size_t data_len);

/**
 * memeq - Are two byte arrays equal?
 * @a: first array
 * @al: bytes in first array
 * @b: second array
 * @bl: bytes in second array
 *
 * Example:
 *	if (memeq(somebytes, bytes_len, otherbytes, otherbytes_len)) {
 *		printf("memory blocks are the same!\n");
 *	}
 */
PURE_FUNCTION
static inline bool memeq(const void *a, size_t al, const void *b, size_t bl)
{
	return al == bl && (al == 0 || !memcmp(a, b, bl));
}

/**
 * memstarts - determine if @data starts with @prefix
 * @data: does this begin with @prefix?
 * @data_len: bytes in @data
 * @prefix: does @data begin with these bytes?
 * @prefix_len: bytes in @prefix
 *
 * Returns true if @data starts with @prefix, otherwise return false.
 *
 * Example:
 *	if (memstarts(somebytes, bytes_len, otherbytes, otherbytes_len)) {
 *		printf("somebytes starts with otherbytes!\n");
 *	}
 */
PURE_FUNCTION
static inline bool memstarts(void const *data, size_t data_len,
		void const *prefix, size_t prefix_len)
{
	if (prefix_len > data_len)
		return false;
	return memeq(data, prefix_len, prefix, prefix_len);
}

/**
 * memeqstr - Is a byte array equal to a NUL terminated string?
 * @data: byte array
 * @length: length of @data in bytes
 * @string: NUL terminated string
 *
 * The '\0' byte is ignored when checking if @bytes == @string.
 *
 * Example:
 *	if (memeqstr(somebytes, bytes_len, "foo")) {
 *		printf("somebytes == 'foo'!\n");
 *	}
 */
PURE_FUNCTION
static inline bool memeqstr(const void *data, size_t length, const char *string)
{
	return memeq(data, length, string, strlen(string));
}

/**
 * memeqzero - Is a byte array all zeroes?
 * @data: byte array
 * @length: length of @data in bytes
 *
 * Example:
 *	if (memeqzero(somebytes, bytes_len)) {
 *		printf("somebytes == 0!\n");
 *	}
 */
PURE_FUNCTION
bool memeqzero(const void *data, size_t length);

/**
 * memstarts_str - Does this byte array start with a string prefix?
 * @a: byte array
 * @al: length in bytes
 * @s: string prefix
 *
 * Example:
 *	if (memstarts_str(somebytes, bytes_len, "It")) {
 *		printf("somebytes starts with 'It'\n");
 *	}
 */
PURE_FUNCTION
static inline bool memstarts_str(const void *a, size_t al, const char *s)
{
	return memstarts(a, al, s, strlen(s));
}

/**
 * memends - Does this byte array end with a given byte-array suffix?
 * @s: byte array
 * @s_len: length in bytes
 * @suffix: byte array suffix
 * @suffix_len: length of suffix in bytes
 *
 * Returns true if @suffix appears as a substring at the end of @s,
 * false otherwise.
 */
PURE_FUNCTION
static inline bool memends(const void *s, size_t s_len, const void *suffix, size_t suffix_len)
{
	return (s_len >= suffix_len) && (memcmp((const char *)s + s_len - suffix_len,
						suffix, suffix_len) == 0);
}

/**
 * memends_str - Does this byte array end with a string suffix?
 * @a: byte array
 * @al: length in bytes
 * @s: string suffix
 *
 * Example:
 *	if (memends_str(somebytes, bytes_len, "It")) {
 *		printf("somebytes ends with with 'It'\n");
 *	}
 */
PURE_FUNCTION
static inline bool memends_str(const void *a, size_t al, const char *s)
{
	return memends(a, al, s, strlen(s));
}

/**
 * memoverlaps - Do two memory ranges overlap?
 * @a: pointer to first memory range
 * @al: length of first memory range
 * @b: pointer to second memory range
 * @al: length of second memory range
 */
CONST_FUNCTION
static inline bool memoverlaps(const void *a_, size_t al,
			       const void *b_, size_t bl)
{
	const char *a = a_;
	const char *b = b_;

	return (a < (b + bl)) && (b < (a + al));
}

/*
 * memswap - Exchange two memory regions
 * @a: first region
 * @b: second region
 * @n: length of the regions
 *
 * Undefined results if the two memory regions overlap.
 */
void memswap(void *a, void *b, size_t n);

#if HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
static inline void *memcheck_(const void *data, size_t len)
{
	VALGRIND_CHECK_MEM_IS_DEFINED(data, len);
	return (void *)data;
}
#else
static inline void *memcheck_(const void *data, size_t len)
{
	(void)len;
	return (void *)data;
}
#endif

#if HAVE_TYPEOF
/**
 * memcheck - check that a memory region is initialized
 * @data: start of region
 * @len: length in bytes
 *
 * When running under valgrind, this causes an error to be printed
 * if the entire region is not defined.  Otherwise valgrind only
 * reports an error when an undefined value is used for a branch, or
 * written out.
 *
 * Example:
 *	// Search for space, but make sure it's all initialized.
 *	if (memchr(memcheck(somebytes, bytes_len), ' ', bytes_len)) {
 *		printf("space was found!\n");
 *	}
 */
#define memcheck(data, len) ((__typeof__((data)+0))memcheck_((data), (len)))
#else
#define memcheck(data, len) memcheck_((data), (len))
#endif

/**
 * memtaint - mark a memory region unused
 * @data: start of region
 * @len: length in bytes
 *
 * This writes an "0xdeadbeef" eyecatcher repeatedly to the memory.
 * When running under valgrind, it also tells valgrind that the memory is
 * uninitialized, triggering valgrind errors if it is used for branches
 * or written out (or passed to memcheck!) in future.
 *
 * Example:
 *	// We'll reuse this buffer later, but be sure we don't access it.
 *	memtaint(somebytes, bytes_len);
 */
void memtaint(void *data, size_t len);
#endif /* CCAN_MEM_H */
