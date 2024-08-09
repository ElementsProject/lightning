/* CC0 (Public domain) - see LICENSE file for details */

#include "config.h"

#include <assert.h>
#include <string.h>
#include <ccan/mem/mem.h>

#if !HAVE_MEMMEM
void *memmem(const void *haystack, size_t haystacklen,
	     const void *needle, size_t needlelen)
{
	const char *p;

	if (needlelen > haystacklen)
		return NULL;

	p = haystack;

	for (p = haystack;
	     (p + needlelen) <= ((const char *)haystack + haystacklen);
	     p++)
		if (memcmp(p, needle, needlelen) == 0)
			return (void *)p;

	return NULL;
}
#endif

#if !HAVE_MEMRCHR
void *memrchr(const void *s, int c, size_t n)
{
	unsigned char *p = (unsigned char *)s;

	while (n) {
		if (p[n-1] == c)
			return p + n - 1;
		n--;
	}

	return NULL;
}
#endif

void *mempbrkm(const void *data_, size_t len, const void *accept_, size_t accept_len)
{
	const char *data = data_, *accept = accept_;
	size_t i, j;

	for (i = 0; i < len; i++)
		for (j = 0; j < accept_len; j++)
			if (accept[j] == data[i])
				return (void *)&data[i];
	return NULL;
}

void *memcchr(void const *data, int c, size_t data_len)
{
	char const *p = data;
	size_t i;

	for (i = 0; i < data_len; i++)
		if (p[i] != c)
			return (void *)&p[i];

	return NULL;
}

#define MEMSWAP_TMP_SIZE	256

void memswap(void *a, void *b, size_t n)
{
	char *ap = a;
	char *bp = b;
	char tmp[MEMSWAP_TMP_SIZE];

	assert(!memoverlaps(a, n, b, n));

	while (n) {
		size_t m = n > MEMSWAP_TMP_SIZE ? MEMSWAP_TMP_SIZE : n;

		memcpy(tmp, bp, m);
		memcpy(bp, ap, m);
		memcpy(ap, tmp, m);

		ap += m;
		bp += m;
		n -= m;
	}
}

bool memeqzero(const void *data, size_t length)
{
	const unsigned char *p = data;
	size_t len;

	/* Check first 16 bytes manually */
	for (len = 0; len < 16; len++) {
		if (!length)
			return true;
		if (*p)
			return false;
		p++;
		length--;
	}

	/* Now we know that's zero, memcmp with self. */
	return memcmp(data, p, length) == 0;
}

void memtaint(void *data, size_t len)
{
	/* Using 16 bytes is a bit quicker than 4 */
	const unsigned tainter[]
		= { 0xdeadbeef, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef };
	char *p = data;

	while (len >= sizeof(tainter)) {
		memcpy(p, tainter, sizeof(tainter));
		p += sizeof(tainter);
		len -= sizeof(tainter);
	}
	memcpy(p, tainter, len);

#if HAVE_VALGRIND_MEMCHECK_H
	(void)VALGRIND_MAKE_MEM_UNDEFINED(data, len);
#endif
}
