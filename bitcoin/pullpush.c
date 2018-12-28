#include "pullpush.h"
#include "varint.h"
#include <assert.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>

void push_varint(varint_t v,
		 void (*push)(const void *, size_t, void *), void *pushp)
{
	u8 buf[VARINT_MAX_LEN];

	push(buf, varint_put(buf, v), pushp);
}

void push_le32(u32 v,
	       void (*push)(const void *, size_t, void *), void *pushp)
{
	le32 l = cpu_to_le32(v);
	push(&l, sizeof(l), pushp);
}

void push_le64(u64 v,
	       void (*push)(const void *, size_t, void *), void *pushp)
{
	le64 l = cpu_to_le64(v);
	push(&l, sizeof(l), pushp);
}

void push_varint_blob(const tal_t *blob,
		      void (*push)(const void *, size_t, void *),
		      void *pushp)
{
	push_varint(tal_bytelen(blob), push, pushp);
	push(blob, tal_bytelen(blob), pushp);
}

void push(const void *data, size_t len, void *pptr_)
{
	u8 **pptr = pptr_;
	size_t oldsize = tal_count(*pptr);

	tal_resize(pptr, oldsize + len);
	memcpy(*pptr + oldsize, memcheck(data, len), len);
}

/* Sets *cursor to NULL and returns NULL when a pull fails. */
const u8 *pull(const u8 **cursor, size_t *max, void *copy, size_t n)
{
	const u8 *p = *cursor;

	if (*max < n) {
		*cursor = NULL;
		*max = 0;
		/* Just make sure we don't leak uninitialized mem! */
		if (copy)
			memset(copy, 0, n);
		return NULL;
	}
	*cursor += n;
	*max -= n;
	assert(p);
	if (copy)
		memcpy(copy, p, n);
	return memcheck(p, n);
}

u64 pull_varint(const u8 **cursor, size_t *max)
{
	u64 ret;
	size_t len;

	len = varint_get(*cursor, *max, &ret);
	if (len == 0) {
		*cursor = NULL;
		*max = 0;
		return 0;
	}
	pull(cursor, max, NULL, len);
	return ret;
}

u32 pull_le32(const u8 **cursor, size_t *max)
{
	le32 ret;

	if (!pull(cursor, max, &ret, sizeof(ret)))
		return 0;
	return le32_to_cpu(ret);
}

u64 pull_le64(const u8 **cursor, size_t *max)
{
	le64 ret;

	if (!pull(cursor, max, &ret, sizeof(ret)))
		return 0;
	return le64_to_cpu(ret);
}
