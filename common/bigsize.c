#include "config.h"
#include <assert.h>
#include <common/bigsize.h>
#include <wire/wire.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

size_t bigsize_len(bigsize_t v)
{
	if (v < 0xfd) {
		return 1;
	} else if (v <= 0xffff) {
		return 3;
	} else if (v <= 0xffffffff) {
		return 5;
	} else {
		return 9;
	}
}

size_t bigsize_put(u8 buf[BIGSIZE_MAX_LEN], bigsize_t v)
{
	u8 *p = buf;

	if (v < 0xfd) {
		*(p++) = v;
	} else if (v <= 0xffff) {
		(*p++) = 0xfd;
		(*p++) = v >> 8;
		(*p++) = v;
	} else if (v <= 0xffffffff) {
		(*p++) = 0xfe;
		(*p++) = v >> 24;
		(*p++) = v >> 16;
		(*p++) = v >> 8;
		(*p++) = v;
	} else {
		(*p++) = 0xff;
		(*p++) = v >> 56;
		(*p++) = v >> 48;
		(*p++) = v >> 40;
		(*p++) = v >> 32;
		(*p++) = v >> 24;
		(*p++) = v >> 16;
		(*p++) = v >> 8;
		(*p++) = v;
	}
	return p - buf;
}

size_t bigsize_get(const u8 *p, size_t max, bigsize_t *val)
{
	if (max < 1) {
		SUPERVERBOSE("EOF");
		return 0;
	}

	switch (*p) {
	case 0xfd:
		if (max < 3) {
			SUPERVERBOSE("unexpected EOF");
			return 0;
		}
		*val = ((u64)p[1] << 8) + p[2];
		if (*val < 0xfd) {
			SUPERVERBOSE("decoded bigsize is not canonical");
			return 0;
		}
		return 3;
	case 0xfe:
		if (max < 5) {
			SUPERVERBOSE("unexpected EOF");
			return 0;
		}
		*val = ((u64)p[1] << 24) + ((u64)p[2] << 16)
			+ ((u64)p[3] << 8) + p[4];
		if ((*val >> 16) == 0) {
			SUPERVERBOSE("decoded bigsize is not canonical");
			return 0;
		}
		return 5;
	case 0xff:
		if (max < 9) {
			SUPERVERBOSE("unexpected EOF");
			return 0;
		}
		*val = ((u64)p[1] << 56) + ((u64)p[2] << 48)
			+ ((u64)p[3] << 40) + ((u64)p[4] << 32)
			+ ((u64)p[5] << 24) + ((u64)p[6] << 16)
			+ ((u64)p[7] << 8) + p[8];
		if ((*val >> 32) == 0) {
			SUPERVERBOSE("decoded bigsize is not canonical");
			return 0;
		}
		return 9;
	default:
		*val = *p;
		return 1;
	}
}

bigsize_t fromwire_bigsize(const u8 **cursor, size_t *max)
{
	bigsize_t v;
	size_t len = bigsize_get(*cursor, *max, &v);

	if (len == 0) {
		fromwire_fail(cursor, max);
		return 0;
	}
	assert(len <= *max);
	fromwire(cursor, max, NULL, len);
	return v;
}

void towire_bigsize(u8 **pptr, const bigsize_t val)
{
	u8 buf[BIGSIZE_MAX_LEN];
	size_t len;

	len = bigsize_put(buf, val);
	towire(pptr, buf, len);
}
