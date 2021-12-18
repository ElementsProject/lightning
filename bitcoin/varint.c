#include "config.h"
#include <bitcoin/varint.h>

size_t varint_size(varint_t v)
{
	if (v < 0xfd)
		return 1;
	if (v <= 0xffff)
		return 3;
	if (v <= 0xffffffff)
		return 5;
	return 9;
}

size_t varint_put(u8 buf[VARINT_MAX_LEN], varint_t v)
{
	u8 *p = buf;

	if (v < 0xfd) {
		*(p++) = v;
	} else if (v <= 0xffff) {
		(*p++) = 0xfd;
		(*p++) = v;
		(*p++) = v >> 8;
	} else if (v <= 0xffffffff) {
		(*p++) = 0xfe;
		(*p++) = v;
		(*p++) = v >> 8;
		(*p++) = v >> 16;
		(*p++) = v >> 24;
	} else {
		(*p++) = 0xff;
		(*p++) = v;
		(*p++) = v >> 8;
		(*p++) = v >> 16;
		(*p++) = v >> 24;
		(*p++) = v >> 32;
		(*p++) = v >> 40;
		(*p++) = v >> 48;
		(*p++) = v >> 56;
	}
	return p - buf;
}

size_t varint_get(const u8 *p, size_t max, varint_t *val)
{
	if (max < 1)
		return 0;

	switch (*p) {
	case 0xfd:
		if (max < 3)
			return 0;
		*val = ((u64)p[2] << 8) + p[1];
		return 3;
	case 0xfe:
		if (max < 5)
			return 0;
		*val = ((u64)p[4] << 24) + ((u64)p[3] << 16)
			+ ((u64)p[2] << 8) + p[1];
		return 5;
	case 0xff:
		if (max < 9)
			return 0;
		*val = ((u64)p[8] << 56) + ((u64)p[7] << 48)
			+ ((u64)p[6] << 40) + ((u64)p[5] << 32)
			+ ((u64)p[4] << 24) + ((u64)p[3] << 16)
			+ ((u64)p[2] << 8) + p[1];
		return 9;
	default:
		*val = *p;
		return 1;
	}
}
