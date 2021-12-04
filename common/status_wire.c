#include "config.h"
#include <common/status_wire.h>
#include <wire/wire.h>

enum status_failreason fromwire_status_failreason(const u8 **cursor,
						  size_t *max)
{
	u8 r = fromwire_u8(cursor, max);
	if (r > STATUS_FAIL_MAX) {
		fromwire_fail(cursor, max);
		r = STATUS_FAIL_INTERNAL_ERROR;
	}
	return r;
}

enum log_level fromwire_log_level(const u8 **cursor, size_t *max)
{
	u8 l = fromwire_u8(cursor, max);
	if (l > LOG_LEVEL_MAX) {
		fromwire_fail(cursor, max);
		l = LOG_BROKEN;
	}
	return l;
}

void towire_log_level(u8 **pptr, enum log_level level)
{
	towire_u8(pptr, level);
}

void towire_status_failreason(u8 **pptr, enum status_failreason reason)
{
	towire_u8(pptr, reason);
}
