#ifndef LIGHTNING_COMMON_STATUS_WIRE_H
#define LIGHTNING_COMMON_STATUS_WIRE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <common/status_levels.h>
#include <stddef.h>

enum status_failreason fromwire_status_failreason(const u8 **cursor,
						  size_t *max);
enum log_level fromwire_log_level(const u8 **cursor, size_t *max);

void towire_log_level(u8 **pptr, enum log_level level);
void towire_status_failreason(u8 **pptr, enum status_failreason reason);
#endif /* LIGHTNING_COMMON_STATUS_WIRE_H */
