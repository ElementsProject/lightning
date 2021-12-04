#ifndef LIGHTNING_COMMON_ERRCODE_H
#define LIGHTNING_COMMON_ERRCODE_H

#include "config.h"

#include <ccan/short_types/short_types.h>

typedef s32 errcode_t;

#define PRIerrcode PRId32

#endif /* LIGHTNING_COMMON_ERRCODE_H */
