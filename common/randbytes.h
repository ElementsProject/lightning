#ifndef LIGHTNING_COMMON_RANDBYTES_H
#define LIGHTNING_COMMON_RANDBYTES_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>
#include <stddef.h>

/* Usually the libsodium routine randombytes_buf, but dev options can make this deterministic */
#define randbytes(bytes, num_bytes)				\
	do {							\
		static u64 offset;				\
		randbytes_((bytes), (num_bytes), &offset);	\
	} while(0)

void randbytes_(void *bytes, size_t num_bytes, u64 *offset);

void dev_override_randbytes(const char *argv0, long int seed);

bool randbytes_overridden(void);
#endif /* LIGHTNING_COMMON_RANDBYTES_H */
