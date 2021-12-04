#ifndef LIGHTNING_COMMON_DESCRIPTOR_CHECKSUM_H
#define LIGHTNING_COMMON_DESCRIPTOR_CHECKSUM_H
#include "config.h"
#include <stdbool.h>

/* https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md#reference */
#define DESCRIPTOR_CHECKSUM_LENGTH 8

struct descriptor_checksum {
	char csum[DESCRIPTOR_CHECKSUM_LENGTH + 1];
};

bool descriptor_checksum(const char *descriptor, int desc_size,
			 struct descriptor_checksum *checksum);

#endif /* LIGHTNING_COMMON_DESCRIPTOR_CHECKSUM_H */
