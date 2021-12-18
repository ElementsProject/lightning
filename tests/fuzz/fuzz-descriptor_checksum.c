#include "config.h"
#include <tests/fuzz/libfuzz.h>

#include <common/descriptor_checksum.h>

void init(int *argc, char ***argv)
{
}

void run(const uint8_t *data, size_t size)
{
	char *string;
	struct descriptor_checksum checksum;

	/* We should not crash nor overflow the checksum buffer. */

	string = to_string(NULL, data, size);
	descriptor_checksum(string, tal_count(string), &checksum);
	tal_free(string);
}
