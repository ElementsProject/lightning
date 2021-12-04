#include "config.h"
#include <assert.h>
#include <tests/fuzz/libfuzz.h>

#include <common/base32.h>
#include <common/base64.h>

void init(int *argc, char ***argv)
{
}

void run(const uint8_t *data, size_t size)
{
	char *encoded;
	uint8_t *decoded;

	encoded = b32_encode(NULL, data, size);
	decoded = b32_decode(NULL, encoded, strlen(encoded));
	assert(memcmp(decoded, data, size) == 0);
	tal_free(encoded);
	tal_free(decoded);

	encoded = b64_encode(NULL, data, size);
	tal_free(encoded);
}
