#include "config.h"
#include <tests/fuzz/libfuzz.h>

#include <assert.h>
#include <ccan/isaac/isaac64.h>
#include <common/pseudorand.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerInitialize(int *argc, char ***argv);

/* Provide a non-random pseudo-random function to speed fuzzing. */
static isaac64_ctx isaac64;

uint64_t pseudorand(uint64_t max)
{
	assert(max);
	return isaac64_next_uint(&isaac64, max);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	isaac64_init(&isaac64, NULL, 0);

	run(data, size);
	return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	init(argc, argv);

	return 0;
}

const uint8_t **get_chunks(const void *ctx, const uint8_t *data,
			  size_t data_size, size_t chunk_size)
{
	size_t n_chunks = data_size / chunk_size;
	const uint8_t **chunks = tal_arr(ctx, const uint8_t *, n_chunks);

	for (size_t i = 0; i < n_chunks; i++)
		chunks[i] = tal_dup_arr(chunks, const uint8_t,
					data + i * chunk_size, chunk_size, 0);

	return chunks;
}

char *to_string(const tal_t *ctx, const u8 *data, size_t data_size)
{
	char *string = tal_arr(ctx, char, data_size + 1);

	for (size_t i = 0; i < data_size; i++)
		string[i] = (char) data[i] % (CHAR_MAX + 1);
	string[data_size] = '\0';

	return string;
}
