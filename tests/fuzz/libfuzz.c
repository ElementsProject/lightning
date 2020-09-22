#include <tests/fuzz/libfuzz.h>

#include <ccan/tal/tal.h>
#include <common/utils.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerInitialize(int *argc, char ***argv);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
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
