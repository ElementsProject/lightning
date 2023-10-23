#include "config.h"

#include <assert.h>
#include <ccan/isaac/isaac64.h>
#include <common/pseudorand.h>
#include <stdlib.h>
#include <string.h>
#include <tests/fuzz/libfuzz.h>

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

static size_t insert_part(const u8 *in1, size_t in1_size, const u8 *in2,
			  size_t in2_size, u8 *out, size_t max_out_size)
{
	size_t max_insert_size;
	size_t insert_begin;
	size_t insert_size;
	size_t in2_begin;

	if (in1_size >= max_out_size)
		return 0;
	if (in1_size == 0 || in2_size == 0)
		return 0;

	max_insert_size = max_out_size - in1_size;
	if (max_insert_size > in2_size)
		max_insert_size = in2_size;
	insert_begin = rand() % in1_size;
	insert_size = (rand() % max_insert_size) + 1;

	in2_begin = rand() % (in2_size - insert_size + 1);

	memcpy(out, in1, insert_begin);
	memcpy(out + insert_begin, in2 + in2_begin, insert_size);
	memcpy(out + insert_begin + insert_size, in1 + insert_begin,
	       in1_size - insert_begin);

	return in1_size + insert_size;
}

static size_t overwrite_part(const u8 *in1, size_t in1_size, const u8 *in2,
			     size_t in2_size, u8 *out, size_t max_out_size)
{
	size_t overwrite_begin;
	size_t overwrite_size;
	size_t in2_begin;

	if (in1_size > max_out_size)
		return 0;
	if (in1_size == 0)
		return 0;

	overwrite_begin = rand() % in1_size;
	overwrite_size = (rand() % (in1_size - overwrite_begin)) + 1;
	if (overwrite_size > in2_size)
		overwrite_size = in2_size;
	in2_begin = rand() % (in2_size - overwrite_size + 1);

	memcpy(out, in1, in1_size);
	memcpy(out + overwrite_begin, in2 + in2_begin, overwrite_size);

	return in1_size;
}

size_t cross_over(const u8 *in1, size_t in1_size, const u8 *in2,
		  size_t in2_size, u8 *out, size_t max_out_size, unsigned seed)
{
	srand(seed);
	if (rand() % 2)
		return insert_part(in1, in1_size, in2, in2_size, out,
				   max_out_size);
	return overwrite_part(in1, in1_size, in2, in2_size, out, max_out_size);
}
