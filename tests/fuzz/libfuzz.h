#ifndef LIGHTNING_TESTS_FUZZ_LIBFUZZ_H
#define LIGHTNING_TESTS_FUZZ_LIBFUZZ_H

#include <stddef.h>
#include <stdint.h>

/* Called once before running the target. Use it to setup the testing
 * environment. */
void init(int *argc, char ***argv);

/* The actual target called multiple times with mutated data. */
void run(const uint8_t *data, size_t size);

/* Copy an array of chunks from data. */
const uint8_t **get_chunks(const void *ctx, const uint8_t *data,
			  size_t data_size, size_t chunk_size);

#endif /* LIGHTNING_TESTS_FUZZ_LIBFUZZ_H */
