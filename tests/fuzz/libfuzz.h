#ifndef LIGHTNING_TESTS_FUZZ_LIBFUZZ_H
#define LIGHTNING_TESTS_FUZZ_LIBFUZZ_H

#include "config.h"
#include <ccan/ccan/short_types/short_types.h>
#include <ccan/ccan/tal/tal.h>
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

/* Copy the data as a string. */
char *to_string(const tal_t *ctx, const u8 *data, size_t data_size);

#endif /* LIGHTNING_TESTS_FUZZ_LIBFUZZ_H */
