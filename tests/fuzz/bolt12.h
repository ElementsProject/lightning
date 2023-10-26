/* This header contains custom mutators used by all the fuzz-bolt12-* fuzz
 * targets. The actual fuzz targets only need to:
 *   1. Define the bech32_hrp string to the expected HRP for inputs.
 *   2. Implement the run() function. asdfa
 */
#ifndef LIGHTNING_TESTS_FUZZ_BOLT12_H
#define LIGHTNING_TESTS_FUZZ_BOLT12_H

#include "config.h"
#include <common/bech32_util.h>
#include <common/setup.h>
#include <common/utils.h>
#include <string.h>
#include <tests/fuzz/libfuzz.h>

/* Include bolt12.c directly, to gain access to string_to_data(). */
#include "../../common/bolt12.c"

/* The HRP to use in our custom mutators. For bolt12, this can be "lno", "lnr",
 * or "lni". */
extern const char *bech32_hrp;

/* Default mutator defined by libFuzzer. */
size_t LLVMFuzzerMutate(u8 *data, size_t size, size_t max_size);

/* Custom mutators for use by libFuzzer, defined below. */
size_t LLVMFuzzerCustomMutator(u8 *fuzz_data, size_t size, size_t max_size,
			       unsigned int seed);
size_t LLVMFuzzerCustomCrossOver(const u8 *data1, size_t size1, const u8 *data2,
				 size_t size2, u8 *out, size_t max_size,
				 unsigned seed);

/* Encodes a dummy bolt12 offer/invoice-request/invoice into fuzz_data and
 * returns the size of the encoded string. */
static size_t initial_input(u8 *fuzz_data, size_t size, size_t max_size)
{
	static char *dummy;
	static size_t dummy_size;
	if (!dummy) {
		/* Initialize dummy to bech32_hrp followed by '1'. */
		size_t bech32_hrp_len = strlen(bech32_hrp);
		dummy = tal_dup_arr(NULL, char, bech32_hrp, bech32_hrp_len, 1);
		dummy[bech32_hrp_len] = '1';
		dummy_size = bech32_hrp_len + 1;
	}

	size = max_size < dummy_size ? max_size : dummy_size;
	memcpy(fuzz_data, dummy, size);

	clean_tmpctx();
	return size;
}

/* A custom mutator that decodes the bech32 input, mutates the decoded input,
 * and then re-encodes the mutated input. This produces an input corpus that
 * consists entirely of correctly encoded bech32 strings, enabling efficient
 * fuzzing of the bolt12 decoding logic without the fuzzer getting stuck on
 * fuzzing the bech32 decoding logic. */
size_t LLVMFuzzerCustomMutator(u8 *fuzz_data, size_t size, size_t max_size,
			       unsigned int seed)
{
	const u8 *decoded_data;
	size_t decoded_size;
	u8 *mutated_data;
	size_t mutated_size;
	char *encoded_data;
	size_t encoded_size;
	char *fail;

	/* Decode the input. */
	decoded_data = string_to_data(tmpctx, (char *)fuzz_data, size,
				      bech32_hrp, &decoded_size, &fail);
	if (!decoded_data)
		return initial_input(fuzz_data, size, max_size);
	if (decoded_size > max_size)
		return initial_input(fuzz_data, size, max_size);

	/* Mutate the data part of the decoded input. */
	mutated_data = tal_dup_arr(tmpctx, u8, decoded_data, decoded_size,
				   max_size - decoded_size);
	mutated_size = LLVMFuzzerMutate(mutated_data, decoded_size, max_size);
	tal_resize(&mutated_data, mutated_size);

	/* Encode the mutated input. */
	encoded_data = to_bech32_charset(tmpctx, bech32_hrp, mutated_data);
	encoded_size = tal_bytelen(encoded_data) - 1; /* Truncate null byte. */

	if (encoded_size > max_size)
		return initial_input(fuzz_data, size, max_size);

	memcpy(fuzz_data, encoded_data, encoded_size);
	clean_tmpctx();

	return encoded_size;
}

static size_t cross_over_fail(void)
{
	clean_tmpctx();
	return 0;
}

/* A custom cross-over mutator that decodes the bech32 inputs before cross-over
 * mutating them. Like LLVMFuzzerCustomMutator, this enables more efficient
 * fuzzing of bolt12 offers, invoice requests, and invoices. */
size_t LLVMFuzzerCustomCrossOver(const u8 *data1, size_t size1, const u8 *data2,
				 size_t size2, u8 *out, size_t max_size,
				 unsigned seed)
{
	const u8 *decoded_data1, *decoded_data2;
	size_t decoded_size1, decoded_size2;
	u8 *mutated_data;
	size_t mutated_size;
	char *encoded_data;
	size_t encoded_size;
	char *fail;

	/* Decode inputs. */
	decoded_data1 = string_to_data(tmpctx, (char *)data1, size1, bech32_hrp,
				       &decoded_size1, &fail);
	if (!decoded_data1)
		return cross_over_fail();
	decoded_data2 = string_to_data(tmpctx, (char *)data2, size2, bech32_hrp,
				       &decoded_size2, &fail);
	if (!decoded_data2)
		return cross_over_fail();

	/* Cross-pollinate inputs. */
	mutated_data = tal_arr(tmpctx, u8, max_size);
	mutated_size = cross_over(decoded_data1, decoded_size1, decoded_data2,
				  decoded_size2, mutated_data, max_size, seed);
	tal_resize(&mutated_data, mutated_size);

	/* Encode the mutated input. */
	encoded_data = to_bech32_charset(tmpctx, bech32_hrp, mutated_data);
	encoded_size = tal_bytelen(encoded_data) - 1; /* Truncate null byte. */

	if (encoded_size > max_size)
		return cross_over_fail();

	memcpy(out, encoded_data, encoded_size);
	clean_tmpctx();

	return encoded_size;
}

void init(int *argc, char ***argv) { common_setup("fuzzer"); }

#endif /* LIGHTNING_TESTS_FUZZ_BOLT12_H */
