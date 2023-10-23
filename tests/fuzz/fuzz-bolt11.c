#include "config.h"

#include <bitcoin/chainparams.h>
#include <common/bech32.h>
#include <common/bolt11.h>
#include <common/features.h>
#include <common/setup.h>
#include <common/utils.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tests/fuzz/libfuzz.h>

// Default mutator defined by libFuzzer.
size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);
size_t LLVMFuzzerCustomMutator(uint8_t *fuzz_data, size_t size, size_t max_size,
			       unsigned int seed);
size_t LLVMFuzzerCustomCrossOver(const u8 *in1, size_t in1_size, const u8 *in2,
				 size_t in2_size, u8 *out, size_t max_out_size,
				 unsigned seed);

void init(int *argc, char ***argv) { common_setup("fuzzer"); }

// Encodes a dummy bolt11 invoice into `fuzz_data` and returns the size of the
// encoded string.
static size_t initial_input(uint8_t *fuzz_data, size_t size, size_t max_size)
{
	// Dummy invoice was created by encoding a default initialized `struct
	// bolt11`.
	const char dummy[] =
	    "lnbc16lta047pp5h6lta047h6lta047h6lta047h6lta047h6lta047h6lta047"
	    "h6lqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
	    "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqxnht6w";

	const size_t dummy_len = sizeof(dummy) - 1;
	size = max_size < dummy_len ? max_size : dummy_len;
	memcpy(fuzz_data, dummy, size);

	clean_tmpctx();
	return size;
}

// We use a custom mutator to produce an input corpus that consists entirely of
// correctly encoded bech32 strings. This enables us to efficiently fuzz the
// bolt11 decoding logic without the fuzzer getting stuck on fuzzing the bech32
// decoding/encoding logic.
//
// This custom mutator does the following things:
//   1. Attempt to bech32 decode the given input (returns the encoded dummy
//      invoice on failure).
//   2. Mutate either the human readable or data part of the invoice using
//      libFuzzer's default mutator `LLVMFuzzerMutate`.
//   3. Attempt to bech32 encode the mutated hrp and data (returns the endcoded
//      dummy on failure).
//   4. Write the encoded result to `fuzz_data` if its size does not exceed
//      `max_size`, otherwise return the encoded dummy invoice.
size_t LLVMFuzzerCustomMutator(uint8_t *fuzz_data, size_t size, size_t max_size,
			       unsigned int seed)
{
	// A minimum size of 9 prevents hrp_maxlen <= 0 and data_maxlen <= 0.
	if (size < 9)
		return initial_input(fuzz_data, size, max_size);

	// Interpret fuzz input as string (ensure it's null terminated).
	char *input = to_string(tmpctx, fuzz_data, size);

	// Attempt to bech32 decode the input.
	size_t hrp_maxlen = strlen(input) - 6;
	char *hrp = tal_arr(tmpctx, char, hrp_maxlen);
	size_t data_maxlen = strlen(input) - 8;
	u5 *data = tal_arr(tmpctx, u5, data_maxlen);
	size_t datalen = 0;
	if (bech32_decode(hrp, data, &datalen, input, (size_t)-1) !=
	    BECH32_ENCODING_BECH32) {
		// Decoding failed, this should only happen when starting from
		// an empty corpus.
		return initial_input(fuzz_data, size, max_size);
	}

	// Mutate either the hrp or data. Given the same seed, the same
	// mutation is performed.
	srand(seed);
	switch (rand() % 2) {
	case 0: { // Mutate hrp and ensure it's still null terminated.
		size_t new_len = LLVMFuzzerMutate((uint8_t *)hrp, strlen(hrp),
						  hrp_maxlen - 1);
		hrp[new_len] = '\0';
		break;
	}
	case 1: // Mutate data and re-assign datalen.
		datalen =
		    LLVMFuzzerMutate((uint8_t *)data, datalen, data_maxlen);
		break;
	}

	// Encode the mutated input.
	char *output = tal_arr(tmpctx, char, strlen(hrp) + datalen + 8);
	if (!bech32_encode(output, hrp, data, datalen, (size_t)-1,
			   BECH32_ENCODING_BECH32)) {
		return initial_input(fuzz_data, size, max_size);
	}

	// Write the result into `fuzz_data`.
	size_t output_len = strlen(output);
	if (output_len > max_size)
		return initial_input(fuzz_data, size, max_size);

	memcpy(fuzz_data, output, output_len);
	clean_tmpctx();
	return output_len;
}

size_t LLVMFuzzerCustomCrossOver(const u8 *in1, size_t in1_size, const u8 *in2,
				 size_t in2_size, u8 *out, size_t max_out_size,
				 unsigned seed)
{
	if (in1_size < 9 || in2_size < 9)
		return 0;

	// Interpret fuzz inputs as string (ensure it's null terminated).
	char *input1 = to_string(tmpctx, in1, in1_size);
	char *input2 = to_string(tmpctx, in2, in2_size);

	const size_t max_hrp1 = strlen(input1) - 6;
	const size_t max_hrp2 = strlen(input2) - 6;
	const size_t max_data1 = max_hrp1 - 2;
	const size_t max_data2 = max_hrp2 - 2;

	// Attempt to bech32 decode the inputs.
	char *hrp1 = tal_arr(tmpctx, char, max_hrp1);
	char *hrp2 = tal_arr(tmpctx, char, max_hrp2);
	u5 *data1 = tal_arr(tmpctx, u5, max_data1);
	u5 *data2 = tal_arr(tmpctx, u5, max_data2);

	size_t data1_len = 0;
	if (bech32_decode(hrp1, data1, &data1_len, input1, (size_t)-1) !=
	    BECH32_ENCODING_BECH32)
		// Decoding failed, this should only happen when starting from
		// an empty corpus.
		return 0;
	size_t data2_len = 0;
	if (bech32_decode(hrp2, data2, &data2_len, input2, (size_t)-1) !=
	    BECH32_ENCODING_BECH32)
		// Decoding failed, this should only happen when starting from
		// an empty corpus.
		return 0;

	srand(seed);
	char *out_hrp;
	u5 *out_data;
	size_t out_data_len;
	if (rand() % 2) {
		// Cross-over the HRP.
		out_data = data1;
		out_data_len = data1_len;

		size_t max_out_hrp_size = max_out_size - data1_len - 8;
		out_hrp = tal_arr(tmpctx, char, max_out_hrp_size + 1);

		size_t out_hrp_size = cross_over(
		    (u8 *)hrp1, strlen(hrp1), (u8 *)hrp2, strlen(hrp2),
		    (u8 *)out_hrp, max_out_hrp_size, (unsigned)rand());
		out_hrp[out_hrp_size] = '\0';
	} else {
		// Cross-over the data part.
		out_hrp = hrp1;

		size_t max_out_data_size = max_out_size - strlen(hrp1) - 8;
		out_data = tal_arr(tmpctx, u5, max_out_data_size);

		out_data_len =
		    cross_over(data1, data1_len, data2, data2_len, out_data,
			       max_out_data_size, (unsigned)rand());
	}

	// Encode the output.
	if (!bech32_encode((char *)out, out_hrp, out_data, out_data_len,
			   max_out_size, BECH32_ENCODING_BECH32))
		return 0;

	clean_tmpctx();
	return strlen((char *)out);
}

void run(const uint8_t *data, size_t size)
{
	char *invoice_str = to_string(tmpctx, data, size);
	char *fail;

	bolt11_decode(tmpctx, invoice_str, NULL, NULL, NULL, &fail);

	clean_tmpctx();
}
