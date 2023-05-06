#include "config.h"
#include <assert.h>

#include <common/bech32.h>
#include <stdint.h>
#include <string.h>
#include <tests/fuzz/libfuzz.h>

void init(int *argc, char ***argv)
{
}

void run(const uint8_t *data, size_t size)
{
	const char hrp_inv[5] = "lnbc\0", hrp_addr[3] = "bc\0";
	char *bech32_str, *hrp_out, *addr;
	uint8_t *data_out;
	size_t data_out_len, bech32_str_cap;
	int decode_wit_version;
	bech32_encoding benc, benc_decoded;

	if (size < 1)
		return;

	/* Buffer size is defined in each function's doc comment. */
	benc = data[0] ? BECH32_ENCODING_BECH32 : BECH32_ENCODING_BECH32M;
	bech32_str_cap = (size - 1) + strlen(hrp_inv) + 8;
	bech32_str = malloc(bech32_str_cap);
	if (bech32_encode(bech32_str, hrp_inv, data + 1, size - 1,
			  bech32_str_cap, benc) == 1) {
		hrp_out = malloc(strlen(bech32_str) - 6);
		data_out = malloc(strlen(bech32_str) - 8);

		benc_decoded = bech32_decode(hrp_out, data_out, &data_out_len,
					     bech32_str, bech32_str_cap);
		assert(benc_decoded == benc);
		assert(strcmp(hrp_inv, hrp_out) == 0);
		assert(data_out_len == size - 1);
		assert(memcmp(data_out, data + 1, data_out_len) == 0);

		free(hrp_out);
		free(data_out);
	}
	free(bech32_str);

	data_out = malloc(size);

	/* This is also used as part of sign and check message. */
	data_out_len = 0;
	bech32_convert_bits(data_out, &data_out_len, 8, data, size, 5, 1);
	data_out_len = 0;
	bech32_convert_bits(data_out, &data_out_len, 8, data, size, 5, 0);

	addr = malloc(73 + strlen(hrp_addr));
	for (int wit_version = 0; wit_version < 2; ++wit_version) {
		if (segwit_addr_encode(addr, hrp_addr, wit_version, data,
				       size) == 0)
			continue;

		assert(segwit_addr_decode(&decode_wit_version, data_out,
					  &data_out_len, hrp_addr, addr) == 1);
		assert(decode_wit_version == wit_version);
		assert(data_out_len == size);
		assert(memcmp(data_out, data, data_out_len) == 0);
	}
	free(addr);

	free(data_out);
}
