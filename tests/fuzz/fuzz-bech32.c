#include "config.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <tests/fuzz/libfuzz.h>

#include <common/bech32.h>

void init(int *argc, char ***argv)
{
}

void run(const uint8_t *data, size_t size)
{
	const char hrp_inv[5] = "lnbc\0", hrp_addr[3] = "bc\0";
	char *bech32_str, *hrp_out, *addr;
	uint8_t *data_out;
	size_t data_out_len;
	int wit_version;
	bech32_encoding benc;

	/* Buffer size is defined in each function's doc comment. */
	bech32_str = malloc(size + strlen(hrp_inv) + 8);
	benc = data[0] ? BECH32_ENCODING_BECH32 : BECH32_ENCODING_BECH32M;
	/* FIXME: needs a dictionary / a startup seed corpus to pass this more
	 * frequently. */
	if (bech32_encode(bech32_str, hrp_inv, data+1, size-1, size-1, benc) == 1) {
		hrp_out = malloc(strlen(bech32_str) - 6);
		data_out = malloc(strlen(bech32_str) - 8);
		assert(bech32_decode(hrp_out, data_out, &data_out_len, bech32_str, size) == benc);
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
	wit_version = 0;
	if (segwit_addr_encode(addr, hrp_addr, wit_version, data, size) == 1)
		segwit_addr_decode(&wit_version, data_out, &data_out_len, hrp_addr, addr);
	wit_version = 1;
	if (segwit_addr_encode(addr, hrp_addr, wit_version, data, size) == 1)
		segwit_addr_decode(&wit_version, data_out, &data_out_len, hrp_addr, addr);
	free(addr);

	free(data_out);
}
