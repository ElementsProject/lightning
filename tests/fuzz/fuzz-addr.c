#include "config.h"

#include <assert.h>
#include <common/addr.h>
#include <common/setup.h>
#include <common/utils.h>
#include <tests/fuzz/libfuzz.h>

void init(int *argc, char ***argv)
{
	chainparams = chainparams_for_network("bitcoin");
	common_setup("fuzzer");
}

void run(const uint8_t *data, size_t size)
{
	uint8_t *script_pubkey = tal_dup_arr(tmpctx, uint8_t, data, size, 0);

	char *addr = encode_scriptpubkey_to_addr(tmpctx, chainparams, script_pubkey);
	if (addr) {
		uint8_t *decoded_script_pubkey;
		assert(decode_scriptpubkey_from_addr(tmpctx, chainparams, addr, &decoded_script_pubkey));
		assert(tal_arr_eq(script_pubkey, decoded_script_pubkey));
	}

	clean_tmpctx();
}
