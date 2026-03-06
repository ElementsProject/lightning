#include "config.h"

#include <assert.h>
#include <ccan/mem/mem.h>
#include <common/addr.h>
#include <common/setup.h>
#include <common/utils.h>
#include <tests/fuzz/libfuzz.h>

void init(int *argc, char ***argv)
{
	chainparams = chainparams_for_network("bitcoin");
	/* Don't call this if we're in unit-test mode, as libfuzz.c does it */
	if (!tmpctx)
		common_setup("fuzzer");
}

void run(const uint8_t *data, size_t size)
{
	char *addr = encode_scriptpubkey_to_addr(tmpctx, chainparams, data, size);
	if (addr) {
		uint8_t *decoded_script_pubkey;
		assert(decode_scriptpubkey_from_addr(tmpctx, chainparams, addr, &decoded_script_pubkey));
		assert(memeq(data, size, decoded_script_pubkey, tal_bytelen(decoded_script_pubkey)));
	}

	clean_tmpctx();
}
