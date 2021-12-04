#include "config.h"
#include "common/utils.h"
#include <tests/fuzz/libfuzz.h>

#include <common/addr.h>
#include <common/setup.h>

void init(int *argc, char ***argv)
{
	chainparams = chainparams_for_network("bitcoin");
	common_setup("fuzzer");
}

void run(const uint8_t *data, size_t size)
{
	uint8_t *script_pubkey = tal_dup_arr(tmpctx, uint8_t, data, size, 0);

	encode_scriptpubkey_to_addr(tmpctx, chainparams, script_pubkey);

	clean_tmpctx();
}
