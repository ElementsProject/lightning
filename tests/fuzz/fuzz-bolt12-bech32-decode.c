/* A fuzz target for the bolt12-specific bech32 decoding logic. */
#include "config.h"
#include <common/setup.h>
#include <common/utils.h>
#include <stddef.h>
#include <tests/fuzz/libfuzz.h>

/* Include bolt12.c directly, to gain access to string_to_data(). */
#include "../../common/bolt12.c"

void init(int *argc, char ***argv) { common_setup("fuzzer"); }

void run(const u8 *data, size_t size)
{
	size_t dlen;
	char *fail;

	string_to_data(tmpctx, (const char *)data, size, "lno", &dlen, &fail);

	clean_tmpctx();
}
