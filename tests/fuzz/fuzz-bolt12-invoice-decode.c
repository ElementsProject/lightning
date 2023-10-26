#include "config.h"
#include <common/bolt12.h>
#include <common/utils.h>
#include <stddef.h>
#include <tests/fuzz/bolt12.h>
#include <tests/fuzz/libfuzz.h>

const char *bech32_hrp = "lni";

void run(const u8 *data, size_t size)
{
	char *fail;

	invoice_decode(tmpctx, (const char *)data, size, /*feature_set=*/NULL,
		       /*must_be_chain=*/NULL, &fail);

	clean_tmpctx();
}
