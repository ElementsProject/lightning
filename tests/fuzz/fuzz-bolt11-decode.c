#include "config.h"
#include <assert.h>

#include <common/bolt11.h>
#include <common/setup.h>
#include <common/utils.h>
#include <stdio.h>
#include <string.h>
#include <tests/fuzz/libfuzz.h>

void init(int *argc, char ***argv) { common_setup("fuzzer"); }

void run(const u8 *data, size_t size)
{
	char *str = tal_arr(NULL, char, size + 1);
	char *fail_reason;

	memcpy(str, data, size);
	str[size] = '\0';

	bolt11_decode(str, str, /*our_features=*/NULL, /*description=*/NULL,
		      /*must_be_chain=*/NULL, &fail_reason);

	clean_tmpctx();
	tal_free(str);
}
