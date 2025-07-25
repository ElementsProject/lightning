#include "config.h"
#include <assert.h>
#include <ccan/ccan/tal/str/str.h>
#include <common/utils.h>
#include <common/setup.h>
#include <common/wireaddr.h>
#include <bitcoin/chainparams.h>
#include <tests/fuzz/libfuzz.h>

#define DEFAULT_PORT 9735

void init(int *argc, char ***argv)
{
	common_setup("fuzzer");
	chainparams = chainparams_for_network("bitcoin");
}

void run(const uint8_t *data, size_t size)
{
	char *addr = tal_arr(tmpctx, char, size + 1);
	if (!addr)
		return;
	memcpy(addr, data, size);
	addr[size] = '\0';

	struct wireaddr_internal *wa = tal(tmpctx, struct wireaddr_internal);
	const char *err;

	err = parse_wireaddr_internal(tmpctx, addr, DEFAULT_PORT, NULL, wa);

	if (!err) {
		u8 *output_buffer = tal_arr(tmpctx, u8, 0);
		towire_wireaddr_internal(&output_buffer, wa);
		size_t len = tal_bytelen(output_buffer);

		struct wireaddr_internal *decoded_wa = tal(tmpctx, struct wireaddr_internal);
		assert(fromwire_wireaddr_internal((const u8 **) &output_buffer, &len, decoded_wa));
		assert(wireaddr_internal_eq(wa, decoded_wa));
	}

	clean_tmpctx();
}
