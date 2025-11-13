#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <ccan/ccan/tal/str/str.h>
#include <common/setup.h>
#include <common/utils.h>
#include <common/wireaddr.h>
#include <tests/fuzz/libfuzz.h>

#define DEFAULT_PORT 9735

void init(int *argc, char ***argv)
{
	/* Don't call this if we're in unit-test mode, as libfuzz.c does it */
	if (!tmpctx)
		common_setup("fuzzer");
	chainparams = chainparams_for_network("bitcoin");
}

void run(const uint8_t *data, size_t size)
{
	char *addr = to_string(tmpctx, data, size);

	struct wireaddr wa, decoded_wa;
	const char *err;

	err = parse_wireaddr(tmpctx, addr, DEFAULT_PORT, NULL, &wa);

	if (!err) {
		assert(fmt_wireaddr(tmpctx, &wa));

		u8 *output_buffer = tal_arr(tmpctx, u8, 0);
		towire_wireaddr(&output_buffer, &wa);
		size_t len = tal_bytelen(output_buffer);

		assert(fromwire_wireaddr((const u8 **)&output_buffer, &len,
					 &decoded_wa));
		assert(wireaddr_eq(&wa, &decoded_wa));
	}

	clean_tmpctx();
}
