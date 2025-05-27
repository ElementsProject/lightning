#include "config.h"
#include <common/bolt12.h>
#include <common/utils.h>
#include <wire/wire.h>
#include <tests/fuzz/libfuzz.h>

void init(int *argc, char ***argv)
{}

void run(const u8 *data, size_t size)
{
	size_t span_start_offset, span_size;

	u64 minfield = fromwire_u64(&data, &size);
	u64 maxfield = fromwire_u64(&data, &size);

	const u8 *buf = tal_dup_arr(tmpctx, u8, data, size, 0);
	span_size = tlv_span(buf, minfield, maxfield, &span_start_offset);
	assert(span_start_offset + span_size <= size);

	clean_tmpctx();
}
