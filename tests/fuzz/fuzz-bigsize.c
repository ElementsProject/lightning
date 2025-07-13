#include "config.h"
#include <assert.h>

#include <common/bigsize.h>
#include <tests/fuzz/libfuzz.h>

void init(int *argc, char ***argv)
{
}

void run(const uint8_t *data, size_t size)
{
	uint8_t *wire_buff, buff[BIGSIZE_MAX_LEN];
	const uint8_t **wire_chunks, *wire_ptr;
	size_t wire_max;

	for (size_t chunk_size = 1; chunk_size <= BIGSIZE_MAX_LEN; chunk_size++) {
		wire_chunks = get_chunks(NULL, data, size, chunk_size);
		for (size_t i = 0; i < tal_count(wire_chunks); i++) {
			wire_max = tal_count(wire_chunks[i]);
			wire_ptr = wire_chunks[i];

			bigsize_t bs = fromwire_bigsize(&wire_ptr, &wire_max), bs_decoded;
			assert(bigsize_put(buff, bs) > 0);
			assert(bigsize_len(bs));
			assert(bigsize_get(buff, sizeof(buff), &bs_decoded) == bigsize_len(bs));
			assert(bs_decoded == bs);

			wire_buff = tal_arr(NULL, uint8_t, 8);
			towire_bigsize(&wire_buff, bs);
			tal_free(wire_buff);
		}
		tal_free(wire_chunks);
	}
}
