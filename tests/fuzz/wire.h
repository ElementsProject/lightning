/* Helper functions used by all the fuzz-wire-* targets. Each target needs to
 * implement encode(), decode(), and equal() for its message type. It can then
 * use the test_decode_encode() macro to run the fuzz test.
 */
#ifndef LIGHTNING_TESTS_FUZZ_WIRE_H
#define LIGHTNING_TESTS_FUZZ_WIRE_H

#include "config.h"
#include <assert.h>
#include <common/setup.h>

#include <tests/fuzz/libfuzz.h>
#include <wire/peer_wire.h>

static u8 *prefix_arr(const u8 *data, size_t size, u16 prefix)
{
	u8 *p = tal_arr(NULL, u8, 0);
	towire_u16(&p, prefix);
	towire(&p, data, size);
	return p;
}

/* The init function used by all fuzz-wire-* targets. */
void init(int *argc, char ***argv) { common_setup("fuzzer"); }

/* Test that decoding arbitrary data does not crash. Then, if the data was
 * successfully decoded, test that encoding and decoding the message does not
 * alter it. */
#define test_decode_encode(data, size, prefix, msgtype)                        \
	do {                                                                   \
		const u8 *buf = prefix_arr(data, size, prefix);                \
		msgtype *decoded1, *decoded2;                                  \
		void *encoded;                                                 \
		do {                                                           \
			decoded1 = decode(buf, buf);                           \
			if (!decoded1)                                         \
				break;                                         \
                                                                               \
			encoded = encode(buf, decoded1);                       \
			assert(encoded && "failed to re-encode message");      \
                                                                               \
			decoded2 = decode(buf, encoded);                       \
			assert(decoded2 && "failed to re-decode message");     \
                                                                               \
			assert(equal(decoded1, decoded2));                     \
		} while (0);                                                   \
                                                                               \
		tal_free(buf);                                                 \
	} while (0)

#endif /* LIGHTNING_TESTS_FUZZ_WIRE_H */
