/* This is a fuzz test for Act 2 of the BOLT 8 handshake. We intercept io_read()
 * to inject the fuzzer-generated Act 2 packet in the handshake.
 *
 * The expected sequence of events for this test is:
 *   1. initiator calls io_write() with an Act 1 packet
 *     - we discard the valid Act 1 packet
 *   2. initiator calls io_read() for the Act 2 packet
 *     - we inject the fuzzer-generated packet
 *   3. initiator fails to validate the packet
 */
#include "config.h"
#include <assert.h>
#include <ccan/io/io.h>
#include <ccan/mem/mem.h>
#include <common/utils.h>
#include <tests/fuzz/connectd_handshake.h>
#include <tests/fuzz/libfuzz.h>

/* The io_write() interceptor.
 *
 * This should be called exactly once, when the initiator is writing out its Act
 * 1 packet. We check that the packet is initialized and discard it. */
static struct io_plan *
test_write(struct io_conn *conn, const void *data, size_t len,
	   struct io_plan *(*next)(struct io_conn *, struct handshake *),
	   struct handshake *h)
{
	++write_count;
	assert(write_count == 1 && "too many calls to io_write()");

	assert(len == ACT_ONE_SIZE);
	memcheck(data, len);

	return next(conn, h);
}

/* The io_read() interceptor.
 *
 * This should be called exactly once, when the initiator is reading the Act 2
 * packet. We inject fuzzer input here. */
static struct io_plan *test_read(struct io_conn *conn, void *data, size_t len,
				 struct io_plan *(*next)(struct io_conn *,
							 struct handshake *),
				 struct handshake *h)
{
	++read_count;
	assert(read_count == 1 && "too many calls to io_read()");

	assert(len == ACT_TWO_SIZE);
	assert(bytes_remaining >= len);
	memcpy(data, bytes, len);
	bytes += len;
	bytes_remaining -= len;

	return next(conn, h);
}

void run(const u8 *data, size_t size)
{
	if (size < randombytes_SEEDBYTES + ACT_TWO_SIZE)
		return;

	init_globals(data, size);

	handshake(INITIATOR);

	clean_tmpctx();
}
