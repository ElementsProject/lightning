/* This is a fuzz test for Act 1 of the BOLT 8 handshake. We intercept io_read()
 * to inject the fuzzer-generated Act 1 packet in the handshake.
 *
 * The expected sequence of events for this test is:
 *   1. responder calls io_read() for the Act 1 packet
 *     - we inject the fuzzer-generated packet
 *   2. if packet is valid, responder calls io_write() with an Act 2 packet
 *     - we fail the handshake
 */
#include "config.h"
#include <assert.h>
#include <ccan/io/io.h>
#include <common/utils.h>
#include <tests/fuzz/connectd_handshake.h>
#include <tests/fuzz/libfuzz.h>

/* The io_write() interceptor.
 *
 * If the fuzzer-generated Act 1 packet was valid, this should be called exactly
 * once. Otherwise it should not be called at all. */
static struct io_plan *
test_write(struct io_conn *conn, const void *data, size_t len,
	   struct io_plan *(*next)(struct io_conn *, struct handshake *),
	   struct handshake *h)
{
	++write_count;
	assert(write_count == 1 && "too many calls to io_write()");

	/* Act 1 packet validation succeeded. Responder is sending the Act 2
	 * packet. Check that it is initialized. */
	assert(len == ACT_TWO_SIZE);
	memcheck(data, len);

	return handshake_failed(conn, h);
}

/* The io_read() interceptor.
 *
 * This should be called exactly once, when the responder is reading the Act 1
 * packet. We inject fuzzer input here. */
static struct io_plan *test_read(struct io_conn *conn, void *data, size_t len,
				 struct io_plan *(*next)(struct io_conn *,
							 struct handshake *),
				 struct handshake *h)
{
	++read_count;
	assert(read_count == 1 && "too many calls to io_read()");

	assert(len == ACT_ONE_SIZE);
	assert(bytes_remaining >= len);
	memcpy(data, bytes, len);
	bytes += len;
	bytes_remaining -= len;

	return next(conn, h);
}

void run(const uint8_t *data, size_t size)
{
	if (size < randombytes_SEEDBYTES + ACT_ONE_SIZE)
		return;

	init_globals(data, size);

	handshake(RESPONDER);

	clean_tmpctx();
}
