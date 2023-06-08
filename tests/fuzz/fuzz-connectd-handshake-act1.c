/* This is a fuzz test for Act 1 of the BOLT 8 handshake. We intercept io_read()
 * to inject the fuzzer-generated Act 1 packet in the handshake.
 *
 * The expected sequence of events for this test is:
 *   1. responder calls io_read() for the Act 1 packet
 *     - we inject the fuzzer-generated packet
 *   2. responder fails to validate the packet
 */
#include "config.h"
#include <assert.h>
#include <ccan/io/io.h>
#include <common/utils.h>
#include <tests/fuzz/connectd_handshake.h>
#include <tests/fuzz/libfuzz.h>

/* The io_write() interceptor.
 *
 * The handshake should fail during Act 1 packet validation, so this should
 * never be called. */
static struct io_plan *
test_write(struct io_conn *conn, const void *data, size_t len,
	   struct io_plan *(*next)(struct io_conn *, struct handshake *),
	   struct handshake *h)
{
	assert(false && "unexpected call to io_write()");
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
