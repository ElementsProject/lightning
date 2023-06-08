/* This header contains globals and helper functions used by all the
 * fuzz-connectd-handshake-act* fuzz targets. It also takes care of intercepting
 * io_read(), io_write(), and randombytes_buf(), so that the actual fuzz targets
 * only need to implement the test_read() and test_write() interceptors and the
 * run() function.
 */
#ifndef LIGHTNING_TESTS_FUZZ_CONNECTD_HANDSHAKE_H
#define LIGHTNING_TESTS_FUZZ_CONNECTD_HANDSHAKE_H

#include "config.h"
#include <assert.h>
#include <ccan/io/io.h>
#include <ccan/str/hex/hex.h>
#include <common/setup.h>
#include <common/status.h>
#include <common/wireaddr.h>
#include <fcntl.h>
#include <tests/fuzz/libfuzz.h>

/* No randomness please, we want to replicate test vectors. */
#include <sodium/randombytes.h>

static void seeded_randombytes_buf(u8 *secret, size_t len);
#define randombytes_buf(secret, len) seeded_randombytes_buf((secret), (len))

struct handshake;

static struct io_plan *
test_write(struct io_conn *conn, const void *data, size_t len,
	   struct io_plan *(*next)(struct io_conn *, struct handshake *),
	   struct handshake *h);

static struct io_plan *test_read(struct io_conn *conn, void *data, size_t len,
				 struct io_plan *(*next)(struct io_conn *,
							 struct handshake *),
				 struct handshake *h);

#undef io_write
#define io_write(conn, data, len, cb, cb_arg)                                  \
	test_write((conn), (data), (len), (cb), (cb_arg))

#undef io_read
#define io_read(conn, data, len, cb, cb_arg)                                   \
	test_read((conn), (data), (len), (cb), (cb_arg))

/* Include handshake.c directly, so we can intercept io_write and io_read. */
#include "../../connectd/handshake.c"

static struct pubkey init_pub, resp_pub;
static struct privkey init_priv, resp_priv;
static const u8 *bytes;
static size_t bytes_remaining;
static int read_count, write_count, ecdh_count;
static u8 seed[randombytes_SEEDBYTES];

static struct pubkey pubkey(const char *str)
{
	struct pubkey p;
	assert(pubkey_from_hexstr(str, strlen(str), &p));
	return p;
}

static struct privkey privkey(const char *str)
{
	struct privkey p;
	assert(hex_decode(str, strlen(str), &p, sizeof(p)));
	return p;
}

/* The init function used by all fuzz-connectd-handshake-act* targets. */
void init(int *argc, char ***argv)
{
	int devnull = open("/dev/null", O_WRONLY);
	assert(devnull >= 0);
	status_setup_sync(devnull);

	common_setup("fuzzer");

	/* These keys are copied from BOLT 8 test vectors, though we use them in
	 * a different setting.
	 *
	 * BOLT #8:
	 *
	 *    name: transport-responder successful handshake
	 *    ls.priv=2121212121212121212121212121212121212121212121212121212121212121
	 *    ls.pub=028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7
	 *    e.priv=0x2222222222222222222222222222222222222222222222222222222222222222
	 *    e.pub=0x02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27
	 */
	init_priv = privkey(
	    "2121212121212121212121212121212121212121212121212121212121212121");
	init_pub = pubkey("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa6"
			  "12b469132ec7f7");
	resp_priv = privkey(
	    "2222222222222222222222222222222222222222222222222222222222222222");
	resp_pub = pubkey("02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf"
			  "22285f1bae3f27");
}

/* This function should be called at the start of each fuzz iteration to reset
 * globals to their initial values. */
static void init_globals(const u8 *data, size_t size)
{
	bytes = data;
	bytes_remaining = size;

	read_count = 0;
	write_count = 0;
	ecdh_count = 0;

	/* Seed the RNG with fuzzer input. */
	assert(bytes_remaining >= randombytes_SEEDBYTES);
	memcpy(seed, bytes, randombytes_SEEDBYTES);
	bytes += randombytes_SEEDBYTES;
	bytes_remaining -= randombytes_SEEDBYTES;
}

/* Replaces randombytes_buf with randomness generated deterministically from
 * the fuzzer-generated seed. */
static void seeded_randombytes_buf(u8 *secret, size_t len)
{
	randombytes_buf_deterministic(secret, len, seed);

	/* Use the latest random bytes as seed for the next call. */
	assert(len >= randombytes_SEEDBYTES);
	memcpy(seed, secret, randombytes_SEEDBYTES);
}

extern secp256k1_context *secp256k1_ctx;

/* An interceptor that performs ECDH using the responder's private key. This is
 * expected to be called exactly once, by the responder, during Act 1. */
void ecdh(const struct pubkey *point, struct secret *ss)
{
	++ecdh_count;
	assert(ecdh_count == 1 && "too many calls to ecdh()");

	assert(secp256k1_ecdh(secp256k1_ctx, ss->data, &point->pubkey,
			      resp_priv.secret.data, NULL, NULL) == 1);
}

/* A dummy function to call on handshake success. It should never be called
 * since the fuzzer should not be able to brute force a valid handshake. */
static struct io_plan *
success(struct io_conn *conn UNUSED, const struct pubkey *them UNUSED,
	const struct wireaddr_internal *addr UNUSED, struct crypto_state *cs,
	struct oneshot *timeout UNUSED, enum is_websocket is_websocket UNUSED,
	void *unused UNUSED)
{
	assert(false && "handshake unexpectedly succeeded");
}

static struct io_plan *do_handshake(struct io_conn *conn, void *side)
{
	struct wireaddr_internal dummy;
	dummy.itype = ADDR_INTERNAL_WIREADDR;
	dummy.u.wireaddr.wireaddr.addrlen = 0;

	if (side == (void *)RESPONDER)
		return responder_handshake(conn, &resp_pub, &dummy, NULL,
					   NORMAL_SOCKET, success, NULL);

	return initiator_handshake(conn, &init_pub, &resp_pub, &dummy, NULL,
				   NORMAL_SOCKET, success, NULL);
}

/* Attempts to do the indicated side of the handshake, using the test_read and
 * test_write interceptors implemented by the fuzz target. The handshake is
 * expected to always fail since the fuzzer should not be able to brute force a
 * valid handshake. */
static void handshake(enum bolt8_side side)
{
	struct io_conn *conn =
	    io_new_conn(tmpctx, -1, do_handshake, (void *)side);
	assert(!conn && "handshake unexpectedly succeeded");
}

#endif /* LIGHTNING_TESTS_FUZZ_CONNECTD_HANDSHAKE_H */
