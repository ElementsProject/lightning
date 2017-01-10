#include <assert.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <status.h>
#include <stdio.h>
#include <wire/wire_io.h>

#undef io_read
#undef io_write

static char *read_buf;
static size_t read_buf_len;

static void do_read(void *buf, size_t len)
{
	assert(len <= read_buf_len);
	memcpy(buf, read_buf, len);
	read_buf += len;
	read_buf_len -= len;
}

#define io_read(conn, p, len, next, arg)			\
	(do_read((p), (len)), (next)((conn), (arg)), NULL)

static char *write_buf;

static void do_write(const void *buf, size_t len)
{
	size_t oldlen = tal_count(write_buf);
	tal_resize(&write_buf, oldlen + len);
	memcpy(write_buf + oldlen, buf, len);
}

#define io_write(conn, p, len, next, arg) \
	(do_write((p), (len)), (next)((conn), (arg)), NULL)

#define status_trace(fmt, ...) \
	printf(fmt "\n", __VA_ARGS__)

#include "../cryptomsg.c"

const void *trc;

static struct io_plan *check_msg_write(struct io_conn *conn, struct peer *peer)
{
	assert(tal_count(write_buf) == 2 + 16 + 5 + 16);
	return NULL;
}

static struct io_plan *check_msg_read(struct io_conn *conn, struct peer *peer,
				      u8 *msg)
{
	assert(tal_count(msg) == 5);
	assert(memcmp(msg, "hello", 5) == 0);
	return NULL;
}

static struct sha256 sha256_from_hex(const char *hex)
{
	struct sha256 sha256;
	hex += 2;
	if (!hex_decode(hex, strlen(hex), &sha256, sizeof(sha256)))
		abort();
	return sha256;
}

int main(void)
{
	tal_t *tmpctx = tal_tmpctx(NULL);
	struct crypto_state *cs_out, *cs_in;
	struct sha256 sk, rk, ck;
	const void *msg = tal_dup_arr(tmpctx, char, "hello", 5, 0);
	size_t i;

	trc = tal_tmpctx(tmpctx);

	/* BOLT #8:
	 *
	 * name: transport-initiator successful handshake
	 *...
	 * # ck,temp_k3=0x919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01,0x981a46c820fb7a241bc8184ba4bb1f01bcdfafb00dde80098cb8c38db9141520
	 * # encryptWithAD(0x981a46c820fb7a241bc8184ba4bb1f01bcdfafb00dde80098cb8c38db9141520, 0x000000000000000000000000, 0x5dcb5ea9b4ccc755e0e3456af3990641276e1d5dc9afd82f974d90a47c918660, <empty>)
	 * # t=0x8dc68b1c466263b47fdf31e560e139ba
	 * output: 0x00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba
	 * # HKDF(0x919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01,zero)
	 * output: sk,rk=0x969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9,0xbb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442
	 */
	ck = sha256_from_hex("0x919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01");
	sk = sha256_from_hex("0x969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9");
	rk = sha256_from_hex("0xbb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442");

	cs_out = crypto_state(tmpctx, &sk, &rk, &ck, &ck, 0, 0);
	cs_in = crypto_state(tmpctx, &rk, &sk, &ck, &ck, 0, 0);

	for (i = 0; i < 1002; i++) {
		write_buf = tal_arr(tmpctx, char, 0);

		peer_write_message(NULL, cs_out, msg, check_msg_write);
		if ((i % 500) < 2)
			status_trace("output %zu: 0x%s", i,
				     tal_hex(tmpctx, write_buf));

		read_buf = write_buf;
		read_buf_len = tal_count(read_buf);
		write_buf = tal_arr(tmpctx, char, 0);

		peer_read_message(NULL, cs_in, check_msg_read);
		assert(read_buf_len == 0);
	}
	tal_free(tmpctx);
	return 0;
}
