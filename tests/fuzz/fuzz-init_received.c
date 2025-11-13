/* This is a fuzz test for `peer_init_received()`, which is responsible for
 * handling  BOLT #1 `init` messages. All this test essentially does in encode
 * the fuzzer's input as the payload for a cryptographically valid 'init'
 * message and pass it to this handler.
 */
#include "config.h"
#include <ccan/ccan/io/io.h>
#include <ccan/ccan/str/hex/hex.h>
#include <common/setup.h>
#include <common/utils.h>
#include <fcntl.h>
#include <tests/fuzz/libfuzz.h>

static struct io_plan *test_write(struct io_conn *conn, const void *data,
	size_t len, struct io_plan *(*next)(struct io_conn *, void *), void *arg);

static struct io_plan *test_read(struct io_conn *conn, void *data, size_t len,
	struct io_plan *(*next)(struct io_conn *, void *), void *arg);

#undef io_write
#define io_write(conn, data, len, cb, cb_arg)					\
	test_write((conn),                                                      \
		(data),                                                         \
		(len),                                                          \
		(struct io_plan *(*)(struct io_conn *, void *))(cb),            \
		(void *)(cb_arg))

#undef io_read
#define io_read(conn, data, len, cb, cb_arg)					\
	test_read((conn),							\
		(data),                                                         \
		(len),                                                          \
		(struct io_plan *(*)(struct io_conn *, void *))(cb),            \
		(void *)(cb_arg))

  #include "../../connectd/peer_exchange_initmsg.c"

/* MOCKS START */
bool address_routable(const struct wireaddr *wireaddr UNNEEDED,
		      bool allow_localhost UNNEEDED)
{ return false; }
struct io_plan *peer_connected(struct io_conn *conn UNNEEDED,
			       struct daemon *daemon UNNEEDED,
			       const struct node_id *id UNNEEDED,
			       const struct wireaddr_internal *addr UNNEEDED,
			       const struct wireaddr *remote_addr UNNEEDED,
			       struct crypto_state *cs UNNEEDED,
			       const u8 *their_features TAKES UNNEEDED,
			       enum is_websocket is_websocket UNNEEDED,
			       struct timemono starttime,
			       bool incoming UNNEEDED)
{	if (taken(their_features))
		tal_steal(tmpctx, their_features);
	return io_close(conn);
}
/* MOCKS END */

/* These functions are only called when `peer_init_received()`
 * enounters an error or an unknown message. Simply return
 * when that happens.
 */
static struct io_plan *
test_write(struct io_conn *conn, const void *data, size_t len,
	struct io_plan *(*next)(struct io_conn *, void *), void *arg)
{
	return io_close(conn);
}

static struct io_plan *
test_read(struct io_conn *conn, void *data, size_t len,
	struct io_plan *(*next)(struct io_conn *, void *), void *arg)
{
    return io_close(conn);
}

static struct secret secret_from_hex(const char *hex)
{
	struct secret secret;
	hex += 2;
	if (!hex_decode(hex, strlen(hex), &secret, sizeof(secret)))
		abort();
	return secret;
}

/* Encodes the given message. Stores the decrypting crypto_state in `cs`. */
static u8 *encode_msg(const tal_t *ctx, const void *message, size_t size, struct crypto_state *cs)
{
	struct crypto_state cs_out, cs_in;
	struct secret sk, rk, ck;
	u16 len;

	void *msg = tal_dup_arr(ctx, char, message, size, 0);

	ck = secret_from_hex("0x919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01");
	sk = secret_from_hex("0x969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9");
	rk = secret_from_hex("0xbb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442");

	cs_out.sn = cs_out.rn = cs_in.sn = cs_in.rn = 0;
	cs_out.sk = cs_in.rk = sk;
	cs_out.rk = cs_in.sk = rk;
	cs_out.s_ck = cs_out.r_ck = cs_in.s_ck = cs_in.r_ck = ck;

	u8 *encoded_msg = cryptomsg_encrypt_msg(ctx, &cs_out, msg);

	if (!cryptomsg_decrypt_header(&cs_in, encoded_msg, &len))
			abort();

	/* Trim header */
	memmove(encoded_msg, encoded_msg + CRYPTOMSG_HDR_SIZE,
			tal_bytelen(encoded_msg) - CRYPTOMSG_HDR_SIZE);
	tal_resize(&encoded_msg, tal_bytelen(encoded_msg) - CRYPTOMSG_HDR_SIZE);

	*cs = cs_in;
	return encoded_msg;
}

static struct io_plan *do_nothing(struct io_conn *conn, void *side)
{
	return io_close(conn);
}

void init(int *argc, char ***argv)
{
	chainparams = chainparams_for_network("bitcoin");
	/* Don't call this if we're in unit-test mode, as libfuzz.c does it */
	if (!tmpctx)
		common_setup("fuzzer");
	int devnull = open("/dev/null", O_WRONLY);
	status_setup_sync(devnull);
	dev_towire_allow_invalid_node_id = true;
}

void run(const uint8_t *data, size_t size)
{
	struct io_conn *conn;
	struct crypto_state cs;
	struct early_peer *peer;
	u8 *encoded_msg;
	const struct node_id id = {{
		02,
		00, 00, 00, 00,
		00, 00, 00, 00,
		00, 00, 00, 00,
		00, 00, 00, 00,
		00, 00, 00, 00,
		00, 00, 00, 00,
		00, 00, 00, 00,
		00, 00, 00, 00 }};

	encoded_msg = encode_msg(tmpctx, data, size, &cs);
	peer = tal(tmpctx, struct early_peer);
	peer->cs = cs;
	peer->msg = encoded_msg;
	peer->incoming = true;
	peer->daemon = talz(tmpctx, struct daemon);
	peer->timeout = NULL;
	peer->id = id;

	conn = io_new_conn(tmpctx, -1, do_nothing, NULL);
	peer_init_received(conn, peer);

	clean_tmpctx();
}
