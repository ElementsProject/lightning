/* This is a fuzz test for our message encryption and decryption functions from
 * common/cryptomsg.c. The fuzz test is based on the unit test at
 * common/test/run-cryptomsg.c.
 */
#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <common/cryptomsg.h>
#include <common/setup.h>
#include <common/utils.h>
#include <tests/fuzz/libfuzz.h>

/* Initial crypto states for each fuzz iteration. These are constant after
 * init() is called. */
static struct crypto_state init_cs_out, init_cs_in;

static struct secret secret_from_hex(const char *hex)
{
	struct secret secret;
	hex += 2;
	if (!hex_decode(hex, strlen(hex), &secret, sizeof(secret)))
		abort();
	return secret;
}

void init(int *argc, char ***argv)
{
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
	struct secret sk = secret_from_hex("0x969ab31b4d288cedf6218839b27a3e214"
					   "0827047f2c0f01bf5c04435d43511a9");
	struct secret rk = secret_from_hex("0xbb9020b8965f4df047e07f955f3c4b884"
					   "18984aadc5cdb35096b9ea8fa5c3442");
	struct secret ck = secret_from_hex("0x919219dbb2920afa8db80f9a51787a840"
					   "bcf111ed8d588caf9ab4be716e42b01");

	init_cs_out.sk = sk;
	init_cs_out.rk = rk;
	init_cs_out.s_ck = ck;
	init_cs_out.r_ck = ck;

	init_cs_in.sk = rk;
	init_cs_in.rk = sk;
	init_cs_in.s_ck = ck;
	init_cs_in.r_ck = ck;

	common_setup("fuzzer");
}

/* Test that encrypting and decrypting the message does not alter it. */
static void test_encrypt_decrypt_equality(const u8 *msg)
{
	struct crypto_state cs_out = init_cs_out;
	struct crypto_state cs_in = init_cs_in;
	u8 *dec, *enc;
	u16 len;

	enc = cryptomsg_encrypt_msg(msg, &cs_out, msg);

	assert(cryptomsg_decrypt_header(&cs_in, enc, &len));

	/* Trim header. */
	memmove(enc, enc + CRYPTOMSG_HDR_SIZE,
		tal_bytelen(enc) - CRYPTOMSG_HDR_SIZE);
	tal_resize(&enc, tal_bytelen(enc) - CRYPTOMSG_HDR_SIZE);

	dec = cryptomsg_decrypt_body(msg, &cs_in, enc);
	assert(tal_arr_eq(dec, msg));
}

/* Test header decryption of arbitrary bytes (should always fail). */
static void test_decrypt_header(const u8 *buf)
{
	struct crypto_state cs_in = init_cs_in;
	u16 len;

	if (tal_bytelen(buf) < CRYPTOMSG_HDR_SIZE)
		return;

	assert(!cryptomsg_decrypt_header(&cs_in, buf, &len));
}

/* Test body decryption of arbitrary bytes (should always fail). */
static void test_decrypt_body(const u8 *buf)
{
	struct crypto_state cs_in = init_cs_in;

	assert(cryptomsg_decrypt_body(buf, &cs_in, buf) == NULL);
}

void run(const u8 *data, size_t size)
{
	const u8 *buf = tal_dup_arr(NULL, u8, data, size, 0);

	test_encrypt_decrypt_equality(buf);
	test_decrypt_header(buf);
	test_decrypt_body(buf);

	tal_free(buf);
}
