#include <assert.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/structeq/structeq.h>
#include <lightningd/status.h>

/* Since we use pipes, we need different fds for read and write. */
static int read_fd, write_fd;

static bool fake_read_all(int fd, void *buf, size_t count)
{
	return read_all(read_fd, buf, count);
}

static ssize_t fake_write_all(int fd, const void *buf, size_t count)
{
	return write_all(write_fd, buf, count);
}

static const char *status_prefix;

/* Simply print out status updates. */
#define status_send_sync(msg)			\
	printf("%s:# Act %s\n", status_prefix,	\
	       fromwire_peektype(msg) == WIRE_INITR_ACT_ONE ? "One"	\
	       : fromwire_peektype(msg) == WIRE_INITR_ACT_TWO ? "Two"	\
	       : fromwire_peektype(msg) == WIRE_INITR_ACT_THREE ? "Three" \
	       : fromwire_peektype(msg) == WIRE_RESPR_ACT_ONE ? "One" \
	       : fromwire_peektype(msg) == WIRE_RESPR_ACT_TWO ? "Two" \
	       : fromwire_peektype(msg) == WIRE_RESPR_ACT_THREE ? "Three" \
	       : "UNKNOWN")
#define status_failed(code, fmt, ...)	\
	errx(1, "%s:%s:" fmt "\n", status_prefix, #code, __VA_ARGS__)
#define status_trace(fmt, ...) \
	printf("%s:" fmt "\n", status_prefix, __VA_ARGS__)

#define read_all fake_read_all
#define write_all fake_write_all

/* No randomness please, we want to replicate test vectors. */
#include <sodium/randombytes.h>

static unsigned char e_priv[32];
#define randombytes_buf(secret, len) memcpy((secret), e_priv, len)

#define TESTING
#include "../handshake.c"
#include "utils.h"
#include <ccan/err/err.h>

secp256k1_context *secp256k1_ctx;
const void *trc;
static struct privkey privkey;

void hsm_setup(int fd)
{
}

bool hsm_do_ecdh(struct secret *ss, const struct pubkey *point)
{
	return secp256k1_ecdh(secp256k1_ctx, ss->data, &point->pubkey,
			      privkey.secret.data) == 1;
}

int main(void)
{
	int fds1[2], fds2[2];
	struct pubkey responder_id;
	struct privkey responder_privkey;
	struct secret ck, sk, rk;
	const tal_t *ctx = tal_tmpctx(NULL);

	trc = tal_tmpctx(ctx);

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);

	memset(responder_privkey.secret.data, 0x21,
	       sizeof(responder_privkey.secret.data));
	if (!secp256k1_ec_pubkey_create(secp256k1_ctx,
					&responder_id.pubkey,
					responder_privkey.secret.data))
		errx(1, "Keygen failed");

	if (pipe(fds1) != 0 || pipe(fds2) != 0)
		err(1, "Making pipes");

	switch (fork()) {
	case -1:
		err(1, "fork failed");
	case 0: {
		struct pubkey their_id;

		memset(e_priv, 0x22, sizeof(e_priv));
		read_fd = fds1[0];
		write_fd = fds2[1];
		close(fds1[1]);
		close(fds2[0]);
		privkey = responder_privkey;
		status_prefix = "RESPR";
		status_trace("ls.priv: 0x%s",
			     tal_hexstr(trc, &responder_privkey,
					sizeof(responder_privkey)));
		status_trace("ls.pub: 0x%s",
			     type_to_string(trc, struct pubkey, &responder_id));
		responder(-1, &responder_id, &their_id, &ck, &sk, &rk);
		if (!write_all(write_fd, &ck, sizeof(ck))
		    || !write_all(write_fd, &sk, sizeof(sk))
		    || !write_all(write_fd, &rk, sizeof(rk)))
			err(1, "writing out secrets failed");
		goto out;
	}
	default: {
		struct pubkey initiator_id;
		struct privkey initiator_privkey;
		struct secret their_ck, their_sk, their_rk;

		read_fd = fds2[0];
		write_fd = fds1[1];
		close(fds2[1]);
		close(fds1[0]);

		memset(initiator_privkey.secret.data, 0x11,
		       sizeof(initiator_privkey.secret.data));
		memset(e_priv, 0x12, sizeof(e_priv));
		if (!secp256k1_ec_pubkey_create(secp256k1_ctx,
						&initiator_id.pubkey,
						initiator_privkey.secret.data))
			errx(1, "Initiator keygen failed");
		privkey = initiator_privkey;
		status_prefix = "INITR";
		status_trace("rs.pub: 0x%s",
			     type_to_string(trc, struct pubkey, &responder_id));
		status_trace("ls.priv: 0x%s",
			     tal_hexstr(trc, &initiator_privkey,
					sizeof(initiator_privkey)));
		status_trace("ls.pub: 0x%s",
			     type_to_string(trc, struct pubkey, &initiator_id));

		initiator(-1, &initiator_id, &responder_id, &ck, &sk, &rk);
		if (!read_all(read_fd, &their_ck, sizeof(their_ck))
		    || !read_all(read_fd, &their_sk, sizeof(their_sk))
		    || !read_all(read_fd, &their_rk, sizeof(their_rk)))
			err(1, "reading their secrets failed");

		assert(structeq(&ck, &their_ck));
		assert(structeq(&sk, &their_rk));
		assert(structeq(&rk, &their_sk));
		goto out;
	}
	}

out:
	/* No memory leaks please */
	secp256k1_context_destroy(secp256k1_ctx);
	tal_free(ctx);
	return 0;
}
