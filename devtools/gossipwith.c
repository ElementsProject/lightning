/* Simple tool to route gossip from a peer. */
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include <common/crypto_sync.h>
#include <common/dev_disconnect.h>
#include <common/peer_failed.h>
#include <common/status.h>
#include <netdb.h>
#include <secp256k1_ecdh.h>
#include <wire/peer_wire.h>

#define io_write_ simple_write
#define io_read_ simple_read

static struct io_plan *simple_write(struct io_conn *conn,
				    const void *data, size_t len,
				    struct io_plan *(*next)(struct io_conn *, void *),
				    void *arg);

static struct io_plan *simple_read(struct io_conn *conn,
				   void *data, size_t len,
				   struct io_plan *(*next)(struct io_conn *, void *),
				   void *next_arg);

#include "../connectd/handshake.c"

/* This makes the handshake prototypes work. */
struct io_conn {
	int fd;
};

static struct secret notsosecret;
static bool initial_sync = false;
static unsigned long max_messages = -1UL;

/* Empty stubs to make us compile */
void status_peer_io(enum log_level iodir, const u8 *p)
{
}

void status_fmt(enum log_level level, const char *fmt, ...)
{
}

#if DEVELOPER
void dev_sabotage_fd(int fd)
{
	abort();
}

void dev_blackhole_fd(int fd)
{
	abort();
}

enum dev_disconnect dev_disconnect(int pkt_type)
{
	return DEV_DISCONNECT_NORMAL;
}
#endif

void peer_failed_connection_lost(void)
{
	exit(0);
}

bool hsm_do_ecdh(struct secret *ss, const struct pubkey *point)
{
	if (secp256k1_ecdh(secp256k1_ctx, ss->data, &point->pubkey,
			   notsosecret.data) != 1)
		errx(1, "ECDH failed");
	return true;
}

/* We don't want to discard *any* messages. */
bool is_unknown_msg_discardable(const u8 *cursor)
{
	return false;
}

static struct io_plan *simple_write(struct io_conn *conn,
				    const void *data, size_t len,
				    struct io_plan *(*next)(struct io_conn *, void *),
				    void *arg)
{
	if (!write_all(conn->fd, data, len))
		err(1, "Writing data");
	return next(conn, arg);
}

static struct io_plan *simple_read(struct io_conn *conn,
				   void *data, size_t len,
				   struct io_plan *(*next)(struct io_conn *, void *),
				   void *next_arg)
{
	if (!read_all(conn->fd, data, len))
		err(1, "Reading data");
	return next(conn, next_arg);
}

static struct io_plan *handshake_success(struct io_conn *conn,
					 const struct pubkey *them,
					 const struct wireaddr_internal *addr,
					 const struct crypto_state *orig_cs,
					 char **args)
{
	u8 *msg;
	struct crypto_state cs = *orig_cs;
	u8 *local_features;

	if (initial_sync) {
		local_features = tal(conn, u8);
		local_features[0] = (1 << 3);
	} else
		local_features = NULL;

	msg = towire_init(NULL, NULL, local_features);

	sync_crypto_write(&cs, conn->fd, take(msg));
	/* Ignore their init message. */
	tal_free(sync_crypto_read(NULL, &cs, conn->fd));

	/* Did they ask us to send any messages?  Do so now. */
	while (*args) {
		u8 *m = tal_hexdata(NULL, *args, strlen(*args));
		if (!m)
			errx(1, "Invalid hexdata '%s'", *args);
		sync_crypto_write(&cs, conn->fd, take(m));
		args++;
	}

	/* Now write out whatever we get. */
	while ((msg = sync_crypto_read(NULL, &cs, conn->fd)) != NULL) {
		be16 len = cpu_to_be16(tal_bytelen(msg));

		if (!write_all(STDOUT_FILENO, &len, sizeof(len))
		    || !write_all(STDOUT_FILENO, msg, tal_bytelen(msg)))
			err(1, "Writing out msg");
		tal_free(msg);

		if (--max_messages == 0)
			exit(0);
	}
	err(1, "Reading msg");
}

int main(int argc, char *argv[])
{
	struct io_conn *conn = tal(NULL, struct io_conn);
	struct wireaddr_internal addr;
	int af;
	struct pubkey us, them;
	const char *err_msg;
	const char *at;
	struct addrinfo *ai;

	setup_locale();
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
						 SECP256K1_CONTEXT_SIGN);

	opt_register_noarg("--initial-sync", opt_set_bool, &initial_sync,
			   "Stream complete gossip history at start");
	opt_register_arg("--max-messages", opt_set_ulongval, opt_show_ulongval,
			 &max_messages,
			 "Terminate after reading this many messages (> 0)");
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "id@addr[:port] [hex-msg-tosend...]\n"
			   "Connect to a lightning peer and relay gossip messages from it",
			   "Print this message.");

	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc < 2)
		opt_usage_exit_fail("Need an id@addr to connect to");
	at = strchr(argv[1], '@');
	if (!at)
		opt_usage_exit_fail("Need id@addr");

	if (!pubkey_from_hexstr(argv[1], at - argv[1], &them))
		opt_usage_exit_fail("Invalid id %.*s",
				    (int)(at - argv[1]), argv[1]);

	if (!parse_wireaddr_internal(at+1, &addr, DEFAULT_PORT, NULL,
				     true, false, &err_msg))
		opt_usage_exit_fail("%s '%s'", err_msg, argv[1]);

	switch (addr.itype) {
	case ADDR_INTERNAL_SOCKNAME:
		af = AF_LOCAL;
		ai = wireaddr_internal_to_addrinfo(conn, &addr);
		break;
	case ADDR_INTERNAL_ALLPROTO:
	case ADDR_INTERNAL_AUTOTOR:
	case ADDR_INTERNAL_FORPROXY:
		opt_usage_exit_fail("Don't support proxy use");

	case ADDR_INTERNAL_WIREADDR:
		switch (addr.u.wireaddr.type) {
		case ADDR_TYPE_TOR_V2:
		case ADDR_TYPE_TOR_V3:
			opt_usage_exit_fail("Don't support proxy use");
			break;
		case ADDR_TYPE_IPV4:
			af = AF_INET;
			break;
		case ADDR_TYPE_IPV6:
			af = AF_INET6;
			break;
		case ADDR_TYPE_PADDING:
			abort();
		}
		ai = wireaddr_to_addrinfo(tmpctx, &addr.u.wireaddr);
	}
	conn->fd = socket(af, SOCK_STREAM, 0);
	if (conn->fd < 0)
		err(1, "Creating socket");

	memset(&notsosecret, 0x42, sizeof(notsosecret));
	if (!pubkey_from_secret(&notsosecret, &us))
		errx(1, "Creating pubkey");

	if (connect(conn->fd, ai->ai_addr, ai->ai_addrlen) != 0)
		err(1, "Connecting to %s", at+1);

	initiator_handshake(conn, &us, &them, &addr, handshake_success, argv+2);
	exit(0);
}

