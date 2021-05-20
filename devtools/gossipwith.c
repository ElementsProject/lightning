/* Simple tool to route gossip from a peer. */
#include <bitcoin/block.h>
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/opt/opt.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/hex/hex.h>
#include <common/crypto_sync.h>
#include <common/dev_disconnect.h>
#include <common/features.h>
#include <common/peer_failed.h>
#include <common/per_peer_state.h>
#include <common/status.h>
#include <netdb.h>
#include <poll.h>
#include <secp256k1_ecdh.h>
#include <wire/peer_wire.h>

#define io_write_ simple_write
#define io_read_ simple_read
#define io_close simple_close
static bool stream_stdin = false;
static bool no_init = false;
static bool hex = false;
static int timeout_after = -1;
static u8 *features;

static struct io_plan *simple_write(struct io_conn *conn,
				    const void *data, size_t len,
				    struct io_plan *(*next)(struct io_conn *, void *),
				    void *arg);

static struct io_plan *simple_read(struct io_conn *conn,
				   void *data, size_t len,
				   struct io_plan *(*next)(struct io_conn *, void *),
				   void *next_arg);

static struct io_plan *simple_close(struct io_conn *conn)
{
	return NULL;
}

  #include "../connectd/handshake.c"

/* This makes the handshake prototypes work. */
struct io_conn {
	int fd;
};

static struct secret notsosecret;
static bool initial_sync = false;
static unsigned long max_messages = -1UL;

/* Empty stubs to make us compile */
void status_peer_io(enum log_level iodir,
		    const struct node_id *node_id,
		    const u8 *p)
{
}

void status_fmt(enum log_level level,
		const struct node_id *node_id,
		const char *fmt, ...)
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

static char *opt_set_network(const char *arg, void *unused)
{
	assert(arg != NULL);

	/* Set the global chainparams instance */
	chainparams = chainparams_for_network(arg);
	if (!chainparams)
		return tal_fmt(NULL, "Unknown network name '%s'", arg);
	return NULL;
}

static void opt_show_network(char buf[OPT_SHOW_LEN], const void *unused)
{
	snprintf(buf, OPT_SHOW_LEN, "%s", chainparams->network_name);
}

void peer_failed_connection_lost(void)
{
	exit(0);
}

void ecdh(const struct pubkey *point, struct secret *ss)
{
	if (secp256k1_ecdh(secp256k1_ctx, ss->data, &point->pubkey,
			   notsosecret.data, NULL, NULL) != 1)
		abort();
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
					 struct crypto_state *orig_cs,
					 char **args)
{
	u8 *msg;
	struct per_peer_state *pps = new_per_peer_state(conn, orig_cs);
	struct pollfd pollfd[2];

	pps->peer_fd = io_conn_fd(conn);
	if (initial_sync)
		set_feature_bit(&features,
				OPTIONAL_FEATURE(OPT_INITIAL_ROUTING_SYNC));

	if (!no_init) {
		struct tlv_init_tlvs *tlvs = NULL;
		if (chainparams) {
			tlvs = tlv_init_tlvs_new(NULL);
			tlvs->networks = tal_arr(tlvs, struct bitcoin_blkid, 1);
			tlvs->networks[0] = chainparams->genesis_blockhash;
		}
			msg = towire_init(NULL, NULL, features, tlvs);

		sync_crypto_write(pps, take(msg));
		/* Ignore their init message. */
		tal_free(sync_crypto_read(NULL, pps));
		tal_free(tlvs);
	}

	if (stream_stdin)
		pollfd[0].fd = STDIN_FILENO;
	else
		pollfd[0].fd = -1;
	pollfd[0].events = POLLIN;
	pollfd[1].fd = pps->peer_fd;
	pollfd[1].events = POLLIN;

	while (*args) {
		u8 *m = tal_hexdata(NULL, *args, strlen(*args));
		if (!m)
			errx(1, "Invalid hexdata '%s'", *args);
		sync_crypto_write(pps, take(m));
		args++;
	}

	while (max_messages != 0 || pollfd[0].fd != -1) {
		beint16_t belen;
		u8 *msg;

		if (poll(pollfd, ARRAY_SIZE(pollfd),
			 timeout_after < 0 ? -1 : timeout_after * 1000) == 0)
			return 0;

		/* We always to stdin first if we can */
		if (pollfd[0].revents & POLLIN) {
			if (!read_all(STDIN_FILENO, &belen, sizeof(belen)))
				pollfd[0].fd = -1;
			else {
				msg = tal_arr(NULL, u8, be16_to_cpu(belen));

				if (!read_all(STDIN_FILENO, msg, tal_bytelen(msg)))
					err(1, "Only read partial message");
				sync_crypto_write(pps, take(msg));
			}
		} else if (pollfd[1].revents & POLLIN) {
			msg = sync_crypto_read(NULL, pps);
			if (!msg)
				err(1, "Reading msg");
			if (hex) {
				printf("%s\n", tal_hex(msg, msg));
			} else {
				belen = cpu_to_be16(tal_bytelen(msg));
				if (!write_all(STDOUT_FILENO, &belen, sizeof(belen))
				    || !write_all(STDOUT_FILENO, msg, tal_bytelen(msg)))
					err(1, "Writing out msg");
			}
			tal_free(msg);
			--max_messages;
		}
	}
	exit(0);
}

static char *opt_set_secret(const char *arg, struct secret *s)
{
	if (!hex_decode(arg, strlen(arg), s->data, sizeof(s->data)))
		return "secret must be 64 hex digits";
	return NULL;
}

static void opt_show_secret(char buf[OPT_SHOW_LEN], const struct secret *s)
{
	hex_encode(s->data, sizeof(s->data), buf, OPT_SHOW_LEN);
}

static char *opt_set_features(const char *arg, u8 **features)
{
	*features = tal_hexdata(tal_parent(*features), arg, strlen(arg));
	if (!*features)
		return "features must be valid hex";
	return NULL;
}

int main(int argc, char *argv[])
{
	struct io_conn *conn = tal(NULL, struct io_conn);
	struct wireaddr_internal addr;
	int af = -1;
	struct pubkey us, them;
	const char *err_msg;
	const char *at;
	struct addrinfo *ai = NULL;

	setup_locale();
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY |
						 SECP256K1_CONTEXT_SIGN);

	memset(&notsosecret, 0x42, sizeof(notsosecret));
	features = tal_arr(conn, u8, 0);

	opt_register_noarg("--initial-sync", opt_set_bool, &initial_sync,
			   "Stream complete gossip history at start");
	opt_register_arg("--max-messages", opt_set_ulongval, opt_show_ulongval,
			 &max_messages,
			 "Terminate after reading this many messages");
	opt_register_noarg("--stdin", opt_set_bool, &stream_stdin,
			   "Stream gossip messages from stdin.");
	opt_register_noarg("--no-init", opt_set_bool, &no_init,
			   "Don't send or swallow init messages.");
	opt_register_arg("--privkey", opt_set_secret, opt_show_secret,
			 &notsosecret,
			 "Secret key to use for our identity");
	opt_register_arg("--timeout-after", opt_set_intval, opt_show_intval,
			 &timeout_after,
			 "Exit (success) this many seconds after no msgs rcvd");
	opt_register_noarg("--hex", opt_set_bool, &hex,
			   "Print out messages in hex");
	opt_register_arg("--features=<hex>", opt_set_features, NULL,
			 &features, "Send these features in init");
	opt_register_arg("--network", opt_set_network, opt_show_network,
	                 NULL,
	                 "Select the network parameters (bitcoin, testnet, signet,"
	                 " regtest, liquid, liquid-regtest, litecoin or"
	                 " litecoin-testnet)");
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
				     true, false, true, &err_msg))
		opt_usage_exit_fail("%s '%s'", err_msg, argv[1]);

	switch (addr.itype) {
	case ADDR_INTERNAL_SOCKNAME:
		af = AF_LOCAL;
		ai = wireaddr_internal_to_addrinfo(conn, &addr);
		break;
	case ADDR_INTERNAL_ALLPROTO:
	case ADDR_INTERNAL_AUTOTOR:
	case ADDR_INTERNAL_STATICTOR:
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
		}
		ai = wireaddr_to_addrinfo(tmpctx, &addr.u.wireaddr);
	}

	if (af == -1 || ai == NULL)
		err(1, "Initializing socket");

	conn->fd = socket(af, SOCK_STREAM, 0);
	if (conn->fd < 0)
		err(1, "Creating socket");

	if (!pubkey_from_secret(&notsosecret, &us))
		errx(1, "Creating pubkey");

	if (connect(conn->fd, ai->ai_addr, ai->ai_addrlen) != 0)
		err(1, "Connecting to %s", at+1);

	initiator_handshake(conn, &us, &them, &addr, handshake_success, argv+2);
	exit(0);
}

