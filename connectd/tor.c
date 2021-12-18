#include "config.h"
#include <ccan/io/io.h>
#include <ccan/tal/str/str.h>
#include <common/status.h>
#include <common/utils.h>
#include <connectd/connectd.h>
#include <connectd/tor.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>

#define SOCKS_NOAUTH		0
#define SOCKS_ERROR 	 0xff
#define SOCKS_CONNECT		1
#define SOCKS_TYP_IPV4		1
#define SOCKS_DOMAIN		3
#define SOCKS_TYP_IPV6		4
#define SOCKS_V5            5

#define MAX_SIZE_OF_SOCKS5_REQ_OR_RESP 255
#define SIZE_OF_RESPONSE 		4
#define SIZE_OF_REQUEST 		3
#define SIZE_OF_IPV4_RESPONSE 	6
#define SIZE_OF_IPV6_RESPONSE 	18
#define SOCK_REQ_METH_LEN		3
#define SOCK_REQ_V5_LEN			5
#define SOCK_REQ_V5_HEADER_LEN	7

/* some crufts can not forward ipv6 */
#undef BIND_FIRST_TO_IPV6

struct connecting_socks {
	u8 buffer[MAX_SIZE_OF_SOCKS5_REQ_OR_RESP];
	size_t hlen;
	in_port_t port;
	char *host;
	struct connecting *connect;
};

static const char* socks5strerror(const tal_t *ctx, u8 code)
{
	/* Error codes defined in https://tools.ietf.org/html/rfc1928#section-6 */
	switch (code) {
	case 0:
		return tal_strdup(ctx, "success");
	case 1:
		return tal_strdup(ctx, "general SOCKS server failure");
	case 2:
		return tal_strdup(ctx, "connection not allowed by ruleset");
	case 3:
		return tal_strdup(ctx, "network unreachable");
	case 4:
		return tal_strdup(ctx, "host unreachable");
	case 5:
		return tal_strdup(ctx, "connection refused");
	case 6:
		return tal_strdup(ctx, "TTL expired");
	case 7:
		return tal_strdup(ctx, "command not supported");
	case 8:
		return tal_strdup(ctx, "address type not supported");
	}
	return tal_fmt(ctx, "unknown error: %" PRIu8, code);
}

static struct io_plan *connect_finish2(struct io_conn *conn,
				       struct connecting_socks *connect)
{
	status_io(LOG_IO_IN, NULL, "proxy",
		  connect->buffer + SIZE_OF_RESPONSE + SIZE_OF_IPV4_RESPONSE,
		  SIZE_OF_IPV6_RESPONSE - SIZE_OF_IPV4_RESPONSE);
	status_debug("Now try LN connect out for host %s", connect->host);
	return connection_out(conn, connect->connect);
}

static struct io_plan *connect_finish(struct io_conn *conn,
				      struct connecting_socks *connect)
{
	status_io(LOG_IO_IN, NULL, "proxy",
		  connect->buffer, SIZE_OF_IPV4_RESPONSE + SIZE_OF_RESPONSE);

	/* buffer[1] contains the reply status code and 0 means "success",
	 * see https://tools.ietf.org/html/rfc1928#section-6
	 */
	if ( connect->buffer[1] == '\0') {
		if ( connect->buffer[3] == SOCKS_TYP_IPV6) {
			/* Read rest of response */
			return io_read(conn,
				       connect->buffer + SIZE_OF_RESPONSE +
				       SIZE_OF_IPV4_RESPONSE,
				       SIZE_OF_IPV6_RESPONSE -
				       SIZE_OF_IPV4_RESPONSE,
				       &connect_finish2, connect);

		} else if ( connect->buffer[3] == SOCKS_TYP_IPV4) {
			status_debug("Now try LN connect out for host %s",
				     connect->host);
			return connection_out(conn, connect->connect);
		} else {
			const char *msg = tal_fmt(tmpctx,
			     "Tor connect out for host %s error invalid "
			     "type return: %0x", connect->host,
			     connect->buffer[3]);
			status_debug("%s", msg);
			add_errors_to_error_list(connect->connect, msg);

			errno = ECONNREFUSED;
			return io_close(conn);
		}
	} else {
		const char *msg = tal_fmt(tmpctx,
			     "Error connecting to %s: Tor server reply: %s",
			     connect->host,
			     socks5strerror(tmpctx, connect->buffer[1]));
		status_debug("%s", msg);
		add_errors_to_error_list(connect->connect, msg);

		errno = ECONNREFUSED;
		return io_close(conn);
	}
}

/* called when TOR responds */
static struct io_plan *connect_out(struct io_conn *conn,
				   struct connecting_socks *connect)
{
	return io_read(conn, connect->buffer,
		       SIZE_OF_IPV4_RESPONSE + SIZE_OF_RESPONSE,
		       &connect_finish, connect);

}

static struct io_plan *io_tor_connect_after_resp_to_connect(struct io_conn
							    *conn,
							    struct
							    connecting_socks
							    *connect)
{
	status_io(LOG_IO_IN, NULL, "proxy", connect->buffer, 2);

	if (connect->buffer[1] == SOCKS_ERROR) {
		/* The Tor socks5 server did not like any of our authentication
		 * methods and we provided only "no auth".
		 */
		const char *msg = tal_fmt(tmpctx,
			     "Connected out for %s error: authentication required",
			     connect->host);
		status_debug("%s", msg);
		add_errors_to_error_list(connect->connect, msg);

		errno = ECONNREFUSED;
		return io_close(conn);
	}
	if (connect->buffer[1] == '\0') {
		/* make the V5 request */
		connect->hlen = strlen(connect->host);
		connect->buffer[0] = SOCKS_V5;
		connect->buffer[1] = SOCKS_CONNECT;
		connect->buffer[2] = 0;
		connect->buffer[3] = SOCKS_DOMAIN;
		connect->buffer[4] = connect->hlen;

		memcpy(connect->buffer + SOCK_REQ_V5_LEN, connect->host, connect->hlen);
		memcpy(connect->buffer + SOCK_REQ_V5_LEN + strlen(connect->host),
				&(connect->port), sizeof connect->port);

		status_io(LOG_IO_OUT, NULL, "proxy", connect->buffer,
				SOCK_REQ_V5_HEADER_LEN + connect->hlen);
		return io_write(conn, connect->buffer,
				SOCK_REQ_V5_HEADER_LEN + connect->hlen,
				connect_out, connect);
	} else {
			const char *msg = tal_fmt(tmpctx,
				"Connected out for %s error: unexpected connect answer %0x from the tor socks5 proxy",
				connect->host,
				connect->buffer[1]);
			status_debug("%s", msg);
			add_errors_to_error_list(connect->connect, msg);

		errno = ECONNREFUSED;
		return io_close(conn);
	}
}

static struct io_plan *io_tor_connect_after_req_to_connect(struct io_conn *conn,
							   struct connecting_socks
							   *connect)
{
	return io_read(conn, connect->buffer, 2,
		       &io_tor_connect_after_resp_to_connect, connect);
}

static struct io_plan *io_tor_connect_do_req(struct io_conn *conn,
					     struct connecting_socks *connect)
{
	/* make the init request */
	connect->buffer[0] = SOCKS_V5;
	connect->buffer[1] = 1;
	connect->buffer[2] = SOCKS_NOAUTH;

	status_io(LOG_IO_OUT, NULL, "proxy", connect->buffer, SOCK_REQ_METH_LEN);
	return io_write(conn, connect->buffer, SOCK_REQ_METH_LEN,
			&io_tor_connect_after_req_to_connect, connect);
}

/* called when we want to connect to TOR SOCKS5 */
struct io_plan *io_tor_connect(struct io_conn *conn,
			       const struct addrinfo *tor_proxyaddr,
			       const char *host, u16 port,
			       struct connecting *connect)
{
	struct connecting_socks *connect_tor = tal(connect,
						   struct connecting_socks);

	connect_tor->port = htons(port);
	connect_tor->host = tal_strdup(connect_tor, host);
	connect_tor->connect = connect;

	return io_connect(conn, tor_proxyaddr,
			  &io_tor_connect_do_req, connect_tor);
}
