#include <ccan/io/io.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/str/str.h>
#include <common/status.h>
#include <common/utils.h>
#include <common/wireaddr.h>
#include <connectd/connect.h>
#include <connectd/tor.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

/* some crufts can not forward ipv6*/
#undef BIND_FIRST_TO_IPV6

struct reaching_socks {
	u8 buffer[MAX_SIZE_OF_SOCKS5_REQ_OR_RESP];
	size_t hlen;
	in_port_t port;
	char *host;
	struct reaching *reach;
};

static struct io_plan *connect_finish2(struct io_conn *conn,
				       struct reaching_socks *reach)
{
	status_io(LOG_IO_IN, "proxy",
		  (reach->buffer + SIZE_OF_RESPONSE - SIZE_OF_IPV4_RESPONSE),
		  SIZE_OF_IPV6_RESPONSE - SIZE_OF_RESPONSE - SIZE_OF_IPV4_RESPONSE);
	status_trace("Now try LN connect out for host %s", reach->host);
	return connection_out(conn, reach->reach);
}

static struct io_plan *connect_finish(struct io_conn *conn,
				      struct reaching_socks *reach)
{
	status_io(LOG_IO_IN, "proxy",
		  reach->buffer, SIZE_OF_IPV4_RESPONSE + SIZE_OF_RESPONSE);

	if ( reach->buffer[1] == '\0') {
		if ( reach->buffer[3] == SOCKS_TYP_IPV6) {
			return io_read(conn,
				       (reach->buffer + SIZE_OF_RESPONSE -
					SIZE_OF_IPV4_RESPONSE),
				       SIZE_OF_IPV6_RESPONSE -
				       SIZE_OF_RESPONSE - SIZE_OF_IPV4_RESPONSE,
				       &connect_finish2, reach);

		} else if ( reach->buffer[3] == SOCKS_TYP_IPV4) {
			status_trace("Now try LN connect out for host %s",
				     reach->host);
			return connection_out(conn, reach->reach);
		} else {
			status_trace
			    ("Tor connect out for host %s error invalid type return ",
			     reach->host);
			return io_close(conn);
		}
	} else {
		status_trace("Tor connect out for host %s error: %x ",
			     reach->host, reach->buffer[1]);
		return io_close(conn);
	}
}

/* called when TOR responds */
static struct io_plan *connect_out(struct io_conn *conn,
				   struct reaching_socks *reach)
{
	return io_read(conn, reach->buffer,
		       SIZE_OF_IPV4_RESPONSE + SIZE_OF_RESPONSE,
		       &connect_finish, reach);

}

static struct io_plan *io_tor_connect_after_resp_to_connect(struct io_conn
							    *conn,
							    struct
							    reaching_socks
							    *reach)
{
	status_io(LOG_IO_IN, "proxy", reach->buffer, 2);

	if (reach->buffer[1] == SOCKS_ERROR) {
		status_trace("Connected out for %s error", reach->host);
		return io_close(conn);
	}
	/* make the V5 request */
	reach->hlen = strlen(reach->host);
	reach->buffer[0] = SOCKS_V5;
	reach->buffer[1] = SOCKS_CONNECT;
	reach->buffer[2] = 0;
	reach->buffer[3] = SOCKS_DOMAIN;
	reach->buffer[4] = reach->hlen;

	memcpy(reach->buffer + SOCK_REQ_V5_LEN, reach->host, reach->hlen);
	memcpy(reach->buffer + SOCK_REQ_V5_LEN + strlen(reach->host),
	       &(reach->port), sizeof reach->port);

	status_io(LOG_IO_OUT, "proxy", reach->buffer,
		  SOCK_REQ_V5_HEADER_LEN + reach->hlen);
	return io_write(conn, reach->buffer,
			SOCK_REQ_V5_HEADER_LEN + reach->hlen,
			connect_out, reach);
}

static struct io_plan *io_tor_connect_after_req_to_connect(struct io_conn *conn,
							   struct reaching_socks
							   *reach)
{
	return io_read(conn, reach->buffer, 2,
		       &io_tor_connect_after_resp_to_connect, reach);
}

static struct io_plan *io_tor_connect_do_req(struct io_conn *conn,
					     struct reaching_socks *reach)
{
	/* make the init request */
	reach->buffer[0] = SOCKS_V5;
	reach->buffer[1] = 1;
	reach->buffer[2] = SOCKS_NOAUTH;

	status_io(LOG_IO_OUT, "proxy", reach->buffer, SOCK_REQ_METH_LEN);
	return io_write(conn, reach->buffer, SOCK_REQ_METH_LEN,
			&io_tor_connect_after_req_to_connect, reach);
}

// called when we want to connect to TOR SOCKS5
struct io_plan *io_tor_connect(struct io_conn *conn,
			       const struct addrinfo *tor_proxyaddr,
			       const char *host, u16 port,
			       struct reaching *reach)
{
	struct reaching_socks *reach_tor = tal(reach, struct reaching_socks);

	reach_tor->port = htons(port);
	reach_tor->host = tal_strdup(reach_tor, host);
	reach_tor->reach = reach;

	return io_connect(conn, tor_proxyaddr,
			  &io_tor_connect_do_req, reach_tor);
}
