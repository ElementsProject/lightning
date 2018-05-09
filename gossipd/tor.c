#include <ccan/io/io.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/str/str.h>
#include <common/status.h>
#include <common/utils.h>
#include <common/wireaddr.h>
#include <gossipd/gossip.h>
#include <gossipd/tor.h>
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

static struct io_plan *connect_finish(struct io_conn *,
				      struct reaching_socks *);

static struct io_plan *connect_finish2(struct io_conn *,
				       struct reaching_socks *);

static struct io_plan *connect_out(struct io_conn *, struct reaching_socks *);

static struct io_plan *io_tor_connect_after_req_to_connect(struct io_conn *,
							   struct reaching_socks
							   *);
static struct io_plan *io_tor_connect_after_req_host(struct io_conn *,
						     struct reaching_socks *);

static struct io_plan *io_tor_connect_do_req(struct io_conn *,
					     struct reaching_socks *);

static struct io_plan *connect_out(struct io_conn *, struct reaching_socks *);

static struct io_plan *io_tor_connect_do_req(struct io_conn *,
					     struct reaching_socks *);

static struct io_plan *io_tor_connect_after_resp_to_connect(struct io_conn
							    *conn,
							    struct
							    reaching_socks *);

static struct io_plan *io_tor_connect_after_resp_to_connect(struct io_conn
							    *conn,
							    struct
							    reaching_socks
							    *reach)
{
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

	return io_write(conn, reach->buffer,
			SOCK_REQ_V5_HEADER_LEN + reach->hlen,
			io_tor_connect_after_req_host, reach);
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

	return io_write(conn, reach->buffer, SOCK_REQ_METH_LEN,
			&io_tor_connect_after_req_to_connect, reach);
}

static struct io_plan *connect_finish2(struct io_conn *conn,
				       struct reaching_socks *reach)
{
	status_trace("Now try LN connect out for host %s", reach->host);
	return connection_out(conn, reach->reach);
}

static struct io_plan *connect_finish(struct io_conn *conn,
				      struct reaching_socks *reach)
{

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

static struct io_plan *connect_out(struct io_conn *conn,
				   struct reaching_socks *reach)
{
	return io_read(conn, reach->buffer,
		       SIZE_OF_IPV4_RESPONSE + SIZE_OF_RESPONSE,
		       &connect_finish, reach);

}

/* called when TOR responds */
static struct io_plan *io_tor_connect_after_req_host(struct io_conn *conn,
						     struct reaching_socks
						     *reach)
{
	if (reach->buffer[0] == '0') {
		status_trace("Connected out over tor for %s failed",
			     reach->host);
		return io_close(conn);
	}
	return connect_out(conn, reach);
}

// called when we want to connect to TOR SOCKS5
struct io_plan *io_tor_connect(struct io_conn *conn,
			       const struct wireaddr *tor_proxyaddrs,
			       const struct wireaddr *addr,
			       struct reaching *reach)
{
	struct addrinfo *ai_tor = tal(reach, struct addrinfo);
	char *port_addr = tal(reach, char);
	struct io_plan *plan;
	struct reaching_socks *reach_tor = tal(reach, struct reaching_socks);

	reach_tor->port = htons(addr->port);
	port_addr = tal_fmt(reach, "%u", tor_proxyaddrs->port);
	getaddrinfo((char *)
		    fmt_wireaddr_without_port(tmpctx,
					      tor_proxyaddrs),
		    port_addr, NULL, &ai_tor);
	status_trace("Tor proxyaddr : %s",
		     fmt_wireaddr(reach, tor_proxyaddrs));
	reach_tor->host = tal_strdup(reach, "");

	if (addr->type == ADDR_TYPE_TOR_V3)
		reach_tor->host =
		    tal_fmt(reach, "%.62s",
			    fmt_wireaddr_without_port(tmpctx, addr));
	else if (addr->type == ADDR_TYPE_TOR_V2)
		reach_tor->host =
		    tal_fmt(reach, "%.22s",
			    fmt_wireaddr_without_port(tmpctx, addr));
	else if (addr->type == ADDR_TYPE_IPV4)
		reach_tor->host =
		    tal_fmt(reach, "%s",
			    fmt_wireaddr_without_port(tmpctx, addr));
	else if (addr->type == ADDR_TYPE_IPV6)
		reach_tor->host =
		    tal_fmt(reach, "%s",
			    fmt_wireaddr_without_port(tmpctx, addr));
	reach_tor->reach = reach;

	plan = io_connect(conn, ai_tor, &io_tor_connect_do_req, reach_tor);

	return plan;
}

bool do_we_use_tor_addr(const struct wireaddr *wireaddr)
{
	for (int i = 0; i < tal_count(wireaddr); i++) {
		if ((wireaddr[i].type == ADDR_TYPE_TOR_V2)
		    || (wireaddr[i].type == ADDR_TYPE_TOR_V3))
			return true;
	}
	return false;
}
