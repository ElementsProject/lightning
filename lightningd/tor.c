#include <arpa/inet.h>
#include <assert.h>
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/wireaddr.h>
#include <errno.h>
#include <fcntl.h>
#include <lightningd/tor.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <wire/wire.h>

#define MAX_TOR_COOKIE_LEN 32
#define MAX_TOR_SERVICE_READBUFFER_LEN 255
#define MAX_TOR_ONION_V2_ADDR_LEN 16
#define MAX_TOR_ONION_V3_ADDR_LEN 56

static bool return_from_service_call;

struct tor_service_reaching {
	struct lightningd *ld;
	u8 buffer[MAX_TOR_SERVICE_READBUFFER_LEN];
	char *cookie[MAX_TOR_COOKIE_LEN];
	u8 *p;
	bool noauth;
	size_t hlen;
};

static struct io_plan *io_tor_connect_close(struct io_conn *conn)
{
	err(1, "Cannot create TOR service address");
	return_from_service_call = true;
	return io_close(conn);
}

static struct io_plan *io_tor_connect_create_onion_finished(struct io_conn
							    *conn, struct
							    tor_service_reaching
							    *reach)
{
	char *temp_char;

	if (reach->hlen == MAX_TOR_ONION_V2_ADDR_LEN) {
		size_t n = tal_count(reach->ld->proposed_wireaddr);
		tal_resize(&reach->ld->proposed_wireaddr, n + 1);
		tal_resize(&reach->ld->proposed_listen_announce, n+1);
		reach->ld->proposed_listen_announce[n] = ADDR_ANNOUNCE;
		temp_char = tal_fmt(tmpctx, "%.56s.onion", reach->buffer);
		parse_wireaddr_internal(temp_char,
					&reach->ld->proposed_wireaddr[n],
					reach->ld->portnum, false, NULL);
		return_from_service_call = true;
		return io_close(conn);
	}
	/*on the other hand we can stay connected until ln finish to keep onion alive and then vanish */
	//because when we run with Detach flag as we now do every start of LN creates a new addr while the old
	//stays valid until reboot this might not be desired so we can also drop Detach and use the
	//read_partial to keep it open until LN drops
	//FIXME: SAIBATO we might not want to close this conn
	//return io_read_partial(conn, reach->p, 1 ,&reach->hlen, io_tor_connect_create_onion_finished, reach);
	return io_tor_connect_close(conn);
}

static struct io_plan *io_tor_connect_after_create_onion(struct io_conn *conn, struct
							 tor_service_reaching
							 *reach)
{
	reach->p = reach->p + reach->hlen;

	if (!strstr((char *)reach->buffer, "ServiceID=")) {
		if (reach->hlen == 0)
			return io_tor_connect_close(conn);

		return io_read_partial(conn, reach->p, 1, &reach->hlen,
				       io_tor_connect_after_create_onion,
				       reach);
	} else {
		memset(reach->buffer, 0, sizeof(reach->buffer));
		return io_read_partial(conn, reach->buffer,
				       MAX_TOR_ONION_V2_ADDR_LEN, &reach->hlen,
				       io_tor_connect_create_onion_finished,
				       reach);
	}
}

//V3 tor after 3.3.3.aplha FIXME: TODO SAIBATO
//sprintf((char *)reach->buffer,"ADD_ONION NEW:ED25519-V3 Port=9735,127.0.0.1:9735\r\n");

static struct io_plan *io_tor_connect_make_onion(struct io_conn *conn, struct tor_service_reaching
						 *reach)
{
	if (strstr((char *)reach->buffer, "250 OK") == NULL)
		return io_tor_connect_close(conn);

	sprintf((char *)reach->buffer,
		"ADD_ONION NEW:RSA1024 Port=%d,127.0.0.1:%d Flags=DiscardPK,Detach\r\n",
		reach->ld->portnum, reach->ld->portnum);

	reach->hlen = strlen((char *)reach->buffer);
	reach->p = reach->buffer;
	return io_write(conn, reach->buffer, reach->hlen,
			io_tor_connect_after_create_onion, reach);
}

static struct io_plan *io_tor_connect_after_authenticate(struct io_conn *conn, struct
							 tor_service_reaching
							 *reach)
{
	return io_read(conn, reach->buffer, 7, io_tor_connect_make_onion,
		       reach);
}

static struct io_plan *io_tor_connect_authenticate(struct io_conn *conn, struct
						   tor_service_reaching
						   *reach)
{
	sprintf((char *)reach->buffer, "AUTHENTICATE %s\r\n",
		(char *)reach->cookie);

	if (reach->noauth)
		sprintf((char *)reach->buffer, "AUTHENTICATE\r\n");

	reach->hlen = strlen((char *)reach->buffer);

	return io_write(conn, reach->buffer, reach->hlen,
			io_tor_connect_after_authenticate, reach);

}

static struct io_plan *io_tor_connect_after_answer_pi(struct io_conn *conn, struct
						      tor_service_reaching
						      *reach)
{
	char *p = tal(reach, char);
	char *p2 = tal(reach, char);

	u8 *buf = tal_arrz(reach, u8, MAX_TOR_COOKIE_LEN);

	reach->noauth = false;

	if (strstr((char *)reach->buffer, "NULL"))
		reach->noauth = true;
	else if (strstr((char *)reach->buffer, "HASHEDPASSWORD")
		 && (strlen(reach->ld->tor_service_password))) {
		reach->noauth = false;
		sprintf((char *)reach->cookie, "\"%s\"",
			reach->ld->tor_service_password);
	} else if ((p = strstr((char *)reach->buffer, "COOKIEFILE="))) {
		assert(strlen(p) > 12);
		p2 = strstr((char *)(p + 12), "\"");
		assert(p2 != NULL);
		*(char *)(p + (strlen(p) - strlen(p2))) = 0;

		int fd = open((char *)(p + 12), O_RDONLY);
		if (fd < 0)
			return io_tor_connect_close(conn);
		if (!read(fd, buf, MAX_TOR_COOKIE_LEN)) {
			close(fd);
			return io_tor_connect_close(conn);
		} else
			close(fd);

		hex_encode(buf, 32, (char *)reach->cookie, 80);
		reach->noauth = false;
	} else
		return io_tor_connect_close(conn);

	return io_tor_connect_authenticate(conn, reach);

}

static struct io_plan *io_tor_connect_after_protocolinfo(struct io_conn *conn, struct
							 tor_service_reaching
							 *reach)
{

	memset(reach->buffer, 0, MAX_TOR_SERVICE_READBUFFER_LEN);
	return io_read_partial(conn, reach->buffer,
			       MAX_TOR_SERVICE_READBUFFER_LEN - 1, &reach->hlen,
			       &io_tor_connect_after_answer_pi, reach);
}

static struct io_plan *io_tor_connect_after_resp_to_connect(struct io_conn
							    *conn, struct
							    tor_service_reaching
							    *reach)
{

	sprintf((char *)reach->buffer, "PROTOCOLINFO 1\r\n");
	reach->hlen = strlen((char *)reach->buffer);

	return io_write(conn, reach->buffer, reach->hlen,
			io_tor_connect_after_protocolinfo, reach);
}

static struct io_plan *tor_connect_finish(struct io_conn *conn,
					  struct tor_service_reaching *reach)
{
	return io_tor_connect_after_resp_to_connect(conn, reach);
}

static struct io_plan *tor_conn_init(struct io_conn *conn,
				     struct lightningd *ld)
{
	struct addrinfo *ai_tor = tal(ld, struct addrinfo);
	struct tor_service_reaching *reach =
	    tal(ld, struct tor_service_reaching);

	reach->ld = ld;

	getaddrinfo(fmt_wireaddr_without_port(ld, ld->tor_serviceaddrs),
		    tal_fmt(ld, "%d", ld->tor_serviceaddrs->port), NULL,
		    &ai_tor);

	return io_connect(conn, ai_tor, &tor_connect_finish, reach);
}

bool create_tor_hidden_service_conn(struct lightningd * ld)
{
	int fd;
	struct io_conn *conn;

	return_from_service_call = false;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	conn = io_new_conn(NULL, fd, &tor_conn_init, ld);
	if (!conn) {
		return_from_service_call = true;
		err(1, "Cannot create new TOR connection");
	}
	return true;
}

bool check_return_from_service_call(void)
{
	return return_from_service_call;
}
