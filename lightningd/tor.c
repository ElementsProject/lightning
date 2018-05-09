#include <arpa/inet.h>
#include <assert.h>
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/rbuf/rbuf.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/wireaddr.h>
#include <errno.h>
#include <fcntl.h>
#include <lightningd/log.h>
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

static void *buf_resize(void *buf, size_t len)
{
	tal_resize(&buf, len);
	return buf;
}

static void tor_send_cmd(struct lightningd *ld,
			 struct rbuf *rbuf, const char *cmd)
{
	log_io(ld->log, LOG_IO_OUT, "torcontrol", cmd, strlen(cmd));
	if (!write_all(rbuf->fd, cmd, strlen(cmd)))
		err(1, "Writing '%s' to Tor socket", cmd);

	log_io(ld->log, LOG_IO_OUT, "torcontrol", "\r\n", 2);
	if (!write_all(rbuf->fd, "\r\n", 2))
		err(1, "Writing CRLF to Tor socket");
}

static char *tor_response_line(struct lightningd *ld, struct rbuf *rbuf)
{
	char *line;

	while ((line = rbuf_read_str(rbuf, '\n', buf_resize)) != NULL) {
		log_io(ld->log, LOG_IO_IN, "torcontrol", line, strlen(line));

		/* Weird response */
		if (!strstarts(line, "250"))
			errx(1, "Tor returned '%s'", line);

		/* Last line */
		if (strstarts(line, "250 "))
			break;

		return line + 4;
	}
	return NULL;
}

static void discard_remaining_response(struct lightningd *ld, struct rbuf *rbuf)
{
	while (tor_response_line(ld, rbuf));
}

static void make_onion(struct lightningd *ld, struct rbuf *rbuf)
{
	char *line;

//V3 tor after 3.3.3.aplha FIXME: TODO SAIBATO
//sprintf((char *)reach->buffer,"ADD_ONION NEW:ED25519-V3 Port=9735,127.0.0.1:9735\r\n");
	tor_send_cmd(ld, rbuf,
		     tal_fmt(tmpctx, "ADD_ONION NEW:RSA1024 Port=%d,127.0.0.1:%d Flags=DiscardPK,Detach",
			     ld->portnum, ld->portnum));

	while ((line = tor_response_line(ld, rbuf)) != NULL) {
		size_t n;

		if (!strstarts(line, "ServiceID="))
			continue;
		line += strlen("ServiceID=");
		/* Strip the trailing CR */
		if (strchr(line, '\r'))
			*strchr(line, '\r') = '\0';

		n = tal_count(ld->proposed_wireaddr);
		tal_resize(&ld->proposed_wireaddr, n + 1);
		tal_resize(&ld->proposed_listen_announce, n + 1);
		parse_wireaddr_internal(tal_fmt(tmpctx, "%s.onion", line),
					&ld->proposed_wireaddr[n],
					ld->portnum, false, NULL);
		ld->proposed_listen_announce[n] = ADDR_ANNOUNCE;
		discard_remaining_response(ld, rbuf);
		return;
	}
	errx(1, "Tor didn't give us a ServiceID");
}

/* https://gitweb.torproject.org/torspec.git/tree/control-spec.txt:
 *
 *     MidReplyLine = StatusCode "-" ReplyLine
 *     DataReplyLine = StatusCode "+" ReplyLine CmdData
 *         EndReplyLine = StatusCode SP ReplyLine
 *         ReplyLine = [ReplyText] CRLF
 *         ReplyText = XXXX
 *         StatusCode = 3DIGIT
 */
static void negotiate_auth(struct lightningd *ld, struct rbuf *rbuf)
{
	char *line;
	char *cookiefile = NULL;
	int cookiefileerrno;

	tor_send_cmd(ld, rbuf, "PROTOCOLINFO 1");

	while ((line = tor_response_line(ld, rbuf)) != NULL) {
		const char *p;

		if (!strstarts(line, "AUTH METHODS="))
			continue;

		if (strstr(line, "NULL")) {
			discard_remaining_response(ld, rbuf);
			tor_send_cmd(ld, rbuf, "AUTHENTICATE");
			discard_remaining_response(ld, rbuf);
			return;
		} else if (strstr(line, "HASHEDPASSWORD")
			   && strlen(ld->tor_service_password)) {
			discard_remaining_response(ld, rbuf);
			tor_send_cmd(ld, rbuf,
				     tal_fmt(tmpctx, "AUTHENTICATE \"%s\"",
					     ld->tor_service_password));
			discard_remaining_response(ld, rbuf);
			return;
		} else if ((p = strstr(line, "COOKIEFILE=\"")) != NULL) {
			char *contents, *end;

			p += strlen("COOKIEFILE=\"");
			end = strstr(p, "\"");
			if (!end)
				errx(1, "Tor protocolinfo bad line '%s'", line);
			*end = '\0';

			/* If we can't access this, try other methods */
			cookiefile = tal_strdup(tmpctx, p);
			contents = grab_file(tmpctx, p);
			if (!contents) {
				cookiefileerrno = errno;
				fprintf(stderr, "No cookies for me!\n");
				continue;
			}
			discard_remaining_response(ld, rbuf);
			tor_send_cmd(ld, rbuf,
				     tal_fmt(tmpctx, "AUTHENTICATE %s",
					     tal_hexstr(tmpctx,
							contents,
							tal_len(contents)-1)));
			discard_remaining_response(ld, rbuf);
			return;
		}
	}

	/* Now report if we tried cookie file and it failed */
	if (cookiefile) {
		errno = cookiefileerrno;
		err(1, "Could not open Tor cookie file '%s'", cookiefile);
	}

	errx(1, "Tor protocolinfo did not give auth");
}

void tor_init(struct lightningd *ld)
{
	int fd;
	struct addrinfo *ai_tor;
	struct rbuf rbuf;
	char *buffer;

	if (!ld->config.tor_enable_auto_hidden_service)
		return;

	/* FIXME: Need better way to convert wireaddr to addrinfo... */
	if (getaddrinfo(fmt_wireaddr_without_port(ld, ld->tor_serviceaddr),
			tal_fmt(tmpctx, "%d", ld->tor_serviceaddr->port), NULL,
			&ai_tor) != 0)
		errx(1, "getaddrinfo failed for Tor service");

	fd = socket(ai_tor->ai_family, SOCK_STREAM, 0);
	if (fd < 0)
		err(1, "Creating stream socket for Tor");

	if (connect(fd, ai_tor->ai_addr, ai_tor->ai_addrlen) != 0)
		err(1, "Connecting stream socket to Tor service");

	buffer = tal_arr(tmpctx, char, rbuf_good_size(fd));
	rbuf_init(&rbuf, fd, buffer, tal_len(buffer));

	negotiate_auth(ld, &rbuf);
	make_onion(ld, &rbuf);

	/*on the other hand we can stay connected until ln finish to keep onion alive and then vanish */
	//because when we run with Detach flag as we now do every start of LN creates a new addr while the old
	//stays valid until reboot this might not be desired so we can also drop Detach and use the
	//read_partial to keep it open until LN drops
	//FIXME: SAIBATO we might not want to close this conn
	close(fd);
}
