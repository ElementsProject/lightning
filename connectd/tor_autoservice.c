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
#include <connectd/tor_autoservice.h>
#include <errno.h>
#include <fcntl.h>
#include <lightningd/log.h>
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

static void tor_send_cmd(struct rbuf *rbuf, const char *cmd)
{
	status_io(LOG_IO_OUT, "torcontrol", cmd, strlen(cmd));
	if (!write_all(rbuf->fd, cmd, strlen(cmd)))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Writing '%s' to Tor socket", cmd);

	status_io(LOG_IO_OUT, "torcontrol", "\r\n", 2);
	if (!write_all(rbuf->fd, "\r\n", 2))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Writing CRLF to Tor socket");
}

static char *tor_response_line(struct rbuf *rbuf)
{
	char *line;

	while ((line = rbuf_read_str(rbuf, '\n', buf_resize)) != NULL) {
		status_io(LOG_IO_IN, "torcontrol", line, strlen(line));

		/* Weird response */
		if (!strstarts(line, "250"))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Tor returned '%s'", line);

		/* Last line */
		if (strstarts(line, "250 "))
			break;

		return line + 4;
	}
	return NULL;
}

static void discard_remaining_response(struct rbuf *rbuf)
{
	while (tor_response_line(rbuf));
}

static struct wireaddr *make_onion(const tal_t *ctx,
				   struct rbuf *rbuf,
				   const struct wireaddr *local)
{
	char *line;
	struct wireaddr *onion;

//V3 tor after 3.3.3.aplha FIXME: TODO SAIBATO
//sprintf((char *)reach->buffer,"ADD_ONION NEW:ED25519-V3 Port=9735,127.0.0.1:9735\r\n");
	tor_send_cmd(rbuf,
		     tal_fmt(tmpctx, "ADD_ONION NEW:RSA1024 Port=%d,%s Flags=DiscardPK,Detach",
			     /* FIXME: We *could* allow user to set Tor port */
			     DEFAULT_PORT, fmt_wireaddr(tmpctx, local)));

	while ((line = tor_response_line(rbuf)) != NULL) {
		const char *name;

		if (!strstarts(line, "ServiceID="))
			continue;
		line += strlen("ServiceID=");
		/* Strip the trailing CR */
		if (strchr(line, '\r'))
			*strchr(line, '\r') = '\0';

		name = tal_fmt(tmpctx, "%s.onion", line);
		onion = tal(ctx, struct wireaddr);
		if (!parse_wireaddr(name, onion, 0, false, NULL))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Tor gave bad onion name '%s'", name);
		discard_remaining_response(rbuf);
		return onion;
	}
	status_failed(STATUS_FAIL_INTERNAL_ERROR,
		      "Tor didn't give us a ServiceID");
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
static void negotiate_auth(struct rbuf *rbuf, const char *tor_password)
{
	char *line;
	char *cookiefile = NULL;
	int cookiefileerrno = 0;

	tor_send_cmd(rbuf, "PROTOCOLINFO 1");

	while ((line = tor_response_line(rbuf)) != NULL) {
		const char *p;

		if (!strstarts(line, "AUTH METHODS="))
			continue;

		if (strstr(line, "NULL")) {
			discard_remaining_response(rbuf);
			tor_send_cmd(rbuf, "AUTHENTICATE");
			discard_remaining_response(rbuf);
			return;
		} else if (strstr(line, "HASHEDPASSWORD")
			   && strlen(tor_password)) {
			discard_remaining_response(rbuf);
			tor_send_cmd(rbuf,
				     tal_fmt(tmpctx, "AUTHENTICATE \"%s\"",
					     tor_password));
			discard_remaining_response(rbuf);
			return;
		} else if ((p = strstr(line, "COOKIEFILE=\"")) != NULL) {
			char *contents, *end;

			p += strlen("COOKIEFILE=\"");
			end = strstr(p, "\"");
			if (!end)
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
					      "Tor protocolinfo bad line '%s'",
					      line);
			*end = '\0';

			/* If we can't access this, try other methods */
			cookiefile = tal_strdup(tmpctx, p);
			contents = grab_file(tmpctx, p);
			if (!contents) {
				cookiefileerrno = errno;
				continue;
			}
			assert(tal_count(contents) != 0);
			discard_remaining_response(rbuf);
			tor_send_cmd(rbuf,
				     tal_fmt(tmpctx, "AUTHENTICATE %s",
					     tal_hexstr(tmpctx,
							contents,
							tal_count(contents)-1)));
			discard_remaining_response(rbuf);
			return;
		}
	}

	/* Now report if we tried cookie file and it failed */
	if (cookiefile)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Could not open Tor cookie file '%s': %s",
			      cookiefile, strerror(cookiefileerrno));

	status_failed(STATUS_FAIL_INTERNAL_ERROR,
		      "Tor protocolinfo did not give auth");
}

/* We need to have a bound address we can tell Tor to connect to */
static const struct wireaddr *
find_local_address(const struct wireaddr_internal *bindings)
{
	for (size_t i = 0; i < tal_count(bindings); i++) {
		if (bindings[i].itype != ADDR_INTERNAL_WIREADDR)
			continue;
		if (bindings[i].u.wireaddr.type != ADDR_TYPE_IPV4
		    && bindings[i].u.wireaddr.type != ADDR_TYPE_IPV6)
			continue;
		return &bindings[i].u.wireaddr;
	}
	status_failed(STATUS_FAIL_INTERNAL_ERROR,
		      "No local address found to tell Tor to connect to");
}

struct wireaddr *tor_autoservice(const tal_t *ctx,
				 const struct wireaddr *tor_serviceaddr,
				 const char *tor_password,
				 const struct wireaddr_internal *bindings)
{
	int fd;
	const struct wireaddr *laddr;
	struct wireaddr *onion;
	struct addrinfo *ai_tor;
	struct rbuf rbuf;
	char *buffer;

	laddr = find_local_address(bindings);
	ai_tor = wireaddr_to_addrinfo(tmpctx, tor_serviceaddr);

	fd = socket(ai_tor->ai_family, SOCK_STREAM, 0);
	if (fd < 0)
		err(1, "Creating stream socket for Tor");

	if (connect(fd, ai_tor->ai_addr, ai_tor->ai_addrlen) != 0)
		err(1, "Connecting stream socket to Tor service");

	buffer = tal_arr(tmpctx, char, rbuf_good_size(fd));
	rbuf_init(&rbuf, fd, buffer, tal_count(buffer));

	negotiate_auth(&rbuf, tor_password);
	onion = make_onion(ctx, &rbuf, laddr);

	/*on the other hand we can stay connected until ln finish to keep onion alive and then vanish */
	//because when we run with Detach flag as we now do every start of LN creates a new addr while the old
	//stays valid until reboot this might not be desired so we can also drop Detach and use the
	//read_partial to keep it open until LN drops
	//FIXME: SAIBATO we might not want to close this conn
	close(fd);

	return onion;
}
