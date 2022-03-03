#include "config.h"
#include <ccan/err/err.h>
#include <ccan/rbuf/rbuf.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <common/base64.h>
#include <common/utils.h>
#include <common/wireaddr.h>
#include <connectd/tor_autoservice.h>
#include <errno.h>
#include <lightningd/log.h>
#include <netdb.h>
#include <unistd.h>


static void *buf_resize(struct membuf *mb, void *buf, size_t len)
{
	tal_resize(&buf, len);
	return buf;
}

static void tor_send_cmd(struct rbuf *rbuf, const char *cmd)
{
	status_io(LOG_IO_OUT, NULL, "torcontrol", cmd, strlen(cmd));
	if (!write_all(rbuf->fd, cmd, strlen(cmd)))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Writing '%s' to Tor socket", cmd);

	status_io(LOG_IO_OUT, NULL, "torcontrol", "\r\n", 2);
	if (!write_all(rbuf->fd, "\r\n", 2))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Writing CRLF to Tor socket");
}

static char *tor_response_line_wfail(struct rbuf *rbuf)
{
	char *line = NULL;

	while ((line = rbuf_read_str(rbuf, '\n')) != NULL) {
		status_io(LOG_IO_IN, NULL, "torcontrol", line, strlen(line));

		/* Weird response */
		if (!strstarts(line, "250") && !strstarts(line, "550"))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Tor returned '%s'", line);

		/* Last line */
		if (strstarts(line, "250 ") || strstarts(line, "550 "))
			break;

		return line + 4;
	}
	if (line)
		return line + 4;
	else
		return NULL;
}

static char *tor_response_line(struct rbuf *rbuf)
{
	char *line;

	while ((line = rbuf_read_str(rbuf, '\n')) != NULL) {
		status_io(LOG_IO_IN, NULL, "torcontrol", line, strlen(line));

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
				   const struct wireaddr *local,
				   bool use_v3_autotor,
				   u16 port)
{
	char *line;
	struct wireaddr *onion;

	/* Now that V3 is out of Beta default to V3 autoservice onions if version is above 0.4
	*/
	tor_send_cmd(rbuf, "PROTOCOLINFO 1");

	while ((line = tor_response_line(rbuf)) != NULL) {

		if (!strstarts(line, "VERSION Tor="))
			continue;

		if (use_v3_autotor)
			if (strstr(line, "\"0.0") ||
				strstr(line, "\"0.1") ||
				strstr(line, "\"0.2") ||
				strstr(line, "\"0.3")) {
						use_v3_autotor = false;
						status_unusual("Autotor: fallback to try a V2 onion service, your Tor version is smaller than 0.4.x.x");
			}
	};

	if (!use_v3_autotor) {
		tor_send_cmd(rbuf,
		     tal_fmt(tmpctx, "ADD_ONION NEW:RSA1024 Port=%d,%s Flags=DiscardPK,Detach",
			     port, fmt_wireaddr(tmpctx, local)));
	} else {
		tor_send_cmd(rbuf,
		     tal_fmt(tmpctx, "ADD_ONION NEW:ED25519-V3 Port=%d,%s Flags=DiscardPK,Detach",
			     port, fmt_wireaddr(tmpctx, local)));
	}

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
		if (!parse_wireaddr(name, onion, local->port, false, NULL))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Tor gave bad onion name '%s'", name);
		status_info("New autotor service onion address: \"%s:%d\" bound from extern port:%d", name, local->port, port);
		discard_remaining_response(rbuf);
		return onion;
	}
	status_failed(STATUS_FAIL_INTERNAL_ERROR,
		      "Tor didn't give us a ServiceID");
}

static struct wireaddr *make_fixed_onion(const tal_t *ctx,
				   struct rbuf *rbuf,
				   const struct wireaddr *local, const char *blob, u16 port)
{
	char *line;
	struct wireaddr *onion;
	char *blob64;

	blob64 = b64_encode(tmpctx, blob, 64);

	tor_send_cmd(rbuf,
			 tal_fmt(tmpctx, "ADD_ONION ED25519-V3:%s Port=%d,%s Flags=DiscardPK",
			 blob64, port, fmt_wireaddr(tmpctx, local)));

	while ((line = tor_response_line_wfail(rbuf))) {
		const char *name;
		if (strstarts(line, "Onion address collision"))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Tor address in use");

		if (!strstarts(line, "ServiceID="))
			continue;
		line += strlen("ServiceID=");
		/* Strip the trailing CR */
		if (strchr(line, '\r'))
			*strchr(line, '\r') = '\0';

		name = tal_fmt(tmpctx, "%s.onion", line);
		onion = tal(ctx, struct wireaddr);
		if (!parse_wireaddr(name, onion, port, false, NULL))
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Tor gave bad onion name '%s'", name);
		#ifdef SUPERVERBOSE
		 status_info("Static Tor service onion address: \"%s:%d,%s\"from blob %s base64 %s ",
						name, port ,fmt_wireaddr(tmpctx, local), blob ,blob64);
		#else
		status_info("Static Tor service onion address: \"%s:%d,%s\" bound from extern port %d ",
						name, port ,fmt_wireaddr(tmpctx, local), port);
		#endif
		discard_remaining_response(rbuf);
		return onion;
	}
	return NULL;
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

struct wireaddr *tor_autoservice(const tal_t *ctx,
				 const struct wireaddr_internal *tor_serviceaddr,
				 const char *tor_password,
				 const struct wireaddr *laddr,
				 const bool use_v3_autotor)
{
	int fd;
	struct wireaddr *onion;
	struct addrinfo *ai_tor;
	struct rbuf rbuf;
	char *buffer;

	ai_tor = wireaddr_to_addrinfo(tmpctx, &tor_serviceaddr->u.torservice.address);

	fd = socket(ai_tor->ai_family, SOCK_STREAM, 0);
	if (fd < 0)
		err(1, "Creating stream socket for Tor");

	if (connect(fd, ai_tor->ai_addr, ai_tor->ai_addrlen) != 0)
		err(1, "Connecting stream socket to Tor service");

	buffer = tal_arr(tmpctx, char, rbuf_good_size(fd));
	rbuf_init(&rbuf, fd, buffer, tal_count(buffer), buf_resize);

	negotiate_auth(&rbuf, tor_password);
	onion = make_onion(ctx, &rbuf, laddr, use_v3_autotor, tor_serviceaddr->u.torservice.port);

	/*on the other hand we can stay connected until ln finish to keep onion alive and then vanish */
	//because when we run with Detach flag as we now do every start of LN creates a new addr while the old
	//stays valid until reboot this might not be desired so we can also drop Detach and use the
	//read_partial to keep it open until LN drops
	//FIXME: SAIBATO we might not want to close this conn
	close(fd);

	return onion;
}

struct wireaddr *tor_fixed_service(const tal_t *ctx,
				 const struct wireaddr_internal *tor_serviceaddr,
				 const char *tor_password,
				 const char *blob,
				 const struct wireaddr *bind,
				 const u8 index)
{
	int fd;
	const struct wireaddr *laddr;
	struct wireaddr *onion;
	struct addrinfo *ai_tor;
	struct rbuf rbuf;
	char *buffer;

	laddr = bind;
	ai_tor = wireaddr_to_addrinfo(tmpctx, &tor_serviceaddr->u.torservice.address);

	fd = socket(ai_tor->ai_family, SOCK_STREAM, 0);
	if (fd < 0)
		err(1, "Creating stream socket for Tor");

	if (connect(fd, ai_tor->ai_addr, ai_tor->ai_addrlen) != 0)
		err(1, "Connecting stream socket to Tor service");

	buffer = tal_arr(tmpctx, char, rbuf_good_size(fd));
	rbuf_init(&rbuf, fd, buffer, tal_count(buffer), buf_resize);

	negotiate_auth(&rbuf, tor_password);

	onion = make_fixed_onion(ctx, &rbuf, laddr, blob, tor_serviceaddr->u.torservice.port);
	/*on the other hand we can stay connected until ln finish to keep onion alive and then vanish
	* because when we run with Detach flag as we now do every start of LN creates a new addr while the old
	* stays valid until reboot this might not be desired so we can also drop Detach and use the
	* read_partial to keep it open until LN drops
	* DO NOT CLOSE FD TO KEEP ADDRESS ALIVE AS WE DO NOT DETACH WITH STATIC ADDRESS
	*/
	return onion;
}
