/* A simple standalone websocket <-> binary proxy.
 * See https://datatracker.ietf.org/doc/html/rfc6455
 */
#include "config.h"
#include <ccan/base64/base64.h>
#include <ccan/endian/endian.h>
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/mem/mem.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/setup.h>
#include <common/utils.h>
#include <connectd/sha1.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

/*
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-------+-+-------------+-------------------------------+
     |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
     |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
     |N|V|V|V|       |S|             |   (if payload len==126/127)   |
     | |1|2|3|       |K|             |                               |
     +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
     |     Extended payload length continued, if payload len == 127  |
     + - - - - - - - - - - - - - - - +-------------------------------+
     |                               |Masking-key, if MASK set to 1  |
     +-------------------------------+-------------------------------+
     | Masking-key (continued)       |          Payload Data         |
     +-------------------------------- - - - - - - - - - - - - - - - +
     :                     Payload Data continued ...                :
     + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
     |                     Payload Data continued ...                |
     +---------------------------------------------------------------+
*/

/* RFC-6455:

  A |Sec-WebSocket-Accept| header field.  The value of this header field
  is constructed by concatenating /key/, defined above in step 4 in
  Section 4.2.2, with the string "258EAFA5-
  E914-47DA-95CA-C5AB0DC85B11", taking the SHA-1 hash of this
  concatenated value to obtain a 20-byte value and base64- encoding (see
  Section 4 of [RFC4648]) this 20-byte hash.

...

   NOTE: As an example, if the value of the |Sec-WebSocket-Key| header
   field in the client's handshake were "dGhlIHNhbXBsZSBub25jZQ==", the
   server would append the string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
   to form the string "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-
   C5AB0DC85B11".  The server would then take the SHA-1 hash of this
   string, giving the value 0xb3 0x7a 0x4f 0x2c 0xc0 0x62 0x4f 0x16 0x90
   0xf6 0x46 0x06 0xcf 0x38 0x59 0x45 0xb2 0xbe 0xc4 0xea.  This value
   is then base64-encoded, to give the value
   "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", which would be returned in the
   |Sec-WebSocket-Accept| header field.
*/
static const char *websocket_accept_str(const tal_t *ctx, const char *key)
{
	u8 sha1[20];
	const char *concat;
	char base64[100];

	concat = tal_fmt(tmpctx, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11",
			 key);
	sha1digest(sha1, (const u8 *)concat, strlen(concat));
	if (base64_encode(base64, sizeof(base64), (const char *)sha1, sizeof(sha1)) == -1)
		abort();

	return tal_strdup(ctx, base64);
}

static void NORETURN PRINTF_FMT(2,3)
bad_http(int fd, const char *fmt, ...)
{
	va_list ap;
	char *resp;

	resp = tal_strdup(tmpctx, "HTTP/1.1 400 I only speak websocket\r\n\r\n");
	va_start(ap, fmt);
	tal_append_vfmt(&resp, fmt, ap);
	va_end(ap);

	write_all(fd, resp, strlen(resp));
	exit(1);
}

/* We know headers are terminated by \r\n\r\n at this point */
static const char *get_http_hdr(const tal_t *ctx, const u8 *buf, size_t buflen,
				const char *hdrname)
{
	size_t hdrlen;

	for (;;) {
		const u8 *end = memmem(buf, buflen, "\r\n", 2);
		hdrlen = end - buf;

		/* Empty line?  End of headers. */
		if (hdrlen == 0)
			return NULL;
		/* header name followed by : */
		if (memstarts(buf, hdrlen, hdrname, strlen(hdrname))
		    && buf[strlen(hdrname)] == ':')
			break;
		buf = end + 2;
	}

	buf += strlen(hdrname) + 1;
	hdrlen -= strlen(hdrname) + 1;

	/* Ignore leading whitespace (technically, they can split
	 * fields over multiple lines, but that's silly for the fields
	 * we're dealing with, so Naah). */
	while (hdrlen && cisspace(*buf)) {
		buf++;
		hdrlen--;
	}

	return tal_strndup(ctx, (const char *)buf, hdrlen);
}

static bool http_headers_complete(const u8 *buf, size_t len)
{
	return memmem(buf, len, "\r\n\r\n", 4) != NULL;
}

static void http_respond(int fd, const u8 *buf, size_t len)
{
	const char *hdr;
	char *resp;

	/* RFC-6455:

	   The client's opening handshake consists of the following
	   parts.  If the server, while reading the handshake, finds
	   that the client did not send a handshake that matches the
	   description below ...  the server MUST stop processing the
	   client's handshake and return an HTTP response with an
	   appropriate error code (such as 400 Bad Request).

	   1.   An HTTP/1.1 or higher GET request, including a "Request-URI"
	   [RFC2616] that should be interpreted as a /resource name/
	   defined in Section 3 (or an absolute HTTP/HTTPS URI containing
	   the /resource name/).

	   2.   A |Host| header field containing the server's authority.

	   3.   An |Upgrade| header field containing the value "websocket",
	   treated as an ASCII case-insensitive value.

	   4.   A |Connection| header field that includes the token "Upgrade",
	   treated as an ASCII case-insensitive value.

	   5.   A |Sec-WebSocket-Key| header field with a base64-encoded (see
	   Section 4 of [RFC4648]) value that, when decoded, is 16 bytes in
	   length.

	   6.   A |Sec-WebSocket-Version| header field, with a value of 13.
	*/
	hdr = get_http_hdr(tmpctx, buf, len, "Upgrade");
	if (!hdr || !strstr(hdr, "websocket"))
		bad_http(fd, "Upgrade: websocket missing");
	hdr = get_http_hdr(tmpctx, buf, len, "Connection");
	if (!hdr || !strstr(hdr, "Upgrade"))
		bad_http(fd, "Connection: Upgrade missing");
	hdr = get_http_hdr(tmpctx, buf, len, "Sec-WebSocket-Version");
	if (!hdr || !streq(hdr, "13"))
		bad_http(fd, "Sec-WebSocket-Version: must be 13");
	hdr = get_http_hdr(tmpctx, buf, len, "Sec-WebSocket-Key");
	if (!hdr)
		bad_http(fd, "Sec-WebSocket-Key missing");

	resp = tal_fmt(tmpctx,
		       "HTTP/1.1 101 Switching Protocols\r\n"
		       "Upgrade: websocket\r\n"
		       "Connection: Upgrade\r\n"
		       "Sec-WebSocket-Accept: %s\r\n\r\n",
		       websocket_accept_str(tmpctx, hdr));

	if (!write_all(fd, resp, strlen(resp)))
		exit(0);
}

static void http_upgrade(int fd)
{
	u8 buf[65536];
	size_t len = 0;

	alarm(60);
	while (!http_headers_complete(buf, len)) {
		int r;
		r = read(STDIN_FILENO, buf + len, sizeof(buf) - len);
		if (r <= 0)
			bad_http(STDIN_FILENO, "No header end after %zu bytes",
				 len);
		len += r;
	}
	http_respond(STDIN_FILENO, buf, len);
	alarm(0);
}

static void lightningd_to_websocket(int lightningfd, int wsfd)
{
	/* We prepend ws header */
	u8 buf[4 + 65535];
	int len;
	/* Not continued frame (0x80), opcode = 2 (binary) */
	const u8 firstbyte = 0x82;
	size_t off;

	len = read(lightningfd, 4 + buf, sizeof(buf) - 4);
	if (len <= 0)
		exit(0);

	if (len > 125) {
		buf[0] = firstbyte;
		buf[1] = 126;
		buf[2] = (len >> 8);
		buf[3] = len;
		off = 0;
		len += 4;
	} else {
		buf[2] = firstbyte;
		buf[3] = len;
		off = 2;
		len += 2;
	}
	if (!write_all(wsfd, buf + off, len))
		exit(0);
}

/* Returns payload size, sets inmask, is_binframe */
static size_t read_payload_header(int fd, u8 inmask[4], bool *is_binframe)
{
	/* Worst case header. */
	u8 frame_hdr[20];
	bool mask_set;
	size_t hdrsize = 2, len;

	/* First two bytes define hdr size. */
	if (!read_all(fd, frame_hdr, 2))
		exit(0);

	/* RFC-6455:
	 *  %x2 denotes a binary frame
	 */
	*is_binframe = ((frame_hdr[0] & 0x0F) == 2);
	mask_set = (frame_hdr[1] & 0x80);
	len = (frame_hdr[1] & 0x7f);

	if (len == 126)
		hdrsize += 2;
	else if (len == 127)
		hdrsize += 8;

	if (mask_set)
		hdrsize += 4;

	/* Read rest of hdr if necessary */
	if (hdrsize > 2 && !read_all(fd, frame_hdr + 2, hdrsize - 2))
		exit(0);

	if (len == 126) {
		be16 be16len;
		memcpy(&be16len, frame_hdr + 2, 2);
		len = be16_to_cpu(be16len);
	} else if (len == 127) {
		be64 be64len;
		memcpy(&be64len, frame_hdr + 2, 8);
		len = be64_to_cpu(be64len);
	}

	if (mask_set) {
		memcpy(inmask, frame_hdr + hdrsize - 4, 4);
		hdrsize += 4;
	} else
		memset(inmask, 0, 4);

	return len;
}

static void apply_mask(u8 *buf, size_t len, const u8 inmask[4])
{
	for (size_t i = 0; i < len; i++)
		buf[i] ^= inmask[i % 4];
}

static void websocket_to_lightningd(int wsfd, int lightningfd)
{
	size_t len;
	u8 inmask[4];
	bool is_binframe;

	len = read_payload_header(wsfd, inmask, &is_binframe);
	while (len > 0) {
		u8 buf[65536];
		int rlen = len;

		if (rlen > sizeof(buf))
			rlen = sizeof(buf);

		rlen = read(wsfd, buf, rlen);
		if (rlen <= 0)
			exit(0);
		apply_mask(buf, rlen, inmask);
		len -= rlen;
		/* We ignore non binary frames (FIXME: Send error!) */
		if (is_binframe && !write_all(lightningfd, buf, rlen))
			exit(0);
	}
}

/* stdin goes to the client, stdout goes to lightningd */
int main(int argc, char *argv[])
{
	struct pollfd pfds[2];

	common_setup(argv[0]);

	if (argc != 1)
		errx(1, "Usage: %s", argv[0]);

	/* Do HTTP-style negotiation to get into websocket frames. */
	io_fd_block(STDIN_FILENO, true);
	http_upgrade(STDIN_FILENO);

	pfds[0].fd = STDIN_FILENO;
	pfds[0].events = POLLIN;
	pfds[1].fd = STDOUT_FILENO;
	pfds[1].events = POLLIN;

	for (;;) {
		poll(pfds, 2, -1);

		if (pfds[1].revents & POLLIN)
			lightningd_to_websocket(STDOUT_FILENO, STDIN_FILENO);
		if (pfds[0].revents & POLLIN)
			websocket_to_lightningd(STDIN_FILENO, STDOUT_FILENO);
	}

	common_shutdown();
	exit(0);
}
