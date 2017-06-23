#include "utils.h"
#include "wire/wire.h"
#include "wire/wire_sync.h"
#include <assert.h>
#include <ccan/breakpoint/breakpoint.h>
#include <ccan/endian/endian.h>
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <lightningd/daemon_conn.h>
#include <lightningd/status.h>
#include <stdarg.h>

static int status_fd = -1;
static struct daemon_conn *status_conn;
const void *trc;

void status_setup_sync(int fd)
{
	assert(status_fd == -1);
	assert(!status_conn);
	status_fd = fd;
	trc = tal_tmpctx(NULL);
}

void status_setup_async(struct daemon_conn *master)
{
	assert(status_fd == -1);
	assert(!status_conn);
	status_conn = master;
	trc = tal_tmpctx(NULL);
}

static bool too_large(size_t len, int type)
{
	if (len > 65535) {
		status_trace("About to truncate msg %i from %zu bytes",
			     type, len);
		return true;
	}
	return false;
}

void status_send_sync(const u8 *p)
{
	const u8 *msg = p;
	assert(status_fd >= 0);

	if (too_large(tal_count(p), fromwire_peektype(p)))
		msg = tal_dup_arr(p, u8, p, 65535, 0);

	if (!wire_sync_write(status_fd, msg))
		err(1, "Writing out status len %zu", tal_count(msg));
	tal_free(p);
}

static void status_send_with_hdr(u16 type, const void *p, size_t len)
{
	u8 *msg = tal_arr(NULL, u8, 0);
	towire_u16(&msg, type);
	towire(&msg, p, len);
	if (too_large(tal_len(msg), type))
		tal_resize(&msg, 65535);

	if (status_fd >= 0) {
		if (!wire_sync_write(status_fd, take(msg)))
			err(1, "Writing out status %u len %zu", type, len);
	} else {
		daemon_conn_send(status_conn, take(msg));
	}
}

void status_trace(const char *fmt, ...)
{
	va_list ap;
	char *str;

	va_start(ap, fmt);
	str = tal_vfmt(NULL, fmt, ap);
	status_send_with_hdr(STATUS_TRACE, str, strlen(str));
	tal_free(str);
	va_end(ap);

	/* Free up any temporary children. */
	tal_free(trc);
	trc = tal_tmpctx(NULL);
}

void status_failed(u16 code, const char *fmt, ...)
{
	va_list ap;
	char *str;

	breakpoint();
	assert(code & STATUS_FAIL);
	va_start(ap, fmt);
	str = tal_vfmt(NULL, fmt, ap);
	status_send_with_hdr(code, str, strlen(str));
	va_end(ap);

	/* Don't let it take forever. */
	alarm(10);
	if (status_conn)
		daemon_conn_sync_flush(status_conn);

	exit(0x80 | (code & 0xFF));
}
