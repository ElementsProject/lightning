#include "status.h"
#include "utils.h"
#include "wire/wire.h"
#include "wire/wire_sync.h"
#include <assert.h>
#include <ccan/breakpoint/breakpoint.h>
#include <ccan/endian/endian.h>
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/str/str.h>
#include <stdarg.h>

static int status_fd = -1;
const void *trc;

void status_setup(int fd)
{
	status_fd = fd;
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

void status_send(const u8 *p)
{
	const u8 *msg = p;
	assert(status_fd >= 0);

	if (too_large(tal_count(p), fromwire_peektype(p)))
		msg = tal_dup_arr(p, u8, p, 65535, 0);

	if (!wire_sync_write(status_fd, msg))
		err(1, "Writing out status len %zu", tal_count(msg));
	tal_free(p);
}

void status_send_fd(int fd)
{
	assert(status_fd >= 0);
	assert(fd >= 0);

	if (!fdpass_send(status_fd, fd))
		err(1, "Writing out status fd %i", fd);
	close(fd);
}

static void status_send_with_hdr(u16 type, const void *p, size_t len)
{
	be16 be_type, be_len;

	if (too_large(len + sizeof(be_type), type))
		len = 65535 - sizeof(be_type);

	be_type = cpu_to_be16(type);
	be_len = cpu_to_be16(len + sizeof(be_type));
	assert(status_fd >= 0);
	assert(be16_to_cpu(be_len) == len + sizeof(be_type));

	if (!write_all(status_fd, &be_len, sizeof(be_len))
	    || !write_all(status_fd, &be_type, sizeof(be_type))
	    || !write_all(status_fd, p, len))
		err(1, "Writing out status %u len %zu", type, len);
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

	exit(0x80 | (code & 0xFF));
}
