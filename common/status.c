#include <assert.h>
#include <ccan/breakpoint/breakpoint.h>
#include <ccan/endian/endian.h>
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <common/daemon_conn.h>
#include <common/status.h>
#include <common/utils.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

static int status_fd = -1;
static struct daemon_conn *status_conn;
const void *trc;
volatile bool logging_io = false;

static void got_sigusr1(int signal)
{
	logging_io = !logging_io;
}

static void setup_logging_sighandler(void)
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_handler = got_sigusr1;
	act.sa_flags = SA_RESTART;

	sigaction(SIGUSR1, &act, NULL);
}

void status_setup_sync(int fd)
{
	assert(status_fd == -1);
	assert(!status_conn);
	status_fd = fd;
	trc = tal_tmpctx(NULL);
	setup_logging_sighandler();
}

void status_setup_async(struct daemon_conn *master)
{
	assert(status_fd == -1);
	assert(!status_conn);
	status_conn = master;

	/* Don't use tmpctx here, otherwise debug_poll gets upset. */
	trc = tal(NULL, char);
	setup_logging_sighandler();
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

static void status_io_full(enum side sender, const u8 *p)
{
	u16 type = STATUS_LOG_MIN + LOG_IO;
	u8 *msg = tal_arr(NULL, u8, 0);

	towire_u16(&msg, type);
	towire_bool(&msg, sender == REMOTE);
	towire(&msg, p, tal_len(p));
	if (too_large(tal_len(msg), type))
		tal_resize(&msg, 65535);

	if (status_fd >= 0) {
		if (!wire_sync_write(status_fd, take(msg)))
			err(1, "Writing out status %u len %zu",
			    type, tal_len(p));
	} else {
		daemon_conn_send(status_conn, take(msg));
	}
}

static void status_io_short(enum side sender, const u8 *p)
{
	status_debug("%s %s",
		     sender == LOCAL ? "peer_out" : "peer_in",
		     wire_type_name(fromwire_peektype(p)));
}

void status_io(enum side sender, const u8 *p)
{
	if (logging_io)
		status_io_full(sender, p);
	else
		status_io_short(sender, p);
}

void status_vfmt(enum log_level level, const char *fmt, va_list ap)
{
	char *str;

	str = tal_vfmt(NULL, fmt, ap);
	status_send_with_hdr(STATUS_LOG_MIN + level, str, strlen(str));
	tal_free(str);

	/* Free up any temporary children. */
	if (tal_first(trc)) {
		tal_free(trc);
		trc = tal(NULL, char);
	}
}

void status_fmt(enum log_level level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	status_vfmt(level, fmt, ap);
	va_end(ap);
}

void status_failed(enum status_fail code, const char *fmt, ...)
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

void master_badmsg(u32 type_expected, const u8 *msg)
{
	if (!msg)
		status_failed(STATUS_FAIL_MASTER_IO,
			      "failed reading msg %u: %s",
			      type_expected, strerror(errno));
	status_failed(STATUS_FAIL_MASTER_IO,
		      "Error parsing %u: %s",
		      type_expected, tal_hex(trc, msg));
}
