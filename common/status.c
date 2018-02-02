#include <assert.h>
#include <ccan/breakpoint/breakpoint.h>
#include <ccan/endian/endian.h>
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <common/daemon_conn.h>
#include <common/gen_status_wire.h>
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

static void status_send(const u8 *msg TAKES)
{
	if (status_fd >= 0) {
		int type =fromwire_peektype(msg);
		if (!wire_sync_write(status_fd, msg))
			err(1, "Writing out status %i", type);
	} else {
		daemon_conn_send(status_conn, msg);
	}
}

static void status_io_full(enum side sender, const u8 *p)
{
	status_send(take(towire_status_io(NULL, sender == REMOTE, p)));
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
	status_send(take(towire_status_log(NULL, level, str)));
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

void status_failed(enum status_failreason reason, const char *fmt, ...)
{
	va_list ap;
	char *str;

	breakpoint();
	va_start(ap, fmt);
	str = tal_vfmt(NULL, fmt, ap);
	status_send(take(towire_status_fail(NULL, reason, str)));
	va_end(ap);

	/* Don't let it take forever. */
	alarm(10);
	if (status_conn)
		daemon_conn_sync_flush(status_conn);

	exit(0x80 | (reason & 0xFF));
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
