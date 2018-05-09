#include <assert.h>
#include <ccan/breakpoint/breakpoint.h>
#include <ccan/endian/endian.h>
#include <ccan/err/err.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/str/str.h>
#include <common/daemon_conn.h>
#include <common/gen_status_wire.h>
#include <common/status.h>
#include <common/utils.h>
#include <errno.h>
#include <signal.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

static int status_fd = -1;
static struct daemon_conn *status_conn;
volatile bool logging_io = false;

static void got_sigusr1(int signal UNUSED)
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
	setup_logging_sighandler();
}

void status_setup_async(struct daemon_conn *master)
{
	assert(status_fd == -1);
	assert(!status_conn);
	status_conn = master;

	setup_logging_sighandler();
}

void status_send(const u8 *msg TAKES)
{
	if (status_fd >= 0) {
		int type =fromwire_peektype(msg);
		if (!wire_sync_write(status_fd, msg))
			err(1, "Writing out status %i", type);
	} else {
		daemon_conn_send(status_conn, msg);
	}
}

static void status_io_full(enum log_level iodir, const char *who, const u8 *p)
{
	status_send(take(towire_status_io(NULL, iodir, who, p)));
}

static void status_peer_io_short(enum log_level iodir, const u8 *p)
{
	status_debug("%s %s",
		     iodir == LOG_IO_OUT ? "peer_out" : "peer_in",
		     wire_type_name(fromwire_peektype(p)));
}

void status_peer_io(enum log_level iodir, const u8 *p)
{
	if (logging_io)
		status_io_full(iodir, "", p);
	/* We get a huge amount of gossip; don't log it */
	else if (!is_msg_for_gossipd(p))
		status_peer_io_short(iodir, p);
}

void status_io(enum log_level iodir, const char *who,
	       const void *data, size_t len)
{
	if (!logging_io)
		return;
	/* Horribly inefficient, but so is logging IO generally. */
	status_io_full(iodir, who, tal_dup_arr(tmpctx, u8, data, len, 0));
}

void status_vfmt(enum log_level level, const char *fmt, va_list ap)
{
	char *str;

	str = tal_vfmt(NULL, fmt, ap);
	status_send(take(towire_status_log(NULL, level, str)));
	tal_free(str);
}

void status_fmt(enum log_level level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	status_vfmt(level, fmt, ap);
	va_end(ap);
}

static NORETURN void flush_and_exit(int reason)
{
	/* Don't let it take forever. */
	alarm(10);
	if (status_conn)
		daemon_conn_sync_flush(status_conn);

	exit(0x80 | (reason & 0xFF));
}

void status_send_fatal(const u8 *msg TAKES, int fd1, int fd2)
{
	int reason = fromwire_peektype(msg);
	breakpoint();
	status_send(msg);

	/* We don't support async fd passing here. */
	if (fd1 != -1) {
		assert(!status_conn);
		fdpass_send(status_fd, fd1);
		fdpass_send(status_fd, fd2);
	}

	flush_and_exit(reason);
}

/* FIXME: rename to status_fatal, s/fail/fatal/ in status_failreason enums */
void status_failed(enum status_failreason reason, const char *fmt, ...)
{
	va_list ap;
	char *str;

	va_start(ap, fmt);
	str = tal_vfmt(NULL, fmt, ap);
	va_end(ap);

	status_send_fatal(take(towire_status_fail(NULL, reason, str)),
			  -1, -1);
}

void master_badmsg(u32 type_expected, const u8 *msg)
{
	if (!msg)
		status_failed(STATUS_FAIL_MASTER_IO,
			     "failed reading msg %u: %s",
			     type_expected, strerror(errno));
	status_failed(STATUS_FAIL_MASTER_IO,
		     "Error parsing %u: %s",
		     type_expected, tal_hex(tmpctx, msg));
}
