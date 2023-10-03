#include "config.h"
#include <assert.h>
#include <ccan/breakpoint/breakpoint.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/tal/str/str.h>
#include <common/daemon.h>
#include <common/daemon_conn.h>
#include <common/status.h>
#include <common/status_wiregen.h>
#include <common/version.h>
#include <errno.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

static int status_fd = -1;
static struct daemon_conn *status_conn;
volatile bool logging_io = false;
static bool was_logging_io;

/* If we're more than this many msgs deep, don't add debug messages. */
#define TRACE_QUEUE_LIMIT 20
static size_t traces_suppressed;

static void got_sigusr1(int signal UNUSED)
{
	logging_io = !logging_io;
}

static void setup_logging_sighandler(void)
{
	struct sigaction act;

	/* Could have been set to true by --log-io arg. */
	was_logging_io = logging_io;

	memset(&act, 0, sizeof(act));
	act.sa_handler = got_sigusr1;
	act.sa_flags = SA_RESTART;

	sigaction(SIGUSR1, &act, NULL);
}

static void report_logging_io(const char *why)
{
	if (logging_io != was_logging_io) {
		was_logging_io = logging_io;
		status_debug("%s: IO LOGGING %s",
			     why, logging_io ? "ENABLED" : "DISABLED");
	}
}

void status_setup_sync(int fd)
{
	assert(status_fd == -1);
	assert(!status_conn);
	status_fd = fd;
	setup_logging_sighandler();

	/* Send version now. */
	status_send(take(towire_status_version(NULL, version())));
}

static void destroy_daemon_conn(struct daemon_conn *dc UNUSED)
{
	status_conn = NULL;
}

void status_setup_async(struct daemon_conn *master)
{
	assert(status_fd == -1);
	assert(!status_conn);
	status_conn = master;

	tal_add_destructor(master, destroy_daemon_conn);

	setup_logging_sighandler();

	/* Send version now. */
	status_send(take(towire_status_version(NULL, version())));
}

void status_send(const u8 *msg TAKES)
{
	report_logging_io("SIGUSR1");
	if (status_fd >= 0) {
		if (!wire_sync_write(status_fd, msg))
			/* No point printing error if lightningd is dead. */
			exit(1);
	} else {
		daemon_conn_send(status_conn, msg);
	}
}

static void status_io_full(enum log_level iodir,
			   const struct node_id *peer,
			   const char *who, const u8 *p)
{
	status_send(take(towire_status_io(NULL, iodir, peer, who, p)));
}

static bool status_peer_io_filter_packettype(const u8 *p)
{
	int msg_type = fromwire_peektype(p);
	switch (msg_type) {
	case WIRE_PING:
	case WIRE_PONG:
		return true;
	}
	return false;
}

static void status_peer_io_short(enum log_level iodir,
				 const struct node_id *peer,
				 const u8 *p)
{
	if (!status_peer_io_filter_packettype(p))
		status_peer_debug(peer, "%s %s",
				  iodir == LOG_IO_OUT ? "peer_out" : "peer_in",
				  peer_wire_name(fromwire_peektype(p)));
}

void status_peer_io(enum log_level iodir,
		    const struct node_id *peer,
		    const u8 *p)
{
	report_logging_io("SIGUSR1");
	if (logging_io)
		status_io_full(iodir, peer, "", p);
	/* We get a huge amount of gossip; don't log it */
	else if (!is_msg_for_gossipd(p))
		status_peer_io_short(iodir, peer, p);
}

void status_io(enum log_level iodir,
	       const struct node_id *peer,
	       const char *who,
	       const void *data, size_t len)
{
	report_logging_io("SIGUSR1");
	if (!logging_io)
		return;
	/* Horribly inefficient, but so is logging IO generally. */
	status_io_full(iodir, peer, who, tal_dup_arr(tmpctx, u8, data, len, 0));
}

void status_vfmt(enum log_level level,
		 const struct node_id *peer,
		 const char *fmt, va_list ap)
{
	char *str;

	/* We only suppress async debug msgs.  IO messages are even spammier
	 * but they only occur when explicitly asked for */
	if (level == LOG_DBG && status_conn) {
		size_t qlen = daemon_conn_queue_length(status_conn);

		/* Once suppressing, we keep suppressing until we're empty */
		if (traces_suppressed && qlen == 0) {
			size_t n = traces_suppressed;
			traces_suppressed = 0;
			/* Careful: recursion! */
			status_debug("...[%zu debug messages suppressed]...", n);
		} else if (traces_suppressed || qlen > TRACE_QUEUE_LIMIT) {
			traces_suppressed++;
			return;
		}
	}
	str = tal_vfmt(NULL, fmt, ap);
	status_send(take(towire_status_log(NULL, level, peer, str)));
	tal_free(str);
}

void status_fmt(enum log_level level,
		const struct node_id *peer,
		const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	status_vfmt(level, peer, fmt, ap);
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

void status_send_fd(int fd)
{
	assert(!status_conn);
	fdpass_send(status_fd, fd);
}

void status_send_fatal(const u8 *msg TAKES)
{
	int reason = fromwire_peektype(msg);
	breakpoint();
	status_send(msg);

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

	/* Give a nice backtrace when this happens! */
	if (reason == STATUS_FAIL_INTERNAL_ERROR)
		send_backtrace(str);

	status_send_fatal(take(towire_status_fail(NULL, reason, str)));
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

/* Print BROKEN status: callback for dump_memleak. */
void memleak_status_broken(void *unused, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	status_vfmt(LOG_BROKEN, NULL, fmt, ap);
	va_end(ap);
}
