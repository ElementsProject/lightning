#include <backtrace-supported.h>
#include <backtrace.h>
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/str/str.h>
#include <common/daemon.h>
#include <common/status.h>
#include <common/utils.h>
#include <common/version.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <wally_core.h>

#if BACKTRACE_SUPPORTED
static struct backtrace_state *backtrace_state;
static void (*bt_print)(const char *fmt, ...) PRINTF_FMT(1,2);
static void (*bt_exit)(void);

static int backtrace_status(void *unused UNUSED, uintptr_t pc,
			    const char *filename, int lineno,
			    const char *function)
{
	bt_print("backtrace: %s:%d (%s) %p",
		 filename, lineno, function, (void *)pc);
	return 0;
}

static void crashdump(int sig)
{
	/* We do stderr first, since it's most reliable. */
	warnx("Fatal signal %d (version %s)", sig, version());
	if (backtrace_state)
		backtrace_print(backtrace_state, 0, stderr);

	/* Now send to parent. */
	bt_print("FATAL SIGNAL %d (version %s)", sig, version());
	if (backtrace_state)
		backtrace_full(backtrace_state, 0, backtrace_status, NULL, NULL);

	/* Probably shouldn't return. */
	bt_exit();

	/* This time it will kill us instantly. */
	kill(getpid(), sig);
}

static void crashlog_activate(void)
{
	struct sigaction sa;

	sa.sa_handler = crashdump;
	sigemptyset(&sa.sa_mask);

	/* We want to fall through to default handler */
	sa.sa_flags = SA_RESETHAND;
	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
}
#endif

static int daemon_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	const char *t;

	t = taken_any();
	if (t)
		errx(1, "Outstanding taken pointers: %s", t);

	clean_tmpctx();

	return poll(fds, nfds, timeout);
}

void daemon_setup(const char *argv0,
		  void (*backtrace_print)(const char *fmt, ...),
		  void (*backtrace_exit)(void))
{
	err_set_progname(argv0);

#if BACKTRACE_SUPPORTED
	bt_print = backtrace_print;
	bt_exit = backtrace_exit;
#if DEVELOPER
	/* Suppresses backtrace (breaks valgrind) */
	if (!getenv("LIGHTNINGD_DEV_NO_BACKTRACE"))
		backtrace_state = backtrace_create_state(argv0, 0, NULL, NULL);
#else
	backtrace_state = backtrace_create_state(argv0, 0, NULL, NULL);
#endif
	crashlog_activate();
#endif

	/* We handle write returning errors! */
	signal(SIGPIPE, SIG_IGN);
	secp256k1_ctx = wally_get_secp_context();

	setup_tmpctx();
	io_poll_override(daemon_poll);
}

void daemon_shutdown(void)
{
	tal_free(tmpctx);
	wally_cleanup(0);
}
