#include <backtrace.h>
#include <ccan/err/err.h>
#include <ccan/str/str.h>
#include <common/debug.h>
#include <common/dev_disconnect.h>
#include <common/status.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

static struct backtrace_state *backtrace_state;

static int backtrace_status(void *unused, uintptr_t pc,
			    const char *filename, int lineno,
			    const char *function)
{
	status_trace("backtrace: %s:%u (%s) %p",
		     filename, lineno, function, (void *)pc);
	return 0;
}

static void crashdump(int sig)
{
	/* We do stderr first, since it's most reliable. */
	warnx("Fatal signal %u", sig);
	backtrace_print(backtrace_state, 0, stderr);

	/* Now send to parent. */
	backtrace_full(backtrace_state, 0, backtrace_status, NULL, NULL);
	status_failed(STATUS_FAIL_INTERNAL_ERROR, "FATAL SIGNAL %u", sig);
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

void subdaemon_debug(int argc, char *argv[])
{
#if DEVELOPER
	int i;
	bool printed = false;
#endif

	err_set_progname(argv[0]);
	backtrace_state = backtrace_create_state(argv[0], 0, NULL, NULL);
	crashlog_activate();

#if DEVELOPER
	for (i = 1; i < argc; i++) {
		if (strstarts(argv[i], "--dev-disconnect=")) {
			dev_disconnect_init(atoi(argv[i]
						 + strlen("--dev-disconnect=")));
		}
	}

	/* From debugger, tell gdb "return". */
	for (i = 1; i < argc; i++) {
		while (streq(argv[i], "--debugger")) {
			if (!printed)
				fprintf(stderr, "gdb -ex 'attach %u' %s\n",
					getpid(), argv[0]);
			printed = true;
		}
	}
#endif
}
