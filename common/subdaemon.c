#include <backtrace-supported.h>
#include <backtrace.h>
#include <ccan/err/err.h>
#include <ccan/str/str.h>
#include <common/dev_disconnect.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/utils.h>
#include <common/version.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#if BACKTRACE_SUPPORTED
static struct backtrace_state *backtrace_state;

static int backtrace_status(void *unused UNUSED, uintptr_t pc,
			    const char *filename, int lineno,
			    const char *function)
{
	fprintf(stderr, "backtrace: %s:%d (%s) %p\n",
		filename, lineno, function, (void *)pc);
	status_trace("backtrace: %s:%d (%s) %p",
		     filename, lineno, function, (void *)pc);
	return 0;
}

static void crashdump(int sig)
{
	/* We do stderr first, since it's most reliable. */
	warnx("Fatal signal %d", sig);
	backtrace_print(backtrace_state, 0, stderr);

	/* Now send to parent. */
	backtrace_full(backtrace_state, 0, backtrace_status, NULL, NULL);
	status_failed(STATUS_FAIL_INTERNAL_ERROR, "FATAL SIGNAL %d", sig);
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

#if DEVELOPER
extern volatile bool debugger_connected;
volatile bool debugger_connected;
#endif

void subdaemon_setup(int argc, char *argv[])
{
	if (argc == 2 && streq(argv[1], "--version")) {
		printf("%s\n", version());
		exit(0);
	}

	err_set_progname(argv[0]);
#if BACKTRACE_SUPPORTED
	backtrace_state = backtrace_create_state(argv[0], 0, NULL, NULL);
	crashlog_activate();
#endif

	/* We handle write returning errors! */
	signal(SIGPIPE, SIG_IGN);
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);

	setup_tmpctx();

	for (int i = 1; i < argc; i++) {
		if (streq(argv[i], "--log-io"))
			logging_io = true;
	}

#if DEVELOPER
	/* From debugger, set debugger_spin to 0. */
	for (int i = 1; i < argc; i++) {
		if (streq(argv[i], "--debugger")) {
			fprintf(stderr, "gdb -ex 'attach %u' -ex 'p debugger_connected=1' %s\n",
				getpid(), argv[0]);
			while (!debugger_connected)
				usleep(10000);
		}
		if (strstarts(argv[i], "--dev-disconnect=")) {
			dev_disconnect_init(atoi(argv[i]
						 + strlen("--dev-disconnect=")));
		}
	}
#endif
}
