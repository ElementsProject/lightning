#include <ccan/tal/str/str.h>
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
#include <wally_core.h>

static void status_backtrace_print(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	status_vfmt(LOG_BROKEN, fmt, ap);
	va_end(ap);
}

static void status_backtrace_exit(void)
{
	status_failed(STATUS_FAIL_INTERNAL_ERROR, "FATAL SIGNAL");
}

void subdaemon_setup(int argc, char *argv[])
{
	if (argc == 2 && streq(argv[1], "--version")) {
		printf("%s\n", version());
		exit(0);
	}

	for (int i = 1; i < argc; i++) {
		if (streq(argv[i], "--log-io"))
			logging_io = true;
	}

#if DEVELOPER
	/* From debugger, set debugger_spin to 0. */
	for (int i = 1; i < argc; i++) {
		if (streq(argv[i], "--debugger")) {
			char *cmd = tal_fmt(NULL, "${DEBUG_TERM:-gnome-terminal --} gdb -ex 'attach %u' %s &", getpid(), argv[0]);
			fprintf(stderr, "Running %s\n", cmd);
			/* warn_unused_result is fascist bullshit.
			 * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66425 */
			if (system(cmd))
				;
			/* Continue in the debugger. */
			kill(getpid(), SIGSTOP);
		}
		if (strstarts(argv[i], "--dev-disconnect=")) {
			dev_disconnect_init(atoi(argv[i]
						 + strlen("--dev-disconnect=")));
		}
	}
#endif

	daemon_setup(argv[0], status_backtrace_print, status_backtrace_exit);
}

