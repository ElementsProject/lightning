#include "config.h"
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/version.h>
#include <stdio.h>

static void status_backtrace_print(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	status_vfmt(LOG_BROKEN, NULL, fmt, ap);
	va_end(ap);
}

static void status_backtrace_exit(void)
{
	status_failed(STATUS_FAIL_INTERNAL_ERROR, "FATAL SIGNAL");
}

bool subdaemon_setup(int argc, char *argv[])
{
	bool developer;

	if (argc == 2 && streq(argv[1], "--version")) {
		printf("%s\n", version());
		exit(0);
	}

	for (int i = 1; i < argc; i++) {
		if (streq(argv[i], "--log-io"))
			logging_io = true;
	}

	developer = daemon_developer_mode(argv);
	daemon_setup(argv[0], status_backtrace_print, status_backtrace_exit);
	return developer;
}
