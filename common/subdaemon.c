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
	status_vfmt(LOG_BROKEN, NULL, fmt, ap);
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

	daemon_maybe_debug(argv);

#if DEVELOPER
	for (int i = 1; i < argc; i++) {
		if (strstarts(argv[i], "--dev-disconnect=")) {
			dev_disconnect_init(atoi(argv[i]
						 + strlen("--dev-disconnect=")));
		}
	}
#endif

	daemon_setup(argv[0], status_backtrace_print, status_backtrace_exit);
}

#if DEVELOPER
 // Indented to avoid header-order check
 #include <backtrace.h>
 #include <common/memleak.h>

static int dump_syminfo(void *data UNUSED, uintptr_t pc UNUSED,
			const char *filename, int lineno,
			const char *function)
{
	/* This can happen in backtraces. */
	if (!filename || !function)
		return 0;

	status_debug("    %s:%u (%s)", filename, lineno, function);
	return 0;
}

static void dump_leak_backtrace(const uintptr_t *bt)
{
	if (!bt)
		return;

	/* First one serves as counter. */
	status_debug("  backtrace:");
	for (size_t i = 1; i < bt[0]; i++) {
		backtrace_pcinfo(backtrace_state,
				 bt[i], dump_syminfo,
				 NULL, NULL);
	}
}

bool dump_memleak(struct htable *memtable)
{
	const tal_t *i;
	const uintptr_t *backtrace;
	bool found_leak = false;

	while ((i = memleak_get(memtable, &backtrace)) != NULL) {
		status_broken("MEMLEAK: %p", i);
		if (tal_name(i))
			status_broken("  label=%s", tal_name(i));

		dump_leak_backtrace(backtrace);
		status_broken("  parents:");
		for (tal_t *p = tal_parent(i); p; p = tal_parent(p)) {
			status_broken("    %s", tal_name(p));
			p = tal_parent(p);
		}
		found_leak = true;
	}

	return found_leak;
}
#endif /* DEVELOPER */
