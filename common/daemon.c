#include <assert.h>
#include <backtrace-supported.h>
#include <backtrace.h>
#include <ccan/err/err.h>
#include <ccan/io/io.h>
#include <ccan/str/str.h>
#include <ccan/tal/str/str.h>
#include <common/daemon.h>
#include <common/memleak.h>
#include <common/status.h>
#include <common/utils.h>
#include <common/version.h>
#include <signal.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <wally_core.h>

static const tal_t *wally_tal_ctx;

#if BACKTRACE_SUPPORTED
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

void send_backtrace(const char *why)
{
	/* We do stderr first, since it's most reliable. */
	warnx("%s (version %s)", why, version());
	if (backtrace_state)
		backtrace_print(backtrace_state, 0, stderr);

	/* Now send to parent. */
	bt_print("%s (version %s)", why, version());
	if (backtrace_state)
		backtrace_full(backtrace_state, 0, backtrace_status, NULL, NULL);
}

static void crashdump(int sig)
{
	char why[100];

	snprintf(why, 100, "FATAL SIGNAL %d", sig);
	send_backtrace(why);

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
#else
void send_backtrace(const char *why)
{
}
#endif

int daemon_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	const char *t;

	t = taken_any();
	if (t)
		errx(1, "Outstanding taken pointers: %s", t);

	clean_tmpctx();

	return poll(fds, nfds, timeout);
}

#if DEVELOPER && BACKTRACE_SUPPORTED
static void steal_notify(tal_t *child, enum tal_notify_type n, tal_t *newparent)
{
	tal_t *p = newparent;

	assert(tal_parent(child) == newparent);
	while ((p = tal_parent(p)) != NULL)
		assert(p != child);
}

static void add_steal_notifier(tal_t *parent UNUSED,
			       enum tal_notify_type type UNNEEDED,
			       void *child)
{
	tal_add_notifier(child, TAL_NOTIFY_ADD_CHILD, add_steal_notifier);
	tal_add_notifier(child, TAL_NOTIFY_STEAL, steal_notify);
}

static void add_steal_notifiers(const tal_t *root)
{
	tal_add_notifier(root, TAL_NOTIFY_ADD_CHILD, add_steal_notifier);

	for (const tal_t *i = tal_first(root); i; i = tal_next(i))
		add_steal_notifiers(i);
}
#endif

static void *wally_tal(size_t size)
{
	return tal_arr_label(wally_tal_ctx, u8, size, "wally_notleak");
}

static void wally_free(void *ptr)
{
	tal_free(ptr);
}

static struct wally_operations wally_tal_ops = {
	.malloc_fn = wally_tal,
	.free_fn = wally_free,
};

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
	add_steal_notifiers(NULL);
#else
	backtrace_state = backtrace_create_state(argv0, 0, NULL, NULL);
#endif
	crashlog_activate();
#endif

#if DEVELOPER
	/* This has significant overhead, so we only enable it if told */
	if (getenv("LIGHTNINGD_DEV_MEMLEAK"))
		memleak_init();
#endif

	/* We rely on libsodium for some of the crypto stuff, so we'd better
	 * not start if it cannot do its job correctly. */
	if (sodium_init() == -1)
		errx(1, "Could not initialize libsodium. Maybe not enough entropy"
		     " available ?");

	/* We handle write returning errors! */
	signal(SIGPIPE, SIG_IGN);

	/* We set up Wally, the bitcoin wallet lib */
	wally_tal_ctx = tal_label(NULL, char, "wally_ctx_notleak");
	wally_init(0);
	wally_set_operations(&wally_tal_ops);
	secp256k1_ctx = wally_get_secp_context();

	setup_tmpctx();
	io_poll_override(daemon_poll);
}

void daemon_shutdown(void)
{
	tal_free(tmpctx);
	wally_cleanup(0);
	wally_free(wally_tal_ctx);
}

void daemon_maybe_debug(char *argv[])
{
#if DEVELOPER
	for (int i = 1; argv[i]; i++) {
		if (!streq(argv[i], "--debugger"))
			continue;

		/* Don't let this mess up stdout, so redir to /dev/null */
		char *cmd = tal_fmt(NULL, "${DEBUG_TERM:-gnome-terminal --} gdb -ex 'attach %u' %s >/dev/null &", getpid(), argv[0]);
		fprintf(stderr, "Running %s\n", cmd);
		/* warn_unused_result is fascist bullshit.
		 * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66425 */
		if (system(cmd))
			;
		/* Continue in the debugger. */
		kill(getpid(), SIGSTOP);
	}
#endif /* DEVELOPER */
}
