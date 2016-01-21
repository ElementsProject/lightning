#include "lightningd.h"
#include "log.h"
#include <ccan/array_size/array_size.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <version.h>

static struct lightningd_state *lightningd_state(void)
{
	struct lightningd_state *state = tal(NULL, struct lightningd_state);

	state->log_record = new_log_record(state, 20 * 1024 * 1024, LOG_INFORM);
	state->base_log = new_log(state, state->log_record,
				  "lightningd(%u):", (int)getpid());

	return state;
}

static struct {
	const char *name;
	enum log_level level;
} log_levels[] = {
	{ "IO", LOG_IO },
	{ "DEBUG", LOG_DBG },
	{ "INFO", LOG_INFORM },
	{ "UNUSUAL", LOG_UNUSUAL },
	{ "BROKEN", LOG_BROKEN }
};

static char *arg_log_level(const char *arg, struct lightningd_state *state)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(log_levels); i++) {
		if (strcasecmp(arg, log_levels[i].name) == 0) {
			set_log_level(state->log_record, log_levels[i].level);
			return NULL;
		}
	}
	return tal_fmt(NULL, "unknown log level");
}

static char *arg_log_prefix(const char *arg, struct lightningd_state *state)
{
	set_log_prefix(state->base_log, arg);
	return NULL;
}

static void log_to_file(const char *prefix,
			enum log_level level,
			bool continued,
			const char *str,
			struct lightningd_state *state)
{
	if (!continued) {
		fprintf(state->logf, "%s %s\n", prefix, str);
	} else {
		fprintf(state->logf, "%s \t%s\n", prefix, str);
	}
}

static char *arg_log_to_file(const char *arg, struct lightningd_state *state)
{
	state->logf = fopen(arg, "a");
	if (!state->logf)
		return tal_fmt(NULL, "Failed to open: %s", strerror(errno));
	set_log_outfn(state->log_record, log_to_file, state);
	return NULL;
}

/* Tal wrappers for opt. */
static void *opt_allocfn(size_t size)
{
	return tal_alloc_(NULL, size, false, TAL_LABEL("opt_allocfn", ""));
}

static void *tal_reallocfn(void *ptr, size_t size)
{
	if (!ptr)
		return opt_allocfn(size);
	tal_resize_(&ptr, 1, size, false);
	return ptr;
}

static void tal_freefn(void *ptr)
{
	tal_free(ptr);
}

int main(int argc, char *argv[])
{
	struct lightningd_state *state = lightningd_state();

	err_set_progname(argv[0]);
	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);

	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "\n"
			   "A bitcoin lightning daemon.",
			   "Print this message.");
	opt_register_arg("--log-level", arg_log_level, NULL, state,
			 "log level (debug, info, unusual, broken)");
	opt_register_arg("--log-prefix", arg_log_prefix, NULL, state,
			 "log prefix");
	opt_register_arg("--log-file=<file>", arg_log_to_file, NULL, state,
			 "log to file instead of stdout");
	opt_register_version();

	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc != 1)
		errx(1, "no arguments accepted");

	log_info(state->base_log, "Hello world!");
	tal_free(state);
	opt_free_table();
	return 0;
}
