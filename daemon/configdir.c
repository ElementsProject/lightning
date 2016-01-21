#include "configdir.h"
#include "log.h"
#include <ccan/opt/opt.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <errno.h>

static char *default_configdir(const tal_t *ctx)
{
	char *path;
	const char *env = getenv("HOME");
	if (!env)
		return ".";

	path = path_join(ctx, env, ".lightning");
	return path;
}

void configdir_register_opts(const tal_t *ctx,
			     char **configdir, char **rpc_filename)
{
	*configdir = default_configdir(ctx);
	*rpc_filename = "lightning-rpc";

	opt_register_early_arg("--lightning-dir", opt_set_charp, opt_show_charp,
			       configdir,
			       "working directory: all other files are relative to this");

	opt_register_arg("--rpc-file", opt_set_charp, opt_show_charp,
			 rpc_filename,
			 "Set JSON-RPC socket (or /dev/tty)");
}

/* FIXME: make this nicer! */
static void config_log_stderr_exit(const char *fmt, ...)
{
	char *msg;
	va_list ap;

	va_start(ap, fmt);

	/* This is the format we expect: mangle it to remove '--'. */
	if (streq(fmt, "%s: %.*s: %s")) {
		const char *argv0 = va_arg(ap, const char *);
		unsigned int len = va_arg(ap, unsigned int);
		const char *arg = va_arg(ap, const char *);
		const char *problem = va_arg(ap, const char *);

		msg = tal_fmt(NULL, "%s line %s: %.*s: %s",
			      argv0, arg+strlen(arg)+1, len-2, arg+2, problem);
	} else {
		msg = tal_vfmt(NULL, fmt, ap);
	}
	va_end(ap);

	fatal("%s", msg);
}

/* We turn the config file into cmdline arguments. */
void opt_parse_from_config(const tal_t *ctx)
{
	char *contents, **lines;
	char **argv;
	int i, argc;

	contents = grab_file(ctx, "config");
	/* Doesn't have to exist. */
	if (!contents) {
		if (errno != ENOENT)
			fatal("Opening and reading config: %s",
			      strerror(errno));
		return;
	}

	lines = tal_strsplit(contents, contents, "\r\n", STR_NO_EMPTY);

	/* We have to keep argv around, since opt will point into it */
	argv = tal_arr(ctx, char *, argc = 1);
	argv[0] = "lightning config file";

	for (i = 0; i < tal_count(lines) - 1; i++) {
		if (strstarts(lines[i], "#"))
			continue;
		/* Only valid forms are "foo" and "foo=bar" */
		tal_resize(&argv, argc+1);
		/* Stash line number after nul. */
		argv[argc++] = tal_fmt(argv, "--%s%c%u", lines[i], 0, i+1);
	}
	tal_resize(&argv, argc+1);
	argv[argc] = NULL;

	opt_parse(&argc, argv, config_log_stderr_exit);
	tal_free(contents);
}
