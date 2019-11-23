#include "configdir.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <ccan/cast/cast.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/utils.h>
#include <common/version.h>
#include <errno.h>

/* The regrettable globals */
static const tal_t *options_ctx;

/* Override a tal string; frees the old one. */
char *opt_set_talstr(const char *arg, char **p)
{
	tal_free(*p);
	return opt_set_charp(tal_strdup(options_ctx, arg), p);
}

static char *opt_set_abspath(const char *arg, char **p)
{
	tal_free(*p);
	return opt_set_charp(path_join(options_ctx, take(path_cwd(NULL)), arg),
			     p);
}

/* Tal wrappers for opt. */
static void *opt_allocfn(size_t size)
{
	return tal_arr_label(NULL, char, size,
			     TAL_LABEL(opt_allocfn_notleak, ""));
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

static int config_parse_line_number;

static void config_log_stderr_exit(const char *fmt, ...)
{
	char *msg;
	va_list ap;

	va_start(ap, fmt);

	/* This is the format we expect:*/
	if (streq(fmt, "%s: %.*s: %s")) {
		const char *argv0 = va_arg(ap, const char *);
		unsigned int len = va_arg(ap, unsigned int);
		const char *arg = va_arg(ap, const char *);
		const char *problem = va_arg(ap, const char *);

		assert(argv0 != NULL);
		assert(arg != NULL);
		assert(problem != NULL);
		/*mangle it to remove '--' and add the line number.*/
		msg = tal_fmt(NULL, "%s line %d: %.*s: %s",
			      argv0,
			      config_parse_line_number, len-2, arg+2, problem);
	} else {
		msg = tal_vfmt(NULL, fmt, ap);
	}
	va_end(ap);

	errx(1, "%s", msg);
}

static void parse_include(const char *filename, bool must_exist, bool early)
{
	char *contents, **lines;
	char **all_args; /*For each line: either `--`argument, include file, or NULL*/
	char *argv[3];
	int i, argc;

	contents = grab_file(NULL, filename);

	/* The default config doesn't have to exist, but if the config was
	 * specified on the command line it has to exist. */
	if (!contents) {
		if (must_exist)
			err(1, "Opening and reading %s", filename);
		return;
	}

	lines = tal_strsplit(contents, contents, "\r\n", STR_EMPTY_OK);

	/* We have to keep all_args around, since opt will point into it: use
	 * magic tal name to tell memleak this isn't one. */
	all_args = tal_arr_label(options_ctx, char *, tal_count(lines) - 1,
				 TAL_LABEL(options_array_notleak, ""));

	for (i = 0; i < tal_count(lines) - 1; i++) {
		if (strstarts(lines[i], "#")) {
			all_args[i] = NULL;
		} else if (strstarts(lines[i], "include ")) {
			/* If relative, it's relative to current config file */
			all_args[i] = path_join(all_args,
						take(path_dirname(NULL,
								  filename)),
						lines[i] + strlen("include "));
		} else {
			/* Only valid forms are "foo" and "foo=bar" */
			all_args[i] = tal_fmt(all_args, "--%s", lines[i]);
		}
	}

	/*
	For each line we construct a fake argc,argv commandline.
	argv[1] is the only element that changes between iterations.
	*/
	argc = 2;
	argv[0] = cast_const(char *, filename);
	argv[argc] = NULL;

	for (i = 0; i < tal_count(all_args); i++) {
		if (all_args[i] == NULL)
			continue;

		if (!strstarts(all_args[i], "--")) {
			parse_include(all_args[i], true, early);
			continue;
		}

		config_parse_line_number = i + 1;
		argv[1] = all_args[i];
		if (early) {
			opt_early_parse_incomplete(argc, argv,
						   config_log_stderr_exit);
		} else {
			opt_parse(&argc, argv, config_log_stderr_exit);
			argc = 2; /* opt_parse might have changed it  */
		}
	}

	tal_free(contents);
}

static char *default_base_configdir(const tal_t *ctx)
{
	char *path;
	const char *env = getenv("HOME");
	if (!env)
		return path_cwd(ctx);

	path = path_join(ctx, env, ".lightning");
	return path;
}

static char *default_rpcfile(const tal_t *ctx)
{
	return tal_strdup(ctx, "lightning-rpc");
}

static char *opt_set_network(const char *arg, void *unused)
{
	assert(arg != NULL);

	/* Set the global chainparams instance */
	chainparams = chainparams_for_network(arg);
	if (!chainparams)
		return tal_fmt(NULL, "Unknown network name '%s'", arg);
	return NULL;
}

static char *opt_set_specific_network(const char *network)
{
	return opt_set_network(network, NULL);
}

static void opt_show_network(char buf[OPT_SHOW_LEN], const void *unused)
{
	snprintf(buf, OPT_SHOW_LEN, "%s", chainparams->network_name);
}

/* Special option to ignore stuff we've parsed really early on */
char *opt_ignore(const char *arg, void *unused)
{
	return NULL;
}

char *opt_ignore_noarg(void *unused)
{
	return NULL;
}

void setup_option_allocators(void)
{
	/*~ These functions make ccan/opt use tal for allocations */
	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);
}

/* network is NULL for parsing top-level config file. */
static void parse_implied_config_file(const char *config_basedir,
				      const char *network,
				      bool early)
{
	const char *dir, *filename;

	if (config_basedir)
		dir = path_join(NULL, take(path_cwd(NULL)), config_basedir);
	else
		dir = default_base_configdir(NULL);

	if (network)
		dir = path_join(NULL, take(dir), network);

	filename = path_join(NULL, take(dir), "config");
	parse_include(filename, false, early);
	tal_free(filename);
}

/* If they specify --conf, we just read that.
 * Otherwise we read <lightning-dir>/config then <lightning-dir>/<network>/config
 */
void parse_config_files(const char *config_filename,
			const char *config_basedir,
			bool early)
{
	if (config_filename) {
		parse_include(config_filename, true, early);
		return;
	}

	parse_implied_config_file(config_basedir, NULL, early);
	parse_implied_config_file(config_basedir, chainparams->network_name, early);
}

void initial_config_opts(const tal_t *ctx,
			 int argc, char *argv[],
			 char **config_filename,
			 char **config_basedir,
			 char **config_netdir,
			 char **rpc_filename)
{
	options_ctx = ctx;

	/* First, they could specify a config, which specifies a lightning dir
	 * or a network. */
	*config_filename = NULL;
	opt_register_early_arg("--conf=<file>", opt_set_abspath, NULL,
			       config_filename,
			       "Specify configuration file");

	/* Cmdline can also set lightning-dir. */
	*config_basedir = NULL;
	opt_register_early_arg("--lightning-dir=<dir>",
			       opt_set_abspath, NULL,
			       config_basedir,
			       "Set base directory: network-specific subdirectory is under here");

	/* Handle --version (and exit) here too */
	opt_register_version();

	opt_early_parse_incomplete(argc, argv, opt_log_stderr_exit);

	/* Now, reset and ignore --conf option from now on. */
	opt_free_table();

	opt_register_early_arg("--conf=<file>", opt_ignore, NULL,
			       config_filename,
			       "Specify configuration file");

	/* If they set --conf it can still set --lightning-dir */
	if (!*config_filename) {
		opt_register_early_arg("--lightning-dir=<dir>",
				       opt_ignore, opt_show_charp,
				       config_basedir,
				       "Set base directory: network-specific subdirectory is under here");
	} else {
		opt_register_early_arg("--lightning-dir=<dir>",
				       opt_set_abspath, NULL,
				       config_basedir,
				       "Set base directory: network-specific subdirectory is under here");
	}

	/* Now, config file (or cmdline) can set network and lightning-dir */

	/* We need to know network early, so we can set defaults (which normal
	 * options can change) and default config_netdir */
	opt_register_early_arg("--network", opt_set_network, opt_show_network,
			       NULL,
			       "Select the network parameters (bitcoin, testnet,"
			       " regtest, litecoin or litecoin-testnet)");
	opt_register_early_noarg("--testnet",
				 opt_set_specific_network, "testnet",
				 "Alias for --network=testnet");
	opt_register_early_noarg("--signet",
				 opt_set_specific_network, "signet",
				 "Alias for --network=signet");
	opt_register_early_noarg("--mainnet",
				 opt_set_specific_network, "bitcoin",
				 "Alias for --network=bitcoin");

	/* Read config file first, since cmdline must override */
	if (*config_filename)
		parse_include(*config_filename, true, true);
	else
		parse_implied_config_file(*config_basedir, NULL, true);
	opt_early_parse_incomplete(argc, argv, opt_log_stderr_exit);

	/* We use a global (in common/utils.h) for the chainparams.
	 * We default to testnet for now. */
	if (!chainparams)
		chainparams = chainparams_for_network("testnet");

	if (!*config_basedir)
		*config_basedir = default_base_configdir(ctx);

	*config_netdir
		= path_join(NULL, *config_basedir, chainparams->network_name);

	/* Make sure it's absolute */
	*config_netdir = path_join(ctx, take(path_cwd(NULL)), take(*config_netdir));

	/* Now, reset and ignore those options from now on. */
	opt_free_table();

	opt_register_early_arg("--conf=<file>", opt_ignore, NULL,
			       config_filename,
			       "Specify configuration file");
	opt_register_early_arg("--lightning-dir=<dir>",
			       opt_ignore, opt_show_charp,
			       config_basedir,
			       "Set base directory: network-specific subdirectory is under here");
	opt_register_early_arg("--network", opt_ignore, opt_show_network,
			       NULL,
			       "Select the network parameters (bitcoin, testnet,"
			       " regtest, litecoin or litecoin-testnet)");
	opt_register_early_noarg("--testnet", opt_ignore_noarg, NULL,
				 "Alias for --network=testnet");
	opt_register_early_noarg("--signet", opt_ignore_noarg, NULL,
				 "Alias for --network=signet");
	opt_register_early_noarg("--mainnet", opt_ignore_noarg, NULL,
				 "Alias for --network=bitcoin");

	/* Set this up for when they parse cmdline proper. */
	*rpc_filename = default_rpcfile(ctx);
	opt_register_arg("--rpc-file", opt_set_talstr, opt_show_charp,
			 rpc_filename,
			 "Set JSON-RPC socket (or /dev/tty)");
}
