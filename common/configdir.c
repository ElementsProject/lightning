#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <ccan/cast/cast.h>
#include <ccan/err/err.h>
#include <ccan/opt/opt.h>
#include <ccan/opt/private.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/configdir.h>
#include <common/configvar.h>
#include <common/utils.h>
#include <common/version.h>

int opt_exitcode = 1;

/* The regrettable globals */
static const tal_t *options_ctx;
static struct configvar *current_cv;

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

static struct configvar **gather_file_configvars(const tal_t *ctx,
						 enum configvar_src src,
						 const char *filename,
						 bool must_exist,
						 size_t include_depth)
{
	char *contents, **lines;
	struct configvar **cvs = tal_arr(ctx, struct configvar *, 0);

	contents = grab_file(tmpctx, filename);

	/* The default config doesn't have to exist, but if the config was
	 * specified on the command line it has to exist. */
	if (!contents) {
		if (must_exist)
			err(1, "Opening and reading %s", filename);
		return cvs;
	}

	/* Break into lines. */
	lines = tal_strsplit(contents, contents, "\r\n", STR_EMPTY_OK);
	for (size_t i = 0; i < tal_count(lines) - 1; i++) {
		/* Comments & blank lines*/
		if (strstarts(lines[i], "#") || streq(lines[i], ""))
			continue;

		if (strstarts(lines[i], "include ")) {
			const char *included = lines[i] + strlen("include ");
			struct configvar **sub;

			if (include_depth > 100)
				errx(1, "Include loop with %s and %s", filename, included);

			/* If relative, it's relative to current config file */
			sub = gather_file_configvars(NULL,
						     src,
						     path_join(tmpctx,
							       take(path_dirname(NULL, filename)),
							       included),
						     true,
						     include_depth + 1);
			cvs = configvar_join(ctx, take(cvs), take(sub));
			continue;
		}

		tal_arr_expand(&cvs,
			       configvar_new(cvs, src, filename, i+1, lines[i]));
	}
	return cvs;
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

	/* Ignore if called directly from opt (e.g. lightning-cli) */
	if (!current_cv)
		return NULL;

	if (current_cv->src == CONFIGVAR_NETWORK_CONF)
		return "not permitted in network-specific configuration files";
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

static bool opt_show_network(char *buf, size_t len, const void *unused)
{
	snprintf(buf, len, "%s", chainparams->network_name);
	return true;
}

static char *opt_set_config_filename(const char *arg, char **p)
{
	/* Ignore if called directly from opt (e.g. lightning-cli) */
	if (!current_cv)
		return NULL;

	if (current_cv->src == CONFIGVAR_CMDLINE)
		return opt_set_abspath(arg, p);
	return "not permitted in configuration files";
}

static char *opt_set_lightning_dir(const char *arg, char **p)
{
	/* Ignore if called directly from opt (e.g. lightning-cli) */
	if (!current_cv)
		return NULL;

	if (current_cv->src == CONFIGVAR_CMDLINE
	    || current_cv->src == CONFIGVAR_EXPLICIT_CONF)
		return opt_set_abspath(arg, p);
	return "not permitted in implicit configuration files";
}

void setup_option_allocators(void)
{
	/*~ These functions make ccan/opt use tal for allocations */
	opt_set_alloc(opt_allocfn, tal_reallocfn, tal_freefn);
}

static void parse_configvars(struct configvar **cvs,
			     bool early,
			     bool full_knowledge,
			     bool developer)
{
	for (size_t i = 0; i < tal_count(cvs); i++) {
		const char *problem;
		bool should_know;

		should_know = full_knowledge;
		/* We should always know cmdline args in final parse */
		if (!early && cvs[i]->src == CONFIGVAR_CMDLINE)
			should_know = true;

		current_cv = cvs[i];
		problem = configvar_parse(cvs[i],
					  early,
					  should_know,
					  developer);
		current_cv = NULL;
		if (!problem)
			continue;

		if (cvs[i]->file) {
			errx(opt_exitcode, "Config file %s line %u: %s: %s",
			     cvs[i]->file, cvs[i]->linenum,
			     cvs[i]->configline, problem);
		} else {
			errx(opt_exitcode, "--%s: %s", cvs[i]->configline, problem);
		}
	}
}

static void finished_arg(int *argc, char **argv, size_t *idx,
			 bool remove_args)
{
	if (!remove_args) {
		(*idx)++;
		return;
	}
	memmove(argv + *idx, argv + 1 + *idx, (*argc - *idx) * sizeof(char *));
	(*argc)--;
}

/* Now all options are known, we can turn cmdline into configvars */
static struct configvar **gather_cmdline_args(const tal_t *ctx,
					      int *argc, char **argv,
					      bool remove_args)
{
	struct configvar **cvs = tal_arr(ctx, struct configvar *, 0);

	assert(argv[*argc] == NULL);
	for (size_t i = 1; argv[i];) {
		struct opt_table *ot;
		const char *configline, *arg, *optarg;
		enum configvar_src src;
		bool extra_arg;

		/* End of options? */
		if (streq(argv[i], "--"))
			break;

		if (!strstarts(argv[i], "-")) {
			i++;
			continue;
		}

		if (strstarts(argv[i], "--")) {
			arg = argv[i] + 2;
			ot = opt_find_long(arg, &optarg);
			src = CONFIGVAR_CMDLINE;
		} else {
			/* FIXME: We don't handle multiple short
			 * options here! */
			arg = argv[i] + 1;
			ot = opt_find_short(arg[0]);
			optarg = NULL;
			src = CONFIGVAR_CMDLINE_SHORT;
		}
		if (ot) {
			extra_arg = (ot->type & OPT_HASARG) && !optarg;
		} else {
			/* Unknown (yet!).  Guess if next arg is for this! */
			extra_arg = ((src == CONFIGVAR_CMDLINE_SHORT
				      || !strchr(arg, '='))
				     && argv[i+1]
				     && !strstarts(argv[i+1], "-"));
		}
		finished_arg(argc, argv, &i, remove_args);
		/* We turn `--foo bar` into `--foo=bar` here */
		if (extra_arg) {
			configline = tal_fmt(tmpctx, "%s=%s", arg, argv[i]);
			finished_arg(argc, argv, &i, remove_args);
		} else {
			configline = arg;
		}
		tal_arr_expand(&cvs, configvar_new(cvs, src,
						   NULL, 0, configline));
	}
	assert(argv[*argc] == NULL);
	return cvs;
}

void minimal_config_opts(const tal_t *ctx,
			 int argc, char *argv[],
			 char **config_filename,
			 char **basedir,
			 char **config_netdir,
			 char **rpc_filename)
{
	initial_config_opts(tmpctx, &argc, argv, false,
			    config_filename,
			    basedir,
			    config_netdir,
			    rpc_filename);
	tal_steal(ctx, *config_filename);
	tal_steal(ctx, *basedir);
	tal_steal(ctx, *config_netdir);
	tal_steal(ctx, *rpc_filename);
}

struct configvar **initial_config_opts(const tal_t *ctx,
				       int *argc, char *argv[],
				       bool remove_args,
				       char **config_filename,
				       char **config_basedir,
				       char **config_netdir,
				       char **rpc_filename)
{
	struct configvar **cmdline_cvs, **config_cvs, **cvs;

	options_ctx = ctx;

	/* This helps opt_usage. */
	opt_argv0 = argv[0];

	/* Default chain (a global) is bitcoin. */
	chainparams = chainparams_for_network("bitcoin");

	/* First, they could specify a config, or base dir. */
	*config_filename = NULL;
	opt_register_early_arg("--conf=<file>",
			       opt_set_config_filename,
			       /* Doesn't show if it's NULL! */
			       opt_show_charp,
			       config_filename,
			       "Specify configuration file");
	*config_basedir = default_base_configdir(ctx);
	opt_register_early_arg("--lightning-dir=<dir>",
			       opt_set_lightning_dir, opt_show_charp,
			       config_basedir,
			       "Set base directory: network-specific subdirectory is under here");
	opt_register_early_arg("--network", opt_set_network, opt_show_network,
			       NULL,
			       "Select the network parameters (bitcoin, testnet,"
			       " signet, regtest, litecoin or litecoin-testnet)");
	opt_register_early_noarg("--testnet",
				 opt_set_specific_network, "testnet",
				 "Alias for --network=testnet");
	opt_register_early_noarg("--signet",
				 opt_set_specific_network, "signet",
				 "Alias for --network=signet");
	opt_register_early_noarg("--mainnet",
				 opt_set_specific_network, "bitcoin",
				 "Alias for --network=bitcoin");
	opt_register_early_noarg("--regtest",
				 opt_set_specific_network, "regtest",
				 "Alias for --network=regtest");
	/* Handle --version (and exit) here too */
	opt_register_version();

	/* Allow them to override rpc-file too. */
	*rpc_filename = default_rpcfile(ctx);
	opt_register_early_arg("--rpc-file", opt_set_talstr, opt_show_charp,
			       rpc_filename,
			       "Set JSON-RPC socket (or /dev/tty)");

	cmdline_cvs = gather_cmdline_args(tmpctx, argc, argv, remove_args);
	parse_configvars(cmdline_cvs, true, false, false);

	/* Base default or direct config can set network */
	if (*config_filename) {
		config_cvs = gather_file_configvars(NULL,
						    CONFIGVAR_EXPLICIT_CONF,
						    *config_filename, true, 0);
	} else {
		struct configvar **base_cvs, **net_cvs;
		char *dir = path_join(tmpctx, take(path_cwd(NULL)), *config_basedir);
		/* Optional: .lightning/config */
		base_cvs = gather_file_configvars(tmpctx,
						  CONFIGVAR_BASE_CONF,
						  path_join(tmpctx, dir, "config"),
						  false, 0);
		/* This might set network! */
		parse_configvars(configvar_join(tmpctx, base_cvs, cmdline_cvs),
				 true, false, false);

		/* Now, we can get network config */
		dir = path_join(tmpctx, dir, chainparams->network_name);
		net_cvs = gather_file_configvars(tmpctx,
						 CONFIGVAR_NETWORK_CONF,
						 path_join(tmpctx, dir, "config"),
						 false, 0);
		config_cvs = configvar_join(NULL, take(base_cvs), take(net_cvs));
	}
	cvs = configvar_join(ctx, take(config_cvs), cmdline_cvs);

	/* This will be called again, once caller has added their own
	 * early vars! */
	parse_configvars_early(cvs, false);

	*config_netdir
		= path_join(NULL, *config_basedir, chainparams->network_name);

	/* Make sure it's absolute */
	*config_netdir = path_join(ctx, take(path_cwd(NULL)), take(*config_netdir));
	return cvs;
}

void parse_configvars_early(struct configvar **cvs, bool developer)
{
	parse_configvars(cvs, true, false, developer);
}

void parse_configvars_final(struct configvar **cvs,
			    bool full_knowledge,
			    bool developer)
{
	parse_configvars(cvs, false, full_knowledge, developer);
	configvar_finalize_overrides(cvs);
}

bool is_restricted_ignored(const void *fn)
{
	return fn == opt_set_specific_network;
}

bool is_restricted_print_if_nonnull(const void *fn)
{
	return fn == opt_set_config_filename;
}
