#include "configdir.h"
#include <assert.h>
#include <ccan/opt/opt.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <errno.h>

/* Override a tal string; frees the old one. */
char *opt_set_talstr(const char *arg, char **p)
{
	tal_free(*p);
	return opt_set_charp(tal_strdup(NULL, arg), p);
}

static char *default_configdir(const tal_t *ctx)
{
	char *path;
	const char *env = getenv("HOME");
	if (!env)
		return ".";

	path = path_join(ctx, env, ".lightning");
	return path;
}

static char *opt_set_testnet(char **netname)
{
	return opt_set_talstr("testnet", netname);
}

static char *opt_set_mainnet(char **netname)
{
	return opt_set_talstr("bitcoin", netname);
}

void configdir_register_opts(const tal_t *ctx,
			     char **configdir,
			     char **rpc_filename,
			     char **netname)
{
	assert(*netname);
	*configdir = default_configdir(ctx);
	*rpc_filename =	NULL;

	opt_register_early_arg("--lightning-dir=<dir>", opt_set_talstr, opt_show_charp,
			       configdir,
			       "Set working directory. All other files are relative to this");

	opt_register_arg("--rpc-file", opt_set_talstr, NULL,
			 rpc_filename,
			 "Set JSON-RPC socket (or /dev/tty)");

	opt_register_early_arg("--network", opt_set_talstr, opt_show_charp,
			       netname,
			       "Select the network parameters (bitcoin, testnet,"
			       " regtest, litecoin or litecoin-testnet)");

	opt_register_early_noarg("--testnet", opt_set_testnet, netname,
				 "Alias for --network=testnet");
	opt_register_early_noarg("--mainnet", opt_set_mainnet, netname,
				 "Alias for --network=bigtcoin");
}

void config_finalize_rpc_name(const tal_t *ctx, char **rpc_filename,
			      const char *netname)
{
	if (*rpc_filename == NULL)
		*rpc_filename = tal_fmt(ctx, "rpc-%s", netname);
}

/* For each line: either argument string or NULL */
char **args_from_config_file(const tal_t *ctx, const char *configname)
{
	char **all_args, **lines;
	char *contents;

	contents = grab_file(NULL, configname);
	/* Doesn't have to exist. */
	if (!contents)
		return NULL;

	lines = tal_strsplit(contents, contents, "\r\n", STR_NO_EMPTY);
	all_args = tal_arr(ctx, char *, tal_count(lines) - 1);

	for (size_t i = 0; i < tal_count(lines) - 1; i++) {
		if (strstarts(lines[i], "#")) {
			all_args[i] = NULL;
		}
		else {
			/* Only valid forms are "foo" and "foo=bar" */
			all_args[i] = tal_fmt(all_args, "--%s", lines[i]);
		}
	}

	tal_free(contents);
	return all_args;
}
