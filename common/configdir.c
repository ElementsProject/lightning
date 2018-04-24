#include "configdir.h"
#include <assert.h>
#include <ccan/opt/opt.h>
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
}

void config_finalize_rpc_name(const tal_t *ctx, char **rpc_filename,
			      const char *netname)
{
	if (*rpc_filename == NULL)
		*rpc_filename = tal_fmt(ctx, "rpc-%s", netname);
}
