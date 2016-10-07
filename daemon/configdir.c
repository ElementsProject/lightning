#include "configdir.h"
#include "log.h"
#include <ccan/opt/opt.h>
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
