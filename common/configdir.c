#include "configdir.h"
#include <ccan/opt/opt.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <errno.h>
#include <lightningd/lightningd.h>


/* Override a tal string; frees the old one. */
char *opt_set_talstr(const char *arg, char **p)
{
	tal_free(*p);
	return opt_set_charp(tal_strdup(NULL, arg), p);
}

char *opt_set_path_talstr(const char *arg, char **p)
{
	if (arg[0] != '/')
		arg = path_join(tmpctx, path_cwd(tmpctx), arg);
	return opt_set_talstr(arg, p);
}

char *default_configdir(const tal_t *ctx)
{
	char *path;
	const char *env = getenv("HOME");
	if (!env)
		return ".";

	path = path_join(ctx, env, ".lightning");
	return path;
}

char *default_rpcfile(const tal_t *ctx)
{
	return tal_strdup(ctx, "lightning-rpc");
}
