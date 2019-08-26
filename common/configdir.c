#include "configdir.h"
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

char *default_configdir(const tal_t *ctx)
{
	char *path;
	const char *env = getenv("HOME");
	if (!env)
		return tal_strdup(ctx, ".");

	path = path_join(ctx, env, ".lightning");
	return path;
}

char *default_rpcfile(const tal_t *ctx)
{
	return tal_strdup(ctx, "lightning-rpc");
}
