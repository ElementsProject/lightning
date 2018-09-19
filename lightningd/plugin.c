#include "lightningd/plugin.h"

#include <ccan/list/list.h>
#include <ccan/tal/str/str.h>

struct plugin {
	int stdin, stdout;
	pid_t pid;
	char *cmd;
};

struct plugins {
	struct plugin **plugins;
};

struct plugins *plugins_new(const tal_t *ctx){
	struct plugins *p;
	p = tal(ctx, struct plugins);
	p->plugins = tal_arr(p, struct plugin *, 0);
	return p;
}

void plugin_register(struct plugins *plugins, const char* path TAKES)
{
	struct plugin *p;
	size_t n = tal_count(plugins->plugins);
	tal_resize(&plugins->plugins, n+1);
	p = tal(plugins, struct plugin);
	plugins->plugins[n] = p;
	p->cmd = tal_strdup(p, path);
}

void plugins_init(struct plugins *plugins)
{
}
