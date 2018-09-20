#include "lightningd/plugin.h"

#include <ccan/list/list.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/tal/str/str.h>
#include <unistd.h>

struct plugin {
	int stdin, stdout;
	pid_t pid;
	char *cmd;
};

struct plugins {
	struct plugin *plugins;
};

struct plugins *plugins_new(const tal_t *ctx){
	struct plugins *p;
	p = tal(ctx, struct plugins);
	p->plugins = tal_arr(p, struct plugin, 0);
	return p;
}

void plugin_register(struct plugins *plugins, const char* path TAKES)
{
	struct plugin *p;
	size_t n = tal_count(plugins->plugins);
	tal_resize(&plugins->plugins, n+1);
	p = &plugins->plugins[n];
	p->cmd = tal_strdup(p, path);
}

void plugins_init(struct plugins *plugins)
{
	struct plugin *p;
	/* Spawn the plugin processes before entering the io_loop */
	for (size_t i=0; i<tal_count(plugins->plugins); i++) {
		p = &plugins->plugins[i];
		p->pid = pipecmd(&p->stdout, &p->stdin, NULL, p->cmd);
	}
}

void json_add_opt_plugins(struct json_result *response,
			  const struct plugins *plugins)
{
	struct plugin *p;
	json_object_start(response, "plugin");
	for (size_t i=0; i<tal_count(plugins->plugins); i++) {
		p = &plugins->plugins[i];
		json_object_start(response, p->cmd);
		json_object_end(response);
	}
	json_object_end(response);
}
