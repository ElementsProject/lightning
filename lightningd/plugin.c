#include "lightningd/plugin.h"

#include <ccan/io/io.h>
#include <ccan/list/list.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/tal/str/str.h>
#include <lightningd/json.h>
#include <unistd.h>

struct plugin {
	int stdin, stdout;
	pid_t pid;
	char *cmd;
	struct io_conn *stdin_conn, *stdout_conn;
	bool stop;

	/* Stuff we read */
	char *buffer;
	size_t used, len_read;

	/* Stuff we write */
	struct list_head output;
	const char *outbuf;
};

struct plugins {
	struct plugin *plugins;
};

struct json_output {
	struct list_node list;
	const char *json;
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

/**
 * Try to parse a complete message from the plugin's buffer.
 *
 * Internally calls the handler if it was able to fully parse a JSON message,
 * and returns true in that case.
 */
static bool plugin_read_json_one(struct plugin *plugin)
{
	jsmntok_t *toks;
	bool valid;
	toks = json_parse_input(plugin->buffer, plugin->used, &valid);
	if (!toks) {
		if (!valid) {
			/* FIXME (cdecker) Print error and kill the plugin */
			return io_close(plugin->stdout_conn);
		}
		/* We need more. */
		return false;
	}

	/* Empty buffer? (eg. just whitespace). */
	if (tal_count(toks) == 1) {
		plugin->used = 0;
		return false;
	}

	/* FIXME(cdecker) Call dispatch to handle this message. */

	/* Move this object out of the buffer */
	memmove(plugin->buffer, plugin->buffer + toks[0].end,
		tal_count(plugin->buffer) - toks[0].end);
	plugin->used -= toks[0].end;
	tal_free(toks);
	return true;
}

static struct io_plan *plugin_read_json(struct io_conn *conn UNUSED,
					struct plugin *plugin)
{
	bool success;
	plugin->used += plugin->len_read;
	if (plugin->used == tal_count(plugin->buffer))
		tal_resize(&plugin->buffer, plugin->used * 2);

	/* Read and process all messages from the connection */
	do {
		success = plugin_read_json_one(plugin);
	} while (success);

	/* Now read more from the connection */
	return io_read_partial(plugin->stdout_conn,
			       plugin->buffer + plugin->used,
			       tal_count(plugin->buffer) - plugin->used,
			       &plugin->len_read, plugin_read_json, plugin);
}

static struct io_plan *plugin_write_json(struct io_conn *conn UNUSED,
					 struct plugin *plugin)
{
	struct json_output *out;
	out = list_pop(&plugin->output, struct json_output, list);
	if (!out) {
		if (plugin->stop) {
			return io_close(conn);
		} else {
			return io_out_wait(plugin->stdin_conn, plugin,
					   plugin_write_json, plugin);
		}
	}

	/* We have a message we'd like to send */
	plugin->outbuf = tal_steal(plugin, out->json);
	tal_free(out);
	return io_write(conn, plugin->outbuf, strlen(plugin->outbuf),
			plugin_write_json, plugin);
}

static struct io_plan *plugin_conn_init(struct io_conn *conn,
					struct plugin *plugin)
{
	plugin->stop = false;
	if (plugin->stdout == io_conn_fd(conn)) {
		/* We read from their stdout */
		plugin->stdout_conn = conn;
		return io_read_partial(plugin->stdout_conn, plugin->buffer,
				       tal_bytelen(plugin->buffer),
				       &plugin->len_read, plugin_read_json,
				       plugin);
	} else {
		/* We write to their stdin */
		plugin->stdin_conn = conn;
		/* We don't have anything queued yet, wait for notification */
		return io_wait(plugin->stdin_conn, plugin, plugin_write_json,
			       plugin);
	}
}

void plugins_init(struct plugins *plugins)
{
	struct plugin *p;
	char **cmd;
	/* Spawn the plugin processes before entering the io_loop */
	for (size_t i=0; i<tal_count(plugins->plugins); i++) {
		p = &plugins->plugins[i];
		cmd = tal_arr(p, char *, 2);
		cmd[0] = p->cmd;
		cmd[1] = NULL;
		p->pid = pipecmdarr(&p->stdout, &p->stdin, NULL, cmd);

		list_head_init(&p->output);
		p->buffer = tal_arr(p, char, 64);
		p->used = 0;

		/* Create two connections, one read-only on top of p->stdin, and one
		 * write-only on p->stdout */
		io_new_conn(p, p->stdout, plugin_conn_init, p);
		io_new_conn(p, p->stdin, plugin_conn_init, p);
	}
}

void json_add_opt_plugins(struct json_stream *response,
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
