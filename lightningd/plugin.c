#include "lightningd/plugin.h"

#include <ccan/intmap/intmap.h>
#include <ccan/io/io.h>
#include <ccan/list/list.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/tal/str/str.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <lightningd/json.h>
#include <unistd.h>

struct plugin {
	int stdin, stdout;
	pid_t pid;
	char *cmd;
	struct io_conn *stdin_conn, *stdout_conn;
	bool stop;
	struct plugins *plugins;

	/* Stuff we read */
	char *buffer;
	size_t used, len_read;

	/* Stuff we write */
	struct list_head output;
	const char *outbuf;
};

struct plugin_request {
	u64 id;
	/* Method to be called */
	const char *method;

	/* JSON encoded params, either a dict or an array */
	const char *json_params;
	const char *response;
	const jsmntok_t *resulttok, *errortok;

	/* The response handler to be called on success or error */
	void (*cb)(const struct plugin_request *, void *);
	void *arg;
};

struct plugins {
	struct plugin *plugins;
	int pending_init;

	/* Currently pending requests by their request ID */
	UINTMAP(struct plugin_request *) pending_requests;
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
	p->plugins = plugins;
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
	u64 id;
	const jsmntok_t *idtok, *resulttok, *errortok;
	struct plugin_request *request;


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

	resulttok = json_get_member(plugin->buffer, toks, "result");
	errortok = json_get_member(plugin->buffer, toks, "error");
	idtok = json_get_member(plugin->buffer, toks, "id");

	/* FIXME(cdecker) Kill the plugin if either of these fails */
	if (!idtok) {
		return false;
	} else if (!resulttok && !errortok) {
		return false;
	}

	/* We only send u64 ids, so if this fails it's a critical error */
	if (!json_to_u64(plugin->buffer, idtok, &id)) {
		/* FIXME (cdecker) Log an error message and kill the plugin */
		return false;
	}

	request = uintmap_get(&plugin->plugins->pending_requests, id);

	if (!request) {
		/* FIXME(cdecker) Log an error and kill the plugin */
		return false;
	}

	/* We expect the request->cb to copy if needed */
	request->response = plugin->buffer;
	request->errortok = errortok;
	request->resulttok = resulttok;
	request->cb(request, request->arg);

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

static void plugin_request_send_(
    struct plugin *plugin, const char *method TAKES, const char *params TAKES,
    void (*cb)(const struct plugin_request *, void *), void *arg)
{
	static u64 next_request_id = 0;
	struct plugin_request *req = tal(plugin, struct plugin_request);
	struct json_output *out = tal(plugin, struct json_output);
	u64 request_id = next_request_id++;

	req->id = request_id;
	req->method = tal_strdup(req, method);
	req->json_params = tal_strdup(req, params);
	req->cb = cb;
	req->arg = arg;

	/* Add to map so we can find it later when routing the response */
	uintmap_add(&plugin->plugins->pending_requests, req->id, req);

	/* Wrap the request in the JSON-RPC request object */
	out->json = tal_fmt(out, "{"
			    "\"jsonrpc\": \"2.0\", "
			    "\"method\": \"%s\", "
			    "\"params\" : %s, "
			    "\"id\" : %" PRIu64 " }\n",
			    method, params, request_id);

	/* Queue and notify the writer */
	list_add_tail(&plugin->output, &out->list);
	io_wake(plugin);
}

#define plugin_request_send(plugin, method, params, cb, arg)                   \
	plugin_request_send_(                                                  \
	    (plugin), (method), (params),                                      \
	    typesafe_cb_preargs(void, void *, (cb), (arg),                     \
				const struct plugin_request *),                \
	    (arg))

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

/**
 * Callback for the plugin_init request.
 */
static void plugin_init_cb(const struct plugin_request *req, struct plugin *plugin)
{
	/* Check if all plugins are initialized, and break if they are */
	plugin->plugins->pending_init--;
	if (plugin->plugins->pending_init == 0)
		io_break(plugin->plugins);
}

void plugins_init(struct plugins *plugins)
{
	struct plugin *p;
	char **cmd;
	plugins->pending_init = tal_count(plugins->plugins);

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
		plugin_request_send(p, "init", "[]", plugin_init_cb, p);
	}
	io_loop(NULL, NULL);
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
