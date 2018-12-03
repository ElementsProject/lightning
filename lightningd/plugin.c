#include "lightningd/plugin.h"

#include <ccan/intmap/intmap.h>
#include <ccan/io/io.h>
#include <ccan/list/list.h>
#include <ccan/opt/opt.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <ccan/utf8/utf8.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <dirent.h>
#include <errno.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/lightningd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* How many seconds may the plugin take to reply to the `getmanifest
 * call`? This is the maximum delay to `lightningd --help` and until
 * we can start the main `io_loop` to communicate with peers. If this
 * hangs we can't do much, so we put an upper bound on the time we're
 * willing to wait. Plugins shouldn't do any initialization in the
 * `getmanifest` call anyway, that's what `init `is for. */
#define PLUGIN_MANIFEST_TIMEOUT 10

struct plugin {
	struct list_node list;

	pid_t pid;
	char *cmd;
	struct io_conn *stdin_conn, *stdout_conn;
	bool stop;
	struct plugins *plugins;
	const char **plugin_path;

	/* Stuff we read */
	char *buffer;
	size_t used, len_read;

	/* Our json_streams. Since multiple streams could start
	 * returning data at once, we always service these in order,
	 * freeing once empty. */
	struct json_stream **js_arr;

	struct log *log;

	/* List of options that this plugin registered */
	struct list_head plugin_opts;

	const char **methods;

	/* Timer to add a timeout to some plugin RPC calls. Used to
	 * guarantee that `getmanifest` doesn't block indefinitely. */
	const struct oneshot *timeout_timer;
};

struct plugin_request {
	u64 id;
	struct plugin *plugin;

	/* Method to be called */
	const char *method;

	/* JSON encoded params, either a dict or an array */
	const char *json_params;
	const char *response;
	const jsmntok_t *resulttok, *errortok, *toks;
	struct json_stream *stream;

	/* The response handler to be called on success or error */
	void (*cb)(const struct plugin_request *, void *);
	void *arg;
};

struct plugins {
	struct list_head plugins;
	size_t pending_manifests;

	/* Currently pending requests by their request ID */
	UINTMAP(struct plugin_request *) pending_requests;
	struct log *log;
	struct log_book *log_book;

	/* RPC interface to bind JSON-RPC methods to */
	struct jsonrpc *rpc;

	struct timers timers;
};

/* Represents a pending JSON-RPC request that was forwarded to a
 * plugin and is currently waiting for it to return the result. */
struct plugin_rpc_request {
	/* The json-serialized ID as it was passed to us by the
	 * client, will be used to return the result */
	const char *id;

	const char *method;
	const char *params;

	struct plugin *plugin;
	struct command *cmd;
};

/* Simple storage for plugin options inbetween registering them on the
 * command line and passing them off to the plugin */
struct plugin_opt {
	struct list_node list;
	const char *name;
	const char *description;
	char *value;
};

struct plugins *plugins_new(const tal_t *ctx, struct log_book *log_book,
			    struct jsonrpc *rpc)
{
	struct plugins *p;
	p = tal(ctx, struct plugins);
	list_head_init(&p->plugins);
	p->log_book = log_book;
	p->log = new_log(p, log_book, "plugin-manager");
	p->rpc = rpc;
	timers_init(&p->timers, time_mono());
	return p;
}

void plugin_register(struct plugins *plugins, const char* path TAKES)
{
	struct plugin *p;
	p = tal(plugins, struct plugin);
	list_add_tail(&plugins->plugins, &p->list);
	p->plugins = plugins;
	p->cmd = tal_strdup(p, path);
	p->js_arr = tal_arr(p, struct json_stream *, 0);
	p->used = 0;

	p->log = new_log(p, plugins->log_book, "plugin-%s",
			 path_basename(tmpctx, p->cmd));
	p->methods = tal_arr(p, const char *, 0);
	list_head_init(&p->plugin_opts);
}

static bool paths_match(const char *cmd, const char *name)
{
	if (strchr(name, PATH_SEP)) {
		const char *cmd_canon, *name_canon;

		if (streq(cmd, name))
			return true;

		/* These return NULL path doesn't exist */
		cmd_canon = path_canon(tmpctx, cmd);
		name_canon = path_canon(tmpctx, name);
		return cmd_canon && name_canon && streq(name_canon, cmd_canon);
	} else {
		/* No path separator means a basename match. */
		const char *base = path_basename(tmpctx, cmd);

		return streq(base, name);
	}
}

bool plugin_remove(struct plugins *plugins, const char *name)
{
	struct plugin *p, *next;
	bool removed = false;

	list_for_each_safe(&plugins->plugins, p, next, list) {
		if (paths_match(p->cmd, name)) {
			list_del_from(&plugins->plugins, &p->list);
			tal_free(p);
			removed = true;
		}
	}
	return removed;
}

/**
 * Kill a plugin process, with an error message.
 */
static void PRINTF_FMT(2,3) plugin_kill(struct plugin *plugin, char *fmt, ...)
{
	char *msg;
	va_list ap;

	va_start(ap, fmt);
	msg = tal_vfmt(plugin, fmt, ap);
	va_end(ap);

	log_broken(plugin->log, "Killing plugin: %s", msg);
	plugin->stop = true;
	io_wake(plugin);
	kill(plugin->pid, SIGKILL);
	list_del(&plugin->list);
}

/**
 * Create the header of a JSON-RPC request and return open stream.
 *
 * This is a partial request, missing the params element, which the
 * caller needs to add. We can't open it yet since we don't know
 * whether it is supposed to be an object (name-value pairs) or an
 * array.
 */
static struct plugin_request *
plugin_request_new_(struct plugin *plugin, const char *method,
		    void (*cb)(const struct plugin_request *, void *),
		    void *arg)
{
	static u64 next_request_id = 0;
	struct plugin_request *req = tal(plugin, struct plugin_request);
	u64 request_id = next_request_id++;

	req->id = request_id;
	req->method = tal_strdup(req, method);
	req->cb = cb;
	req->arg = arg;
	req->plugin = plugin;

	/* We will not concurrently drain, if we do we must set the
	 * writer to non-NULL */
	req->stream = new_json_stream(req, NULL);

	/* Add to map so we can find it later when routing the response */
	uintmap_add(&plugin->plugins->pending_requests, req->id, req);

	json_object_start(req->stream, NULL);
	json_add_string(req->stream, "jsonrpc", "2.0");
	json_add_string(req->stream, "method", method);
	json_add_u64(req->stream, "id", request_id);
	return req;
}

#define plugin_request_new(plugin, method, cb, arg)                            \
	plugin_request_new_(                                                   \
	    (plugin), (method),                                                \
	    typesafe_cb_preargs(void, void *, (cb), (arg),                     \
				const struct plugin_request *),                \
	    (arg))

/**
 * Given a request, send it to the plugin.
 */
static void plugin_request_queue(struct plugin_request *req)
{
	/* Finish the `params` object and submit the request */
	json_object_end(req->stream); /* root element */
	json_stream_append(req->stream, "\n\n");
	*tal_arr_expand(&req->plugin->js_arr) = req->stream;
	io_wake(req->plugin);
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

	/* FIXME: This could be done more efficiently by storing the
	 * toks and doing an incremental parse, like lightning-cli
	 * does. */
	toks = json_parse_input(plugin->buffer, plugin->used, &valid);
	if (!toks) {
		if (!valid) {
			plugin_kill(plugin, "Failed to parse JSON response");
			return false;
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

	if (!idtok) {
		plugin_kill(plugin, "JSON-RPC response does not contain an \"id\"-field");
		return false;
	} else if (!resulttok && !errortok) {
		plugin_kill(plugin, "JSON-RPC response does not contain a \"result\" or \"error\" field");
		return false;
	}

	/* We only send u64 ids, so if this fails it's a critical error */
	if (!json_to_u64(plugin->buffer, idtok, &id)) {
		plugin_kill(plugin, "JSON-RPC response \"id\"-field is not a u64");
		return false;
	}

	request = uintmap_get(&plugin->plugins->pending_requests, id);

	if (!request) {
		plugin_kill(plugin, "Received a JSON-RPC response for non-existent request");
		return false;
	}

	/* We expect the request->cb to copy if needed */
	request->response = plugin->buffer;
	request->errortok = errortok;
	request->resulttok = resulttok;
	request->toks = toks;
	request->cb(request, request->arg);

	tal_free(request);
	uintmap_del(&plugin->plugins->pending_requests, id);

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

	if (plugin->stop)
		return io_close(plugin->stdout_conn);

	/* Now read more from the connection */
	return io_read_partial(plugin->stdout_conn,
			       plugin->buffer + plugin->used,
			       tal_count(plugin->buffer) - plugin->used,
			       &plugin->len_read, plugin_read_json, plugin);
}

/* Mutual recursion */
static struct io_plan *plugin_write_json(struct io_conn *conn,
					 struct plugin *plugin);

static struct io_plan *plugin_stream_complete(struct io_conn *conn, struct json_stream *js, struct plugin *plugin)
{
	assert(tal_count(plugin->js_arr) > 0);
	/* Remove js and shift all remainig over */
	tal_arr_remove(&plugin->js_arr, 0);

	return plugin_write_json(conn, plugin);
}

static struct io_plan *plugin_write_json(struct io_conn *conn,
					 struct plugin *plugin)
{
	if (tal_count(plugin->js_arr)) {
		return json_stream_output(plugin->js_arr[0], plugin->stdin_conn, plugin_stream_complete, plugin);
	} else if (plugin->stop) {
		return io_close(conn);
	}

	return io_out_wait(conn, plugin, plugin_write_json, plugin);
}

/**
 * Finalizer for both stdin and stdout connections.
 *
 * Takes care of final cleanup, once the plugin is definitely dead.
 */
static void plugin_conn_finish(struct io_conn *conn, struct plugin *plugin)
{
	if (conn == plugin->stdin_conn)
		plugin->stdin_conn = NULL;

	else if (conn == plugin->stdout_conn)
		plugin->stdout_conn = NULL;

	if (plugin->stdin_conn == NULL && plugin->stdout_conn == NULL)
		tal_free(plugin);
}

static struct io_plan *plugin_stdin_conn_init(struct io_conn *conn,
					      struct plugin *plugin)
{
	/* We write to their stdin */
	/* We don't have anything queued yet, wait for notification */
	plugin->stdin_conn = conn;
	io_set_finish(conn, plugin_conn_finish, plugin);
	return io_wait(plugin->stdin_conn, plugin, plugin_write_json, plugin);
}

static struct io_plan *plugin_stdout_conn_init(struct io_conn *conn,
					       struct plugin *plugin)
{
	/* We read from their stdout */
	plugin->stdout_conn = conn;
	io_set_finish(conn, plugin_conn_finish, plugin);
	return io_read_partial(plugin->stdout_conn, plugin->buffer,
			       tal_bytelen(plugin->buffer), &plugin->len_read,
			       plugin_read_json, plugin);
}

/* Callback called when parsing options. It just stores the value in
 * the plugin_opt */
static char *plugin_opt_set(const char *arg, struct plugin_opt *popt)
{
	tal_free(popt->value);
	popt->value = tal_strdup(popt, arg);
	return NULL;
}

/* Add a single plugin option to the plugin as well as registering it with the
 * command line options. */
static bool plugin_opt_add(struct plugin *plugin, const char *buffer,
			   const jsmntok_t *opt)
{
	const jsmntok_t *nametok, *typetok, *defaulttok, *desctok;
	struct plugin_opt *popt;
	nametok = json_get_member(buffer, opt, "name");
	typetok = json_get_member(buffer, opt, "type");
	desctok = json_get_member(buffer, opt, "description");
	defaulttok = json_get_member(buffer, opt, "default");

	if (!typetok || !nametok || !desctok) {
		plugin_kill(plugin,
			    "An option is missing either \"name\", \"description\" or \"type\"");
		return false;
	}

	/* FIXME(cdecker) Support numeric and boolean options as well */
	if (!json_tok_streq(buffer, typetok, "string")) {
		plugin_kill(plugin,
			    "Only \"string\" options currently supported");
		return false;
	}

	popt = tal(plugin, struct plugin_opt);

	popt->name = tal_fmt(plugin, "--%.*s", nametok->end - nametok->start,
			     buffer + nametok->start);
	popt->value = NULL;
	if (defaulttok) {
		popt->value = tal_strndup(popt, buffer + defaulttok->start,
					  defaulttok->end - defaulttok->start);
		popt->description = tal_fmt(
		    popt, "%.*s (default: %s)", desctok->end - desctok->start,
		    buffer + desctok->start, popt->value);
	} else {
		popt->description = tal_strndup(popt, buffer + desctok->start,
						desctok->end - desctok->start);
	}

	list_add_tail(&plugin->plugin_opts, &popt->list);

	opt_register_arg(popt->name, plugin_opt_set, NULL, popt,
			 popt->description);
	return true;
}

/* Iterate through the options in the manifest response, and add them
 * to the plugin and the command line options */
static bool plugin_opts_add(const struct plugin_request *req)
{
	const char *buffer = req->plugin->buffer;
	const jsmntok_t *options =
	    json_get_member(req->plugin->buffer, req->resulttok, "options");

	if (!options) {
		plugin_kill(req->plugin,
			    "\"result.options\" was not found in the manifest");
		return false;
	}

	if (options->type != JSMN_ARRAY) {
		plugin_kill(req->plugin, "\"result.options\" is not an array");
		return false;
	}

	for (size_t i = 0; i < options->size; i++)
		if (!plugin_opt_add(req->plugin, buffer, json_get_arr(options, i)))
			return false;

	return true;
}

static void plugin_rpcmethod_destroy(struct json_command *cmd,
				     struct jsonrpc *rpc)
{
	jsonrpc_command_remove(rpc, cmd->name);
}

static void plugin_rpcmethod_cb(const struct plugin_request *req,
				struct plugin_rpc_request *rpc_req)
{
	struct json_stream *response;
	const jsmntok_t *res;
	assert(req->resulttok || req->errortok);

	if (req->errortok) {
		res = req->errortok;
		command_fail(rpc_req->cmd, PLUGIN_ERROR, "%.*s",
			     res->end - res->start, req->response + res->start);
		tal_free(rpc_req);
		return;
	}

	res = req->resulttok;
	response = json_stream_success(rpc_req->cmd);

	json_add_member(response, NULL, "%.*s", json_tok_len(res),
			json_tok_contents(req->response, res));

	command_success(rpc_req->cmd, response);
	tal_free(rpc_req);
}

static void plugin_rpcmethod_dispatch(struct command *cmd, const char *buffer,
				      const jsmntok_t *params)
{
	const jsmntok_t *toks = params, *methtok, *idtok;
	struct plugin_rpc_request *request;
	struct plugins *plugins = cmd->ld->plugins;
	struct plugin *plugin;
	struct plugin_request *req;

	if (cmd->mode == CMD_USAGE) {
		cmd->usage = "[params]";
		return;
	}

	/* We're given the params, but we need to walk back to the
	 * root object, so just walk backwards until the current
	 * element has no parents, that's going to be the root
	 * element. */
	while (toks->parent != -1)
		toks--;

	methtok = json_get_member(buffer, toks, "method");
	idtok = json_get_member(buffer, toks, "id");
	/* We've parsed them before, these should not fail! */
	assert(idtok != NULL && methtok != NULL);

	request = tal(NULL, struct plugin_rpc_request);
	request->method = tal_strndup(request, buffer + methtok->start,
				      methtok->end - methtok->start);
	request->id = tal_strndup(request, buffer + idtok->start,
				      idtok->end - idtok->start);
	request->params = tal_strndup(request, buffer + params->start,
				      params->end - params->start);
	request->plugin = NULL;
	request->cmd = cmd;

	/* Find the plugin that registered this RPC call */
	list_for_each(&plugins->plugins, plugin, list) {
		for (size_t i=0; i<tal_count(plugin->methods); i++) {
			if (streq(request->method, plugin->methods[i])) {
				request->plugin = plugin;
				goto found;
			}
		}
	}

found:
	/* This should never happen, it'd mean that a plugin didn't
	 * cleanup after dying */
	assert(request->plugin);

	tal_steal(request->plugin, request);
	req = plugin_request_new(request->plugin, request->method, plugin_rpcmethod_cb, request);
	json_stream_append_fmt(req->stream, ", \"params\": %s", request->params);
	plugin_request_queue(req);

	command_still_pending(cmd);
}

static bool plugin_rpcmethod_add(struct plugin *plugin, const char *buffer,
				 const jsmntok_t *meth)
{
	const jsmntok_t *nametok, *desctok, *longdesctok;
	struct json_command *cmd;

	nametok = json_get_member(buffer, meth, "name");
	desctok = json_get_member(buffer, meth, "description");
	longdesctok = json_get_member(buffer, meth, "long_description");

	if (!nametok || nametok->type != JSMN_STRING) {
		plugin_kill(plugin,
			    "rpcmethod does not have a string \"name\": %.*s",
			    meth->end - meth->start, buffer + meth->start);
		return false;
	}

	if (!desctok || desctok->type != JSMN_STRING) {
		plugin_kill(plugin,
			    "rpcmethod does not have a string "
			    "\"description\": %.*s",
			    meth->end - meth->start, buffer + meth->start);
		return false;
	}

	if (longdesctok && longdesctok->type != JSMN_STRING) {
		plugin_kill(plugin,
			    "\"long_description\" is not a string: %.*s",
			    meth->end - meth->start, buffer + meth->start);
		return false;
	}

	cmd = notleak(tal(plugin, struct json_command));
	cmd->name = tal_strndup(cmd, buffer + nametok->start,
				nametok->end - nametok->start);
	cmd->description = tal_strndup(cmd, buffer + desctok->start,
				       desctok->end - desctok->start);
	if (longdesctok)
		cmd->verbose =
		    tal_strndup(cmd, buffer + longdesctok->start,
				longdesctok->end - longdesctok->start);
	else
		cmd->verbose = cmd->description;

	cmd->deprecated = false;
	cmd->dispatch = plugin_rpcmethod_dispatch;
	tal_add_destructor2(cmd, plugin_rpcmethod_destroy, plugin->plugins->rpc);
	if (!jsonrpc_command_add(plugin->plugins->rpc, cmd)) {
		log_broken(plugin->log,
			   "Could not register method \"%s\", a method with "
			   "that name is already registered",
			   cmd->name);
		return false;
	}
	*tal_arr_expand(&plugin->methods) = cmd->name;
	return true;
}

static bool plugin_rpcmethods_add(const struct plugin_request *req)
{
	const char *buffer = req->plugin->buffer;
	const jsmntok_t *methods =
	    json_get_member(req->plugin->buffer, req->resulttok, "rpcmethods");

	if (!methods)
		return false;

	if (methods->type != JSMN_ARRAY) {
		plugin_kill(req->plugin,
			    "\"result.rpcmethods\" is not an array");
		return false;
	}

	for (size_t i = 0; i < methods->size; i++)
		if (!plugin_rpcmethod_add(req->plugin, buffer,
					  json_get_arr(methods, i)))
			return false;
	return true;
}

static void plugin_manifest_timeout(struct plugin *plugin)
{
	log_broken(plugin->log, "The plugin failed to respond to \"getmanifest\" in time, terminating.");
	fatal("Can't recover from plugin failure, terminating.");
}

/**
 * Callback for the plugin_manifest request.
 */
static void plugin_manifest_cb(const struct plugin_request *req, struct plugin *plugin)
{
	/* Check if all plugins have replied to getmanifest, and break
	 * if they are */
	plugin->plugins->pending_manifests--;
	if (plugin->plugins->pending_manifests == 0)
		io_break(plugin->plugins);

	if (req->resulttok->type != JSMN_OBJECT) {
		plugin_kill(plugin,
			    "\"getmanifest\" response is not an object");
		return;
	}

	if (!plugin_opts_add(req) || !plugin_rpcmethods_add(req))
		plugin_kill(plugin, "Failed to register options or methods");
	/* Reset timer, it'd kill us otherwise. */
	tal_free(plugin->timeout_timer);
}

/* If this is a valid plugin return full path name, otherwise NULL */
static const char *plugin_fullpath(const tal_t *ctx, const char *dir,
				   const char *basename)
{
	struct stat st;
	const char *fullname;
	struct utf8_state utf8 = UTF8_STATE_INIT;

	for (size_t i = 0; basename[i]; i++) {
		if (!utf8_decode(&utf8, basename[i]))
			continue;
		/* Not valid UTF8?  Let's not go there... */
		if (errno != 0)
			return NULL;
		if (utf8.used_len != 1)
			continue;
		if (!cispunct(utf8.c))
			continue;
		if (utf8.c != '-' && utf8.c != '_' && utf8.c != '.')
			return NULL;
	}

	fullname = path_join(ctx, dir, basename);
	if (stat(fullname, &st) != 0)
		return tal_free(fullname);
	if (!(st.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH)) || st.st_mode & S_IFDIR)
		return tal_free(fullname);

	/* Ignore directories, they have exec mode, but aren't executable. */
	if (st.st_mode & S_IFDIR)
		return tal_free(fullname);
	return fullname;
}

char *add_plugin_dir(struct plugins *plugins, const char *dir, bool nonexist_ok)
{
	struct dirent *di;
	DIR *d = opendir(dir);
	if (!d) {
		if (nonexist_ok && errno == ENOENT)
			return NULL;
		return tal_fmt("Failed to open plugin-dir %s: %s",
			       dir, strerror(errno));
	}

	while ((di = readdir(d)) != NULL) {
		const char *fullpath;

		if (streq(di->d_name, ".") || streq(di->d_name, ".."))
			continue;
		fullpath = plugin_fullpath(NULL, dir, di->d_name);
		if (fullpath)
			plugin_register(plugins, take(fullpath));
	}
	return NULL;
}

void clear_plugins(struct plugins *plugins)
{
	struct plugin *p;

	log_info(plugins->log, "clear-plugins removing all plugins");
	while ((p = list_pop(&plugins->plugins, struct plugin, list)) != NULL)
		tal_free(p);
}

void plugins_init(struct plugins *plugins)
{
	struct plugin *p;
	char **cmd;
	int stdin, stdout;
	struct timer *expired;
	struct plugin_request *req;
	plugins->pending_manifests = 0;
	uintmap_init(&plugins->pending_requests);

	/* Spawn the plugin processes before entering the io_loop */
	list_for_each(&plugins->plugins, p, list) {
		cmd = tal_arr(p, char *, 2);
		cmd[0] = p->cmd;
		cmd[1] = NULL;
		p->pid = pipecmdarr(&stdout, &stdin, NULL, cmd);

		if (p->pid == -1)
			fatal("error starting plugin '%s': %s", p->cmd,
			      strerror(errno));
		p->buffer = tal_arr(p, char, 64);
		p->stop = false;

		/* Create two connections, one read-only on top of p->stdin, and one
		 * write-only on p->stdout */
		io_new_conn(p, stdout, plugin_stdout_conn_init, p);
		io_new_conn(p, stdin, plugin_stdin_conn_init, p);
		req = plugin_request_new(p, "getmanifest", plugin_manifest_cb, p);
		json_array_start(req->stream, "params");
		json_array_end(req->stream);
		plugin_request_queue(req);
		plugins->pending_manifests++;
		p->timeout_timer = new_reltimer(
		    &plugins->timers, p, time_from_sec(PLUGIN_MANIFEST_TIMEOUT),
		    plugin_manifest_timeout, p);
		tal_free(cmd);
	}

	while (plugins->pending_manifests > 0) {
		void *v = io_loop(&plugins->timers, &expired);
		if (v == plugins)
			break;
		if (expired)
			timer_expired(plugins, expired);
	}
}

static void plugin_config_cb(const struct plugin_request *req,
			     struct plugin *plugin)
{
	/* Nothing to be done here, this is just a report */
}

/* FIXME(cdecker) This just builds a string for the request because
 * the json_stream is tightly bound to the command interface. It
 * should probably be generalized and fixed up. */
static void plugin_config(struct plugin *plugin)
{
	struct plugin_opt *opt;
	const char *name;
	struct plugin_request *req;

	/* No writer since we don't flush concurrently. */
	req = plugin_request_new(plugin, "init", plugin_config_cb, plugin);
	json_object_start(req->stream, "params"); /* start of .params */

	/* Add .params.options */
	json_object_start(req->stream, "options");
	list_for_each(&plugin->plugin_opts, opt, list) {
		/* Trim the `--` that we added before */
		name = opt->name + 2;
		json_add_string(req->stream, name, opt->value);
	}
	json_object_end(req->stream); /* end of .params.options */

	json_object_end(req->stream); /* end of .params */

	plugin_request_queue(req);
}

void plugins_config(struct plugins *plugins)
{
	struct plugin *p;
	list_for_each(&plugins->plugins, p, list) {
		plugin_config(p);
	}
}

void json_add_opt_plugins(struct json_stream *response,
			  const struct plugins *plugins)
{
	struct plugin *p;
	list_for_each(&plugins->plugins, p, list) {
		json_add_string(response, "plugin", p->cmd);
	}
}
