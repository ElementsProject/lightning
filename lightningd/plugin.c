#include "lightningd/plugin.h"

#include <ccan/array_size/array_size.h>
#include <ccan/intmap/intmap.h>
#include <ccan/io/io.h>
#include <ccan/list/list.h>
#include <ccan/opt/opt.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <ccan/utf8/utf8.h>
#include <common/json_command.h>
#include <common/jsonrpc_errors.h>
#include <common/memleak.h>
#include <common/param.h>
#include <common/timeout.h>
#include <dirent.h>
#include <errno.h>
#include <lightningd/json.h>
#include <lightningd/lightningd.h>
#include <lightningd/notification.h>
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

	/* An array of subscribed topics */
	char **subscriptions;
};

struct plugin_request {
	u64 id;
	struct json_stream *stream;

	/* The response handler to be called when plugin gives us an object. */
	void (*cb)(const char *buffer,
		   const jsmntok_t *toks,
		   const jsmntok_t *idtok,
		   void *);
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
	struct lightningd *ld;
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
			    struct jsonrpc *rpc, struct lightningd *ld)
{
	struct plugins *p;
	p = tal(ctx, struct plugins);
	list_head_init(&p->plugins);
	p->log_book = log_book;
	p->log = new_log(p, log_book, "plugin-manager");
	p->rpc = rpc;
	timers_init(&p->timers, time_mono());
	p->ld = ld;
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
 * The caller needs to add the request to req->stream.
 */
static struct plugin_request *
plugin_request_new_(struct plugin *plugin,
		    void (*cb)(const char *buffer,
			       const jsmntok_t *toks,
			       const jsmntok_t *idtok,
			       void *),
		    void *arg)
{
	static u64 next_request_id = 0;
	struct plugin_request *req = tal(plugin, struct plugin_request);

	req->id = next_request_id++;
	req->cb = cb;
	req->arg = arg;

	/* We will not concurrently drain, if we do we must set the
	 * writer to non-NULL */
	req->stream = new_json_stream(req, NULL);

	/* Add to map so we can find it later when routing the response */
	uintmap_add(&plugin->plugins->pending_requests, req->id, req);
	return req;
}

#define plugin_request_new(plugin, cb, arg)			\
	plugin_request_new_(					\
	    (plugin),						\
	    typesafe_cb_preargs(void, void *, (cb), (arg),	\
				const char *buffer,		\
				const jsmntok_t *toks,		\
				const jsmntok_t *idtok),	\
	    (arg))

/**
 * Send a JSON-RPC message (request or notification) to the plugin.
 */
static void plugin_send(struct plugin *plugin, struct json_stream *stream)
{
	tal_steal(plugin->js_arr, stream);
	*tal_arr_expand(&plugin->js_arr) = stream;
	io_wake(plugin);
}

static void plugin_log_handle(struct plugin *plugin, const jsmntok_t *paramstok)
{
	const jsmntok_t *msgtok, *leveltok;
	enum log_level level;
	msgtok = json_get_member(plugin->buffer, paramstok, "message");
	leveltok = json_get_member(plugin->buffer, paramstok, "level");

	if (!msgtok || msgtok->type != JSMN_STRING) {
		plugin_kill(plugin, "Log notification from plugin doesn't have "
				    "a string \"message\" field");
		return;
	}

	if (!leveltok || json_tok_streq(plugin->buffer, leveltok, "info"))
		level = LOG_INFORM;
	else if (json_tok_streq(plugin->buffer, leveltok, "debug"))
		level = LOG_DBG;
	else if (json_tok_streq(plugin->buffer, leveltok, "warn"))
		level = LOG_UNUSUAL;
	else if (json_tok_streq(plugin->buffer, leveltok, "error"))
		level = LOG_BROKEN;
	else {
		plugin_kill(plugin,
			    "Unknown log-level %.*s, valid values are "
			    "\"debug\", \"info\", \"warn\", or \"error\".",
			    json_tok_full_len(leveltok),
			    json_tok_full(plugin->buffer, leveltok));
		return;
	}

	log_(plugin->log, level, "%.*s", msgtok->end - msgtok->start,
	     plugin->buffer + msgtok->start);
}

static void plugin_notification_handle(struct plugin *plugin,
				       const jsmntok_t *toks)
{
	const jsmntok_t *methtok, *paramstok;

	methtok = json_get_member(plugin->buffer, toks, "method");
	paramstok = json_get_member(plugin->buffer, toks, "params");

	if (!methtok || !paramstok) {
		plugin_kill(plugin,
			    "Malformed JSON-RPC notification missing "
			    "\"method\" or \"params\": %.*s",
			    toks->end - toks->start,
			    plugin->buffer + toks->start);
		return;
	}

	/* Dispatch incoming notifications. This is currently limited
	 * to just a few method types, should this ever become
	 * unwieldy we can switch to the AUTODATA construction to
	 * register notification handlers in a variety of places. */
	if (json_tok_streq(plugin->buffer, methtok, "log")) {
		plugin_log_handle(plugin, paramstok);
	} else {
		plugin_kill(plugin, "Unknown notification method %.*s",
			    json_tok_full_len(methtok),
			    json_tok_full(plugin->buffer, methtok));
	}
}

static void plugin_response_handle(struct plugin *plugin,
				   const jsmntok_t *toks,
				   const jsmntok_t *idtok)
{
	struct plugin_request *request;
	u64 id;
	/* We only send u64 ids, so if this fails it's a critical error (note
	 * that this also works if id is inside a JSON string!). */
	if (!json_to_u64(plugin->buffer, idtok, &id)) {
		plugin_kill(plugin,
			    "JSON-RPC response \"id\"-field is not a u64");
		return;
	}

	request = uintmap_get(&plugin->plugins->pending_requests, id);

	if (!request) {
		plugin_kill(
		    plugin,
		    "Received a JSON-RPC response for non-existent request");
		return;
	}

	/* We expect the request->cb to copy if needed */
	request->cb(plugin->buffer, toks, idtok, request->arg);

	uintmap_del(&plugin->plugins->pending_requests, id);
	tal_free(request);
}

/**
 * Try to parse a complete message from the plugin's buffer.
 *
 * Internally calls the handler if it was able to fully parse a JSON message,
 * and returns true in that case.
 */
static bool plugin_read_json_one(struct plugin *plugin)
{
	bool valid;
	const jsmntok_t *toks, *jrtok, *idtok;

	/* FIXME: This could be done more efficiently by storing the
	 * toks and doing an incremental parse, like lightning-cli
	 * does. */
	toks = json_parse_input(plugin->buffer, plugin->buffer, plugin->used,
				&valid);
	if (!toks) {
		if (!valid) {
			plugin_kill(plugin, "Failed to parse JSON response '%.*s'",
				    (int)plugin->used, plugin->buffer);
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

	jrtok = json_get_member(plugin->buffer, toks, "jsonrpc");
	idtok = json_get_member(plugin->buffer, toks, "id");

	if (!jrtok) {
		plugin_kill(
		    plugin,
		    "JSON-RPC message does not contain \"jsonrpc\" field");
		return false;
	}

	if (!idtok) {
		/* A Notification is a Request object without an "id"
		 * member. A Request object that is a Notification
		 * signifies the Client's lack of interest in the
		 * corresponding Response object, and as such no
		 * Response object needs to be returned to the
		 * client. The Server MUST NOT reply to a
		 * Notification, including those that are within a
		 * batch request.
		 *
		 * https://www.jsonrpc.org/specification#notification
		 */
		plugin_notification_handle(plugin, toks);

	} else {
		/* When a rpc call is made, the Server MUST reply with
		 * a Response, except for in the case of
		 * Notifications. The Response is expressed as a
		 * single JSON Object, with the following members:
		 *
		 * - jsonrpc: A String specifying the version of the
		 *   JSON-RPC protocol. MUST be exactly "2.0".
		 *
		 * - result: This member is REQUIRED on success. This
		 *   member MUST NOT exist if there was an error
		 *   invoking the method. The value of this member is
		 *   determined by the method invoked on the Server.
		 *
		 * - error: This member is REQUIRED on error. This
		 *   member MUST NOT exist if there was no error
		 *   triggered during invocation.
		 *
		 * - id: This member is REQUIRED. It MUST be the same
		 *   as the value of the id member in the Request
		 *   Object. If there was an error in detecting the id
		 *   in the Request object (e.g. Parse error/Invalid
		 *   Request), it MUST be Null. Either the result
		 *   member or error member MUST be included, but both
		 *   members MUST NOT be included.
		 *
		 * https://www.jsonrpc.org/specification#response_object
		 */
		plugin_response_handle(plugin, toks, idtok);
	}

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

		/* Processing the message from the plugin might have
		 * resulted in it stopping, so let's check. */
		if (plugin->stop)
			return io_close(plugin->stdout_conn);
	} while (success);

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

	/* It got dropped off the queue, free it. */
	tal_free(js);

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
		popt->value = json_strdup(popt, buffer, defaulttok);
		popt->description = tal_fmt(
		    popt, "%.*s (default: %s)", desctok->end - desctok->start,
		    buffer + desctok->start, popt->value);
	} else {
		popt->description = json_strdup(popt, buffer, desctok);
	}

	list_add_tail(&plugin->plugin_opts, &popt->list);

	opt_register_arg(popt->name, plugin_opt_set, NULL, popt,
			 popt->description);
	return true;
}

/* Iterate through the options in the manifest response, and add them
 * to the plugin and the command line options */
static bool plugin_opts_add(struct plugin *plugin,
			    const char *buffer,
			    const jsmntok_t *resulttok)
{
	const jsmntok_t *options = json_get_member(buffer, resulttok, "options");

	if (!options) {
		plugin_kill(plugin,
			    "\"result.options\" was not found in the manifest");
		return false;
	}

	if (options->type != JSMN_ARRAY) {
		plugin_kill(plugin, "\"result.options\" is not an array");
		return false;
	}

	for (size_t i = 0; i < options->size; i++)
		if (!plugin_opt_add(plugin, buffer, json_get_arr(options, i)))
			return false;

	return true;
}

static void plugin_rpcmethod_destroy(struct json_command *cmd,
				     struct jsonrpc *rpc)
{
	jsonrpc_command_remove(rpc, cmd->name);
}

static void json_stream_forward_change_id(struct json_stream *stream,
					  const char *buffer,
					  const jsmntok_t *toks,
					  const jsmntok_t *idtok,
					  const char *new_id)
{
	/* We copy everything, but replace the id. Special care has to
	 * be taken when the id that is being replaced is a string. If
	 * we don't crop the quotes off we'll transform a numeric
	 * new_id into a string, or even worse, quote a string id
	 * twice. */
	size_t offset = idtok->type==JSMN_STRING?1:0;
	json_stream_append_part(stream, buffer + toks->start,
				idtok->start - toks->start - offset);

	json_stream_append(stream, new_id);
	json_stream_append_part(stream, buffer + idtok->end + offset,
				toks->end - idtok->end - offset);

	/* We promise it will end in '\n\n' */
	/* It's an object (with an id!): definitely can't be less that "{}" */
	assert(toks->end - toks->start >= 2);
	if (buffer[toks->end-1] != '\n')
		json_stream_append(stream, "\n\n");
	else if (buffer[toks->end-2] != '\n')
		json_stream_append(stream, "\n");
}

static void plugin_rpcmethod_cb(const char *buffer,
				const jsmntok_t *toks,
				const jsmntok_t *idtok,
				struct command *cmd)
{
	struct json_stream *response;

	response = json_stream_raw_for_cmd(cmd);
	json_stream_forward_change_id(response, buffer, toks, idtok, cmd->id);
	command_raw_complete(cmd, response);
}

static struct plugin *find_plugin_for_command(struct command *cmd)
{
	struct plugins *plugins = cmd->ld->plugins;
	struct plugin *plugin;

	/* Find the plugin that registered this RPC call */
	list_for_each(&plugins->plugins, plugin, list) {
		for (size_t i=0; i<tal_count(plugin->methods); i++) {
			if (streq(cmd->json_cmd->name, plugin->methods[i]))
				return plugin;
		}
	}
	/* This should never happen, it'd mean that a plugin didn't
	 * cleanup after dying */
	abort();
}

static struct command_result *plugin_rpcmethod_dispatch(struct command *cmd,
							const char *buffer,
							const jsmntok_t *toks,
							const jsmntok_t *params UNNEEDED)
{
	const jsmntok_t *idtok;
	struct plugin *plugin;
	struct plugin_request *req;
	char id[STR_MAX_CHARS(u64)];

	if (cmd->mode == CMD_USAGE || cmd->mode == CMD_CHECK) {
		/* FIXME! */
		cmd->usage = "[params]";
		return command_param_failed();
	}

	plugin = find_plugin_for_command(cmd);

	/* Find ID again (We've parsed them before, this should not fail!) */
	idtok = json_get_member(buffer, toks, "id");
	assert(idtok != NULL);

	req = plugin_request_new(plugin, plugin_rpcmethod_cb, cmd);
	snprintf(id, ARRAY_SIZE(id), "%"PRIu64, req->id);

	json_stream_forward_change_id(req->stream, buffer, toks, idtok, id);
	plugin_send(plugin, req->stream);
	req->stream = NULL;

	return command_still_pending(cmd);
}

static bool plugin_rpcmethod_add(struct plugin *plugin,
				 const char *buffer,
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
	cmd->name = json_strdup(cmd, buffer, nametok);
	cmd->description = json_strdup(cmd, buffer, desctok);
	if (longdesctok)
		cmd->verbose = json_strdup(cmd, buffer, longdesctok);
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

static bool plugin_rpcmethods_add(struct plugin *plugin,
				  const char *buffer,
				  const jsmntok_t *resulttok)
{
	const jsmntok_t *methods =
		json_get_member(buffer, resulttok, "rpcmethods");

	if (!methods)
		return false;

	if (methods->type != JSMN_ARRAY) {
		plugin_kill(plugin,
			    "\"result.rpcmethods\" is not an array");
		return false;
	}

	for (size_t i = 0; i < methods->size; i++)
		if (!plugin_rpcmethod_add(plugin, buffer,
					  json_get_arr(methods, i)))
			return false;
	return true;
}

static bool plugin_subscriptions_add(struct plugin *plugin, const char *buffer,
				     const jsmntok_t *resulttok)
{
	const jsmntok_t *subscriptions =
	    json_get_member(buffer, resulttok, "subscriptions");

	if (!subscriptions) {
		plugin->subscriptions = NULL;
		return true;
	}
	plugin->subscriptions = tal_arr(plugin, char *, 0);
	if (subscriptions->type != JSMN_ARRAY) {
		plugin_kill(plugin, "\"result.subscriptions\" is not an array");
		return false;
	}

	for (int i = 0; i < subscriptions->size; i++) {
		char *topic;
		const jsmntok_t *s = json_get_arr(subscriptions, i);
		if (s->type != JSMN_STRING) {
			plugin_kill(
			    plugin,
			    "result.subscriptions[%d] is not a string: %s", i,
			    plugin->buffer);
			return false;
		}
		topic = json_strdup(plugin, plugin->buffer, s);

		if (!notifications_have_topic(topic)) {
			plugin_kill(
			    plugin,
			    "topic '%s' is not a known notification topic", topic);
			return false;
		}

		*tal_arr_expand(&plugin->subscriptions) = topic;
	}
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
static void plugin_manifest_cb(const char *buffer,
			       const jsmntok_t *toks,
			       const jsmntok_t *idtok,
			       struct plugin *plugin)
{
	const jsmntok_t *resulttok;

	/* Check if all plugins have replied to getmanifest, and break
	 * if they are */
	plugin->plugins->pending_manifests--;
	if (plugin->plugins->pending_manifests == 0)
		io_break(plugin->plugins);

	resulttok = json_get_member(buffer, toks, "result");
	if (!resulttok || resulttok->type != JSMN_OBJECT) {
		plugin_kill(plugin,
			    "\"getmanifest\" result is not an object");
		return;
	}

	if (!plugin_opts_add(plugin, buffer, resulttok)
	    || !plugin_rpcmethods_add(plugin, buffer, resulttok)
	    || !plugin_subscriptions_add(plugin, buffer, resulttok))
		plugin_kill(
		    plugin,
		    "Failed to register options, methods, or subscriptions.");
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
	/* Only regular files please (or symlinks to such: stat not lstat!) */
	if ((st.st_mode & S_IFMT) != S_IFREG)
		return tal_free(fullname);
	/* Must be executable by someone. */
	if (!(st.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH)))
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
		return tal_fmt(NULL, "Failed to open plugin-dir %s: %s",
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

/* For our own "getmanifest" and "init" requests: starts params[] */
static void start_simple_request(struct plugin_request *req, const char *reqname)
{
	json_object_start(req->stream, NULL);
	json_add_string(req->stream, "jsonrpc", "2.0");
	json_add_string(req->stream, "method", reqname);
	json_add_u64(req->stream, "id", req->id);
}

static void end_simple_request(struct plugin *plugin, struct plugin_request *req)
{
	json_object_end(req->stream);
	json_stream_append(req->stream, "\n\n");
	plugin_send(plugin, req->stream);
	req->stream = NULL;
}

void plugins_init(struct plugins *plugins, const char *dev_plugin_debug)
{
	struct plugin *p;
	char **cmd;
	int stdin, stdout;
	struct timer *expired;
	struct plugin_request *req;
	plugins->pending_manifests = 0;
	uintmap_init(&plugins->pending_requests);

	setenv("LIGHTNINGD_PLUGIN", "1", 1);
	/* Spawn the plugin processes before entering the io_loop */
	list_for_each(&plugins->plugins, p, list) {
		bool debug;

		debug = dev_plugin_debug && strends(p->cmd, dev_plugin_debug);
		cmd = tal_arrz(p, char *, 2 + debug);
		cmd[0] = p->cmd;
		if (debug)
			cmd[1] = "--debugger";
		p->pid = pipecmdarr(&stdin, &stdout, &pipecmd_preserve, cmd);

		if (p->pid == -1)
			fatal("error starting plugin '%s': %s", p->cmd,
			      strerror(errno));
		p->buffer = tal_arr(p, char, 64);
		p->stop = false;

		/* Create two connections, one read-only on top of p->stdin, and one
		 * write-only on p->stdout */
		io_new_conn(p, stdout, plugin_stdout_conn_init, p);
		io_new_conn(p, stdin, plugin_stdin_conn_init, p);
		req = plugin_request_new(p, plugin_manifest_cb, p);
		start_simple_request(req, "getmanifest");
		json_array_start(req->stream, "params");
		json_array_end(req->stream);
		end_simple_request(p, req);
		plugins->pending_manifests++;
		/* Don't timeout if they're running a debugger. */
		if (debug)
			p->timeout_timer = NULL;
		else {
			p->timeout_timer
				= new_reltimer(&plugins->timers, p,
					       time_from_sec(PLUGIN_MANIFEST_TIMEOUT),
					       plugin_manifest_timeout, p);
		}
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

static void plugin_config_cb(const char *buffer,
			     const jsmntok_t *toks,
			     const jsmntok_t *idtok,
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
	struct lightningd *ld = plugin->plugins->ld;

	/* No writer since we don't flush concurrently. */
	req = plugin_request_new(plugin, plugin_config_cb, plugin);
	start_simple_request(req, "init");
	json_object_start(req->stream, "params"); /* start of .params */

	/* Add .params.options */
	json_object_start(req->stream, "options");
	list_for_each(&plugin->plugin_opts, opt, list) {
		/* Trim the `--` that we added before */
		name = opt->name + 2;
		json_add_string(req->stream, name, opt->value);
	}
	json_object_end(req->stream); /* end of .params.options */

	/* Add .params.configuration */
	json_object_start(req->stream, "configuration");
	json_add_string(req->stream, "lightning-dir", ld->config_dir);
	json_add_string(req->stream, "rpc-file", ld->rpc_filename);
	json_object_end(req->stream);

	json_object_end(req->stream); /* end of .params */
	end_simple_request(plugin, req);
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

/**
 * Determine whether a plugin is subscribed to a given topic/method.
 */
static bool plugin_subscriptions_contains(struct plugin *plugin,
					  const char *method)
{
	for (size_t i = 0; i < tal_count(plugin->subscriptions); i++)
		if (streq(method, plugin->subscriptions[i]))
			return true;

	return false;
}

void plugins_notify(struct plugins *plugins,
		    const struct jsonrpc_notification *n TAKES)
{
	struct plugin *p;
	list_for_each(&plugins->plugins, p, list) {
		if (plugin_subscriptions_contains(p, n->method))
			plugin_send(p, json_stream_dup(p, n->stream));
	}
	if (taken(n))
		tal_free(n);
}
