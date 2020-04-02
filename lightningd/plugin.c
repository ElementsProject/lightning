#include <ccan/array_size/array_size.h>
#include <ccan/list/list.h>
#include <ccan/opt/opt.h>
#include <ccan/tal/str/str.h>
#include <ccan/utf8/utf8.h>
#include <common/features.h>
#include <common/utils.h>
#include <common/version.h>
#include <lightningd/json.h>
#include <lightningd/notification.h>
#include <lightningd/options.h>
#include <lightningd/plugin.h>
#include <lightningd/plugin_hook.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

/* How many seconds may the plugin take to reply to the `getmanifest`
 * call? This is the maximum delay to `lightningd --help` and until
 * we can start the main `io_loop` to communicate with peers. If this
 * hangs we can't do much, so we put an upper bound on the time we're
 * willing to wait. Plugins shouldn't do any initialization in the
 * `getmanifest` call anyway, that's what `init` is for. */
#define PLUGIN_MANIFEST_TIMEOUT 60

#if DEVELOPER
static void memleak_help_pending_requests(struct htable *memtable,
					  struct plugins *plugins)
{
	memleak_remove_uintmap(memtable, &plugins->pending_requests);
}
#endif /* DEVELOPER */

struct plugins *plugins_new(const tal_t *ctx, struct log_book *log_book,
			    struct lightningd *ld)
{
	struct plugins *p;
	p = tal(ctx, struct plugins);
	list_head_init(&p->plugins);
	p->log_book = log_book;
	p->log = new_log(p, log_book, NULL, "plugin-manager");
	p->ld = ld;
	p->startup = true;
	uintmap_init(&p->pending_requests);
	memleak_add_helper(p, memleak_help_pending_requests);

	return p;
}

static void destroy_plugin(struct plugin *p)
{
	plugin_hook_unregister_all(p);
	list_del(&p->list);
}

struct plugin *plugin_register(struct plugins *plugins, const char* path TAKES)
{
	struct plugin *p, *p_temp;

	/* Don't register an already registered plugin */
	list_for_each(&plugins->plugins, p_temp, list) {
		if (streq(path, p_temp->cmd)) {
			if (taken(path))
				tal_free(path);
			return NULL;
		}
	}

	p = tal(plugins, struct plugin);
	p->plugins = plugins;
	p->cmd = tal_strdup(p, path);

	p->plugin_state = UNCONFIGURED;
	p->js_arr = tal_arr(p, struct json_stream *, 0);
	p->used = 0;
	p->subscriptions = NULL;
	p->dynamic = false;

	p->log = new_log(p, plugins->log_book, NULL, "plugin-%s",
			 path_basename(tmpctx, p->cmd));
	p->methods = tal_arr(p, const char *, 0);
	list_head_init(&p->plugin_opts);

	list_add_tail(&plugins->plugins, &p->list);
	tal_add_destructor(p, destroy_plugin);
	return p;
}

bool plugin_paths_match(const char *cmd, const char *name)
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
		if (plugin_paths_match(p->cmd, name)) {
			list_del_from(&plugins->plugins, &p->list);
			tal_free(p);
			removed = true;
		}
	}
	return removed;
}

void plugin_kill(struct plugin *plugin, char *fmt, ...)
{
	char *msg;
	va_list ap;

	va_start(ap, fmt);
	msg = tal_vfmt(plugin, fmt, ap);
	va_end(ap);

	log_info(plugin->log, "Killing plugin: %s", msg);
	plugin->stop = true;
	io_wake(plugin);
	kill(plugin->pid, SIGKILL);
	list_del(&plugin->list);
}

/**
 * Send a JSON-RPC message (request or notification) to the plugin.
 */
static void plugin_send(struct plugin *plugin, struct json_stream *stream)
{
	tal_steal(plugin->js_arr, stream);
	tal_arr_expand(&plugin->js_arr, stream);
	io_wake(plugin);
}

static void plugin_log_handle(struct plugin *plugin, const jsmntok_t *paramstok)
{
	const jsmntok_t *msgtok, *leveltok;
	enum log_level level;
	bool call_notifier;
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

	call_notifier = (level == LOG_BROKEN || level == LOG_UNUSUAL)? true : false;
	/* FIXME: Let plugin specify node_id? */
	log_(plugin->log, level, NULL, call_notifier, "%.*s", msgtok->end - msgtok->start,
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
	struct plugin_destroyed *pd;
	struct jsonrpc_request *request;
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
	pd = plugin_detect_destruction(plugin);
	request->response_cb(plugin->buffer, toks, idtok, request->response_cb_arg);

	/* Note that in the case of 'plugin stop' this can free request (since
	 * plugin is parent), so detect that case */
	if (!was_plugin_destroyed(pd))
		tal_free(request);
}

/**
 * Try to parse a complete message from the plugin's buffer.
 *
 * Internally calls the handler if it was able to fully parse a JSON message,
 * and returns true in that case.
 */
static bool plugin_read_json_one(struct plugin *plugin, bool *destroyed)
{
	bool valid;
	const jsmntok_t *toks, *jrtok, *idtok;
	struct plugin_destroyed *pd;

	*destroyed = false;
	/* Note that in the case of 'plugin stop' this can free request (since
	 * plugin is parent), so detect that case */

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

	pd = plugin_detect_destruction(plugin);
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

	/* Corner case: rpc_command hook can destroy plugin for 'plugin
	 * stop'! */
	if (was_plugin_destroyed(pd)) {
		*destroyed = true;
	} else {
		/* Move this object out of the buffer */
		memmove(plugin->buffer, plugin->buffer + toks[0].end,
			tal_count(plugin->buffer) - toks[0].end);
		plugin->used -= toks[0].end;
		tal_free(toks);
	}
	return true;
}

static struct io_plan *plugin_read_json(struct io_conn *conn,
					struct plugin *plugin)
{
	bool success;

	log_io(plugin->log, LOG_IO_IN, NULL, "",
	       plugin->buffer + plugin->used, plugin->len_read);

	plugin->used += plugin->len_read;
	if (plugin->used == tal_count(plugin->buffer))
		tal_resize(&plugin->buffer, plugin->used * 2);

	/* Read and process all messages from the connection */
	do {
		bool destroyed;
		success = plugin_read_json_one(plugin, &destroyed);

		/* If it's destroyed, conn is already freed! */
		if (destroyed)
			return io_close(NULL);

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
	plugin->stdout_conn = NULL;
	tal_free(plugin);
}

struct io_plan *plugin_stdin_conn_init(struct io_conn *conn,
                                       struct plugin *plugin)
{
	/* We write to their stdin */
	/* We don't have anything queued yet, wait for notification */
	plugin->stdin_conn = tal_steal(plugin, conn);
	plugin->stdin_conn = conn;
	return io_wait(plugin->stdin_conn, plugin, plugin_write_json, plugin);
}

struct io_plan *plugin_stdout_conn_init(struct io_conn *conn,
                                        struct plugin *plugin)
{
	/* We read from their stdout */
	plugin->stdout_conn = conn;
	io_set_finish(conn, plugin_conn_finish, plugin);
	return io_read_partial(plugin->stdout_conn, plugin->buffer,
			       tal_bytelen(plugin->buffer), &plugin->len_read,
			       plugin_read_json, plugin);
}

char *plugin_opt_flag_set(struct plugin_opt *popt)
{
	/* A set flag is a true */
	*popt->value->as_bool = true;
	return NULL;
}

char *plugin_opt_set(const char *arg, struct plugin_opt *popt)
{
	char *endp;
	long long l;

	tal_free(popt->value->as_str);

	popt->value->as_str = tal_strdup(popt, arg);
	if (streq(popt->type, "int")) {
		errno = 0;
		l = strtoll(arg, &endp, 0);
		if (errno || *endp)
			return tal_fmt(tmpctx, "%s does not parse as type %s",
				       popt->value->as_str, popt->type);
		*popt->value->as_int = l;

		/* Check if the number did not fit in `s64` (in case `long long`
		 * is a bigger type). */
		if (*popt->value->as_int != l)
			return tal_fmt(tmpctx, "%s does not parse as type %s (overflowed)",
				       popt->value->as_str, popt->type);
	} else if (streq(popt->type, "bool")) {
		/* valid values are 'true', 'True', '1', '0', 'false', 'False', or '' */
		if (streq(arg, "true") || streq(arg, "True") || streq(arg, "1")) {
			*popt->value->as_bool = true;
		} else if (streq(arg, "false") || streq(arg, "False")
				|| streq(arg, "0")) {
			*popt->value->as_bool = false;
		} else
			return tal_fmt(tmpctx, "%s does not parse as type %s",
				       popt->value->as_str, popt->type);
	}

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

	popt = tal(plugin, struct plugin_opt);
	popt->value = talz(popt, struct plugin_opt_value);

	popt->name = tal_fmt(popt, "--%.*s", nametok->end - nametok->start,
			     buffer + nametok->start);
	if (json_tok_streq(buffer, typetok, "string")) {
		popt->type = "string";
		if (defaulttok) {
			popt->value->as_str = json_strdup(popt, buffer, defaulttok);
			popt->description = tal_fmt(
					popt, "%.*s (default: %s)", desctok->end - desctok->start,
					buffer + desctok->start, popt->value->as_str);
		}
	} else if (json_tok_streq(buffer, typetok, "int")) {
		popt->type = "int";
		popt->value->as_int = talz(popt->value, s64);
		if (defaulttok) {
			json_to_s64(buffer, defaulttok, popt->value->as_int);
			popt->value->as_str = tal_fmt(popt->value, "%"PRIu64, *popt->value->as_int);
			popt->description = tal_fmt(
					popt, "%.*s (default: %"PRIu64")", desctok->end - desctok->start,
					buffer + desctok->start, *popt->value->as_int);
		}
	} else if (json_tok_streq(buffer, typetok, "bool")) {
		popt->type = "bool";
		popt->value->as_bool = talz(popt->value, bool);
		if (defaulttok) {
			json_to_bool(buffer, defaulttok, popt->value->as_bool);
			popt->value->as_str = tal_fmt(popt->value, *popt->value->as_bool ? "true" : "false");
			popt->description = tal_fmt(
					popt, "%.*s (default: %s)", desctok->end - desctok->start,
					buffer + desctok->start, *popt->value->as_bool ? "true" : "false");
		}
	} else if (json_tok_streq(buffer, typetok, "flag")) {
		popt->type = "flag";
		popt->value->as_bool = talz(popt->value, bool);
		popt->description = json_strdup(popt, buffer, desctok);
		/* We default flags to false, the default token is ignored */
		*popt->value->as_bool = false;

	} else {
		plugin_kill(plugin, "Only \"string\", \"int\", \"bool\", and \"flag\" options are supported");
		return false;
	}
	if (!defaulttok)
		popt->description = json_strdup(popt, buffer, desctok);
	list_add_tail(&plugin->plugin_opts, &popt->list);

	if (streq(popt->type, "flag"))
		opt_register_noarg(popt->name, plugin_opt_flag_set, popt,
				   popt->description);

	else
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
	json_stream_append(stream, buffer + toks->start,
			   idtok->start - toks->start - offset);

	json_stream_append(stream, new_id, strlen(new_id));
	json_stream_append(stream, buffer + idtok->end + offset,
			   toks->end - idtok->end - offset);

	/* We promise it will end in '\n\n' */
	/* It's an object (with an id!): definitely can't be less that "{}" */
	assert(toks->end - toks->start >= 2);
	if (buffer[toks->end-1] != '\n')
		json_stream_append(stream, "\n\n", 2);
	else if (buffer[toks->end-2] != '\n')
		json_stream_append(stream, "\n", 1);
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

struct plugin *find_plugin_for_command(struct lightningd *ld,
				       const char *cmd_name)
{
	struct plugins *plugins = ld->plugins;
	struct plugin *plugin;

	/* Find the plugin that registered this RPC call */
	list_for_each(&plugins->plugins, plugin, list) {
		for (size_t i=0; i<tal_count(plugin->methods); i++) {
			if (streq(cmd_name, plugin->methods[i]))
				return plugin;
		}
	}

	return NULL;
}

static struct command_result *plugin_rpcmethod_dispatch(struct command *cmd,
							const char *buffer,
							const jsmntok_t *toks,
							const jsmntok_t *params UNNEEDED)
{
	const jsmntok_t *idtok;
	struct plugin *plugin;
	struct jsonrpc_request *req;
	char id[STR_MAX_CHARS(u64)];

	if (cmd->mode == CMD_CHECK)
		return command_param_failed();

	plugin = find_plugin_for_command(cmd->ld, cmd->json_cmd->name);
	if (!plugin)
		fatal("No plugin for %s ?", cmd->json_cmd->name);

	/* Find ID again (We've parsed them before, this should not fail!) */
	idtok = json_get_member(buffer, toks, "id");
	assert(idtok != NULL);

	req = jsonrpc_request_start(plugin, NULL, plugin->log,
				    plugin_rpcmethod_cb, cmd);
	snprintf(id, ARRAY_SIZE(id), "%"PRIu64, req->id);

	json_stream_forward_change_id(req->stream, buffer, toks, idtok, id);
	plugin_request_send(plugin, req);
	req->stream = NULL;

	return command_still_pending(cmd);
}

static bool plugin_rpcmethod_add(struct plugin *plugin,
				 const char *buffer,
				 const jsmntok_t *meth)
{
	const jsmntok_t *nametok, *categorytok, *desctok, *longdesctok, *usagetok;
	struct json_command *cmd;
	const char *usage;

	nametok = json_get_member(buffer, meth, "name");
	categorytok = json_get_member(buffer, meth, "category");
	desctok = json_get_member(buffer, meth, "description");
	longdesctok = json_get_member(buffer, meth, "long_description");
	usagetok = json_get_member(buffer, meth, "usage");

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

	if (usagetok && usagetok->type != JSMN_STRING) {
		plugin_kill(plugin,
			    "\"usage\" is not a string: %.*s",
			    meth->end - meth->start, buffer + meth->start);
		return false;
	}

	cmd = notleak(tal(plugin, struct json_command));
	cmd->name = json_strdup(cmd, buffer, nametok);
	if (categorytok)
        cmd->category = json_strdup(cmd, buffer, categorytok);
	else
		cmd->category = "plugin";
	cmd->description = json_strdup(cmd, buffer, desctok);
	if (longdesctok)
		cmd->verbose = json_strdup(cmd, buffer, longdesctok);
	else
		cmd->verbose = cmd->description;
	if (usagetok)
		usage = json_strdup(tmpctx, buffer, usagetok);
	else if (!deprecated_apis) {
		plugin_kill(plugin,
			    "\"usage\" not provided by plugin");
		return false;
	} else
		usage = "[params]";

	cmd->deprecated = false;
	cmd->dispatch = plugin_rpcmethod_dispatch;
	if (!jsonrpc_command_add(plugin->plugins->ld->jsonrpc, cmd, usage)) {
		log_broken(plugin->log,
			   "Could not register method \"%s\", a method with "
			   "that name is already registered",
			   cmd->name);
		return false;
	}
	tal_arr_expand(&plugin->methods, cmd->name);
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

		tal_arr_expand(&plugin->subscriptions, topic);
	}
	return true;
}

static bool plugin_hooks_add(struct plugin *plugin, const char *buffer,
			     const jsmntok_t *resulttok)
{
	const jsmntok_t *hookstok = json_get_member(buffer, resulttok, "hooks");
	if (!hookstok)
		return true;

	for (int i = 0; i < hookstok->size; i++) {
		char *name = json_strdup(NULL, plugin->buffer,
					 json_get_arr(hookstok, i));
		if (!plugin_hook_register(plugin, name)) {
			plugin_kill(plugin,
				    "could not register hook '%s', either the "
				    "name doesn't exist or another plugin "
				    "already registered it.",
				    name);
			tal_free(name);
			return false;
		}
		tal_free(name);
	}
	return true;
}

static void plugin_manifest_timeout(struct plugin *plugin)
{
	log_broken(plugin->log, "The plugin failed to respond to \"getmanifest\" in time, terminating.");
	fatal("Can't recover from plugin failure, terminating.");
}

/* List of JSON keys matching `enum feature_place`. */
static const char *plugin_feature_place_names[] = {"init", NULL, "node", "channel", "invoice"};

bool plugin_parse_getmanifest_response(const char *buffer,
                                       const jsmntok_t *toks,
                                       const jsmntok_t *idtok,
                                       struct plugin *plugin)
{
	const jsmntok_t *resulttok, *dynamictok, *featurestok, *tok;

	resulttok = json_get_member(buffer, toks, "result");
	if (!resulttok || resulttok->type != JSMN_OBJECT)
		return false;

	dynamictok = json_get_member(buffer, resulttok, "dynamic");
	if (dynamictok && !json_to_bool(buffer, dynamictok, &plugin->dynamic))
		plugin_kill(plugin, "Bad 'dynamic' field ('%.*s')",
			    json_tok_full_len(dynamictok),
			    json_tok_full(buffer, dynamictok));

	featurestok = json_get_member(buffer, resulttok, "featurebits");

	if (featurestok) {
		bool have_featurebits = false;
		struct feature_set *fset = talz(tmpctx, struct feature_set);

		BUILD_ASSERT(ARRAY_SIZE(plugin_feature_place_names)
			     == ARRAY_SIZE(fset->bits));

		for (int i = 0; i < ARRAY_SIZE(fset->bits); i++) {
			/* We don't allow setting the obs global init */
			if (!plugin_feature_place_names[i])
				continue;

			tok = json_get_member(buffer, featurestok,
					      plugin_feature_place_names[i]);

			if (!tok)
				continue;

			fset->bits[i] = json_tok_bin_from_hex(fset, buffer, tok);
			have_featurebits |= tal_bytelen(fset->bits[i]) > 0;

			if (!fset->bits[i]) {
				plugin_kill(
				    plugin,
				    "Featurebits returned by plugin is not a "
				    "valid hexadecimal string: %.*s",
				    tok->end - tok->start, buffer + tok->start);
				return true;
			}
		}

		if (plugin->dynamic && have_featurebits) {
			plugin_kill(plugin,
				    "Custom featurebits only allows for non-dynamic "
				    "plugins: dynamic=%d, featurebits=%.*s",
				    plugin->dynamic,
				    featurestok->end - featurestok->start,
				    buffer + featurestok->start);
			return true;
		}

		if (!feature_set_or(plugin->plugins->ld->feature_set, fset)) {
			plugin_kill(plugin,
				    "Custom featurebits already present");
			return true;
		}
	}

	if (!plugin_opts_add(plugin, buffer, resulttok) ||
	    !plugin_rpcmethods_add(plugin, buffer, resulttok) ||
	    !plugin_subscriptions_add(plugin, buffer, resulttok) ||
	    !plugin_hooks_add(plugin, buffer, resulttok))
		return false;

	return true;
}

/**
 * Callback for the plugin_manifest request.
 */
static void plugin_manifest_cb(const char *buffer,
			       const jsmntok_t *toks,
			       const jsmntok_t *idtok,
			       struct plugin *plugin)
{
	/* Check if all plugins have replied to getmanifest, and break
	 * if they have */
	plugin->plugins->pending_manifests--;
	if (plugin->plugins->pending_manifests == 0)
		io_break(plugin->plugins);

	if (!plugin_parse_getmanifest_response(buffer, toks, idtok, plugin))
		plugin_kill(plugin, "%s: Bad response to getmanifest.", plugin->cmd);

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

	/* Someone actually runs this on NTFS, where everything apparently is
	 * executable!  This prevents the most obvious damage. */
	if (streq(basename, "README.md"))
		return tal_free(fullname);

	return fullname;
}

char *add_plugin_dir(struct plugins *plugins, const char *dir, bool error_ok)
{
	struct dirent *di;
	DIR *d = opendir(dir);
	struct plugin *p;

	if (!d) {
		if (deprecated_apis && !path_is_abs(dir)) {
			dir = path_join(tmpctx,
					plugins->ld->original_directory, dir);
			d = opendir(dir);
			if (d) {
				log_unusual(plugins->log, "DEPRECATED WARNING:"
					    " plugin-dir is now relative to"
					    " lightning-dir, please change to"
					    " plugin-dir=%s",
					    dir);
			}
		}
		if (!d) {
			if (!error_ok && errno == ENOENT)
				return NULL;
			return tal_fmt(NULL, "Failed to open plugin-dir %s: %s",
				       dir, strerror(errno));
		}
	}

	while ((di = readdir(d)) != NULL) {
		const char *fullpath;

		if (streq(di->d_name, ".") || streq(di->d_name, ".."))
			continue;
		fullpath = plugin_fullpath(tmpctx, dir, di->d_name);
		if (fullpath) {
			p = plugin_register(plugins, fullpath);
			if (!p && !error_ok)
				return tal_fmt(NULL, "Failed to register %s: %s",
				               fullpath, strerror(errno));
		}
	}
	closedir(d);
	return NULL;
}

void clear_plugins(struct plugins *plugins)
{
	struct plugin *p;

	log_info(plugins->log, "clear-plugins removing all plugins");
	while ((p = list_pop(&plugins->plugins, struct plugin, list)) != NULL)
		tal_free(p);
}

void plugins_add_default_dir(struct plugins *plugins)
{
	DIR *d = opendir(plugins->default_dir);
	if (d) {
		struct dirent *di;

		/* Add this directory itself, and recurse down once. */
		add_plugin_dir(plugins, plugins->default_dir, true);
		while ((di = readdir(d)) != NULL) {
			if (streq(di->d_name, ".") || streq(di->d_name, ".."))
				continue;
			add_plugin_dir(plugins, path_join(tmpctx, plugins->default_dir,
			                                  di->d_name), true);
		}
		closedir(d);
	}
}

void plugins_init(struct plugins *plugins, const char *dev_plugin_debug)
{
	struct plugin *p;
	char **cmd;
	int stdin, stdout;
	struct jsonrpc_request *req;

	plugins->pending_manifests = 0;
	plugins->default_dir = path_join(plugins, plugins->ld->config_basedir, "plugins");
	plugins_add_default_dir(plugins);

	setenv("LIGHTNINGD_PLUGIN", "1", 1);
	setenv("LIGHTNINGD_VERSION", version(), 1);
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
		else
			log_debug(plugins->log, "started(%u) %s", p->pid, p->cmd);
		p->buffer = tal_arr(p, char, 64);
		p->stop = false;

		/* Create two connections, one read-only on top of p->stdout, and one
		 * write-only on p->stdin */
		io_new_conn(p, stdout, plugin_stdout_conn_init, p);
		io_new_conn(p, stdin, plugin_stdin_conn_init, p);
		req = jsonrpc_request_start(p, "getmanifest", p->log,
					    plugin_manifest_cb, p);
		jsonrpc_request_end(req);
		plugin_request_send(p, req);

		plugins->pending_manifests++;
		/* Don't timeout if they're running a debugger. */
		if (debug)
			p->timeout_timer = NULL;
		else {
			p->timeout_timer
				= new_reltimer(plugins->ld->timers, p,
					       time_from_sec(PLUGIN_MANIFEST_TIMEOUT),
					       plugin_manifest_timeout, p);
		}
		tal_free(cmd);
	}

	if (plugins->pending_manifests > 0)
		io_loop_with_timers(plugins->ld);
}

static void plugin_config_cb(const char *buffer,
			     const jsmntok_t *toks,
			     const jsmntok_t *idtok,
			     struct plugin *plugin)
{
	plugin->plugin_state = CONFIGURED;
}

void
plugin_populate_init_request(struct plugin *plugin, struct jsonrpc_request *req)
{
	const char *name;
	struct plugin_opt *opt;
	struct lightningd *ld = plugin->plugins->ld;

	/* Add .params.options */
	json_object_start(req->stream, "options");
	list_for_each(&plugin->plugin_opts, opt, list) {
		/* Trim the `--` that we added before */
		name = opt->name + 2;
		if (opt->value->as_bool) {
			/* We don't include 'flag' types if they're not
			 * flagged on */
			if (streq(opt->type, "flag") && !*opt->value->as_bool)
				continue;

			json_add_bool(req->stream, name, *opt->value->as_bool);
			if (!deprecated_apis)
				continue;
		}
		if (opt->value->as_int) {
			json_add_s64(req->stream, name, *opt->value->as_int);
			if (!deprecated_apis)
				continue;
		}
		if (opt->value->as_str) {
			json_add_string(req->stream, name, opt->value->as_str);
		}
	}
	json_object_end(req->stream); /* end of .params.options */

	/* Add .params.configuration */
	json_object_start(req->stream, "configuration");
	json_add_string(req->stream, "lightning-dir", ld->config_netdir);
	json_add_string(req->stream, "rpc-file", ld->rpc_filename);
	json_add_bool(req->stream, "startup", plugin->plugins->startup);
	json_add_string(req->stream, "network", chainparams->network_name);
	json_object_start(req->stream, "feature_set");
	for (enum feature_place fp = 0; fp < NUM_FEATURE_PLACE; fp++) {
		if (plugin_feature_place_names[fp]) {
			json_add_hex_talarr(req->stream,
					    plugin_feature_place_names[fp],
					    ld->feature_set->bits[fp]);
		}
	}
	json_object_end(req->stream);
	json_object_end(req->stream);
}

/* FIXME(cdecker) This just builds a string for the request because
 * the json_stream is tightly bound to the command interface. It
 * should probably be generalized and fixed up. */
static void
plugin_config(struct plugin *plugin)
{
	struct jsonrpc_request *req;

	req = jsonrpc_request_start(plugin, "init", plugin->log,
	                            plugin_config_cb, plugin);
	plugin_populate_init_request(plugin, req);
	jsonrpc_request_end(req);
	plugin_request_send(plugin, req);
}

void plugins_config(struct plugins *plugins)
{
	struct plugin *p;
	list_for_each(&plugins->plugins, p, list) {
		if (p->plugin_state == UNCONFIGURED)
			plugin_config(p);
	}

	plugins->startup = false;
}

void json_add_opt_plugins(struct json_stream *response,
			  const struct plugins *plugins)
{
	struct plugin *p;
	struct plugin_opt *opt;
	const char *plugin_name;
	const char *opt_name;

	/* DEPRECATED: duplicated JSON "plugin" entries */
	if (deprecated_apis) {
		list_for_each(&plugins->plugins, p, list) {
			json_add_string(response, "plugin", p->cmd);
		}
	}

	/* we output 'plugins' and their options as an array of substructures */
	json_array_start(response, "plugins");
	list_for_each(&plugins->plugins, p, list) {
		json_object_start(response, NULL);
		json_add_string(response, "path", p->cmd);

		/* FIXME: use executables basename until plugins can define their names */
		plugin_name = path_basename(NULL, p->cmd);
		json_add_string(response, "name", plugin_name);
		tal_free(plugin_name);

		if (!list_empty(&p->plugin_opts)) {
			json_object_start(response, "options");
			list_for_each(&p->plugin_opts, opt, list) {
				/* Trim the `--` that we added before */
				opt_name = opt->name + 2;
				if (opt->value->as_bool) {
					json_add_bool(response, opt_name, opt->value->as_bool);
				} else if (opt->value->as_int) {
					json_add_s64(response, opt_name, *opt->value->as_int);
				} else if (opt->value->as_str) {
					json_add_string(response, opt_name, opt->value->as_str);
				} else {
					json_add_null(response, opt_name);
				}
			}
			json_object_end(response);
		}
		json_object_end(response);
	}
	json_array_end(response);
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

	/* If we're shutting down, ld->plugins will be NULL */
	if (plugins) {
		list_for_each(&plugins->plugins, p, list) {
			if (plugin_subscriptions_contains(p, n->method))
				plugin_send(p, json_stream_dup(p, n->stream,
							       p->log));
		}
	}
	if (taken(n))
		tal_free(n);
}

static void destroy_request(struct jsonrpc_request *req,
                            struct plugin *plugin)
{
	uintmap_del(&plugin->plugins->pending_requests, req->id);
}

void plugin_request_send(struct plugin *plugin,
			 struct jsonrpc_request *req TAKES)
{
	/* Add to map so we can find it later when routing the response */
	tal_steal(plugin, req);
	uintmap_add(&plugin->plugins->pending_requests, req->id, req);
	/* Add destructor in case plugin dies. */
	tal_add_destructor2(req, destroy_request, plugin);
	plugin_send(plugin, req->stream);
	/* plugin_send steals the stream, so remove the dangling
	 * pointer here */
	req->stream = NULL;
}

void *plugin_exclusive_loop(struct plugin *plugin)
{
	void *ret;

	io_conn_out_exclusive(plugin->stdin_conn, true);
	io_conn_exclusive(plugin->stdout_conn, true);

	/* We don't service timers here, either! */
	ret = io_loop(NULL, NULL);

	io_conn_out_exclusive(plugin->stdin_conn, false);
	if (io_conn_exclusive(plugin->stdout_conn, false))
		fatal("Still io_exclusive after removing plugin %s?",
		      plugin->cmd);

	return ret;
}

struct log *plugin_get_log(struct plugin *plugin)
{
	return plugin->log;
}

struct plugin_destroyed {
	const struct plugin *plugin;
};

static void mark_plugin_destroyed(const struct plugin *unused,
				  struct plugin_destroyed *pd)
{
	pd->plugin = NULL;
}

struct plugin_destroyed *plugin_detect_destruction(const struct plugin *plugin)
{
	struct plugin_destroyed *pd = tal(NULL, struct plugin_destroyed);
	pd->plugin = plugin;
	tal_add_destructor2(plugin, mark_plugin_destroyed, pd);
	return pd;
}

bool was_plugin_destroyed(struct plugin_destroyed *pd)
{
	if (pd->plugin) {
		tal_del_destructor2(pd->plugin, mark_plugin_destroyed, pd);
		tal_free(pd);
		return false;
	}
	tal_free(pd);
	return true;
}
