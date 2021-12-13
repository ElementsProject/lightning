#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/ccan/tal/grab_file/grab_file.h>
#include <ccan/crc32c/crc32c.h>
#include <ccan/io/io.h>
#include <ccan/mem/mem.h>
#include <ccan/opt/opt.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <ccan/utf8/utf8.h>
#include <common/configdir.h>
#include <common/features.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <common/version.h>
#include <dirent.h>
#include <errno.h>
#include <lightningd/io_loop_with_timers.h>
#include <lightningd/notification.h>
#include <lightningd/plugin.h>
#include <lightningd/plugin_control.h>
#include <lightningd/plugin_hook.h>
#include <sys/stat.h>

/* Only this file can include this generated header! */
# include <plugins/list_of_builtin_plugins_gen.h>

/* How many seconds may the plugin take to reply to the `getmanifest`
 * call? This is the maximum delay to `lightningd --help` and until
 * we can start the main `io_loop` to communicate with peers. If this
 * hangs we can't do much, so we put an upper bound on the time we're
 * willing to wait. Plugins shouldn't do any initialization in the
 * `getmanifest` call anyway, that's what `init` is for. */
#define PLUGIN_MANIFEST_TIMEOUT 60

/* A simple struct associating an incoming RPC method call with the plugin
 * that is handling it and the downstream jsonrpc_request. */
struct plugin_rpccall {
	struct list_node list;
	struct command *cmd;
	struct plugin *plugin;
	struct jsonrpc_request *request;
};

#if DEVELOPER
static void memleak_help_pending_requests(struct htable *memtable,
					  struct plugins *plugins)
{
	memleak_remove_uintmap(memtable, &plugins->pending_requests);
}
#endif /* DEVELOPER */

static const char *state_desc(const struct plugin *plugin)
{
	switch (plugin->plugin_state) {
	case UNCONFIGURED:
		return "unconfigured";
	case AWAITING_GETMANIFEST_RESPONSE:
		return "before replying to getmanifest";
	case NEEDS_INIT:
		return "before we sent init";
	case AWAITING_INIT_RESPONSE:
		return "before replying to init";
	case INIT_COMPLETE:
		return "during normal operation";
	}
	fatal("Invalid plugin state %i for %s",
	      plugin->plugin_state, plugin->cmd);
}

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
	p->plugin_cmds = tal_arr(p, struct plugin_command *, 0);
	p->blacklist = tal_arr(p, const char *, 0);
	p->plugin_idx = 0;
#if DEVELOPER
	p->dev_builtin_plugins_unimportant = false;
#endif /* DEVELOPER */
	uintmap_init(&p->pending_requests);
	memleak_add_helper(p, memleak_help_pending_requests);

	return p;
}

/* Check that all the plugin's subscriptions are actually for known
 * notification topics. Emit a warning if that's not the case, but
 * don't kill the plugin. */
static void plugin_check_subscriptions(struct plugins *plugins,
				       struct plugin *plugin)
{
	for (size_t i = 0; i < tal_count(plugin->subscriptions); i++) {
		const char *topic = plugin->subscriptions[i];
		if (!notifications_have_topic(plugins, topic))
			log_unusual(
			    plugin->log,
			    "topic '%s' is not a known notification topic",
			    topic);
	}
}

static bool plugins_any_in_state(const struct plugins *plugins,
				 enum plugin_state state)
{
	const struct plugin *p;

	list_for_each(&plugins->plugins, p, list) {
		if (p->plugin_state == state)
			return true;
	}
	return false;
}

static bool plugins_all_in_state(const struct plugins *plugins,
				 enum plugin_state state)
{
	const struct plugin *p;

	list_for_each(&plugins->plugins, p, list) {
		if (p->plugin_state != state)
			return false;
	}
	return true;
}

/* Once they've all replied with their manifests, we can order them. */
static void check_plugins_manifests(struct plugins *plugins)
{
	struct plugin *plugin;
	struct plugin **depfail;

	if (plugins_any_in_state(plugins, AWAITING_GETMANIFEST_RESPONSE))
		return;

	/* Now things are settled, try to order hooks. */
	depfail = plugin_hooks_make_ordered(tmpctx);
	for (size_t i = 0; i < tal_count(depfail); i++) {
		/* Only complain and free plugins! */
		if (depfail[i]->plugin_state != NEEDS_INIT)
			continue;
		plugin_kill(depfail[i], LOG_UNUSUAL,
			    "Cannot meet required hook dependencies");
	}

	/* Check that all the subscriptions are matched with real
	 * topics. */
	list_for_each(&plugins->plugins, plugin, list) {
		plugin_check_subscriptions(plugin->plugins, plugin);
	}

	/* As startup, we break out once all getmanifest are returned */
	if (plugins->startup)
		io_break(plugins);
	else
		/* Otherwise we go straight into configuring them */
		plugins_config(plugins);
}

static void check_plugins_initted(struct plugins *plugins)
{
	struct plugin_command **plugin_cmds;

	if (!plugins_all_in_state(plugins, INIT_COMPLETE))
		return;

	/* Clear commands first, in case callbacks add new ones.
	 * Paranoia, but wouldn't that be a nasty bug to find? */
	plugin_cmds = plugins->plugin_cmds;
	plugins->plugin_cmds = tal_arr(plugins, struct plugin_command *, 0);
	for (size_t i = 0; i < tal_count(plugin_cmds); i++)
		plugin_cmd_all_complete(plugins, plugin_cmds[i]);
	tal_free(plugin_cmds);
}

struct command_result *plugin_register_all_complete(struct lightningd *ld,
						    struct plugin_command *pcmd)
{
	if (plugins_all_in_state(ld->plugins, INIT_COMPLETE))
		return plugin_cmd_all_complete(ld->plugins, pcmd);

	tal_arr_expand(&ld->plugins->plugin_cmds, pcmd);
	return NULL;
}

static void destroy_plugin(struct plugin *p)
{
	struct plugin_rpccall *call;

	list_del(&p->list);

	/* Terminate all pending RPC calls with an error. */
	list_for_each(&p->pending_rpccalls, call, list) {
		was_pending(command_fail(
		    call->cmd, PLUGIN_TERMINATED,
		    "Plugin terminated before replying to RPC call."));
	}
	/* Reset, so calls below don't try to fail it again! */
	list_head_init(&p->pending_rpccalls);

	/* If this was last one manifests were waiting for, handle deps */
	if (p->plugin_state == AWAITING_GETMANIFEST_RESPONSE)
		check_plugins_manifests(p->plugins);

	/* Daemon shutdown overrules plugin's importance; aborts init checks */
	if (p->plugins->ld->state == LD_STATE_SHUTDOWN) {
		/* But return if this was the last plugin! */
		if (list_empty(&p->plugins->plugins))
			io_break(destroy_plugin);
		return;
	}

	/* If this was the last one init was waiting for, handle cmd replies */
	if (p->plugin_state == AWAITING_INIT_RESPONSE)
		check_plugins_initted(p->plugins);

	/* Now check if the dying plugin is important.  */
	if (p->important) {
		log_broken(p->log,
			   "Plugin marked as important, "
			   "shutting down lightningd!");
		lightningd_exit(p->plugins->ld, 1);
	}
}

static u32 file_checksum(struct lightningd *ld, const char *path)
{
	char *content;

	if (IFDEV(ld->dev_no_plugin_checksum, false))
		return 0;

	content = grab_file(tmpctx, path);
	if (content == NULL) return 0;
	return crc32c(0, content, tal_count(content));
}

struct plugin *plugin_register(struct plugins *plugins, const char* path TAKES,
			       struct plugin_command *start_cmd, bool important,
			       const char *parambuf STEALS,
			       const jsmntok_t *params STEALS)
{
	struct plugin *p, *p_temp;
	u32 chksum;

	/* Don't register an already registered plugin */
	list_for_each(&plugins->plugins, p_temp, list) {
		if (streq(path, p_temp->cmd)) {
			/* If added as "important", upgrade to "important".  */
			if (important)
				p_temp->important = true;
			/* stop and restart plugin on different checksum */
			chksum = file_checksum(plugins->ld, path);
			if (p_temp->checksum != chksum && !p_temp->important) {
				plugin_kill(p_temp, LOG_INFORM,
					    "Plugin changed, needs restart.");
				break;
			}
			if (taken(path))
				tal_free(path);
			return NULL;
		}
	}

	p = tal(plugins, struct plugin);
	p->plugins = plugins;
	p->cmd = tal_strdup(p, path);
	p->checksum = file_checksum(plugins->ld, p->cmd);
	p->shortname = path_basename(p, p->cmd);
	p->start_cmd = start_cmd;

	p->plugin_state = UNCONFIGURED;
	p->js_arr = tal_arr(p, struct json_stream *, 0);
	p->used = 0;
	p->notification_topics = tal_arr(p, const char *, 0);
	p->subscriptions = NULL;
	p->dynamic = false;
	p->index = plugins->plugin_idx++;

	p->log = new_log(p, plugins->log_book, NULL, "plugin-%s", p->shortname);
	p->methods = tal_arr(p, const char *, 0);
	list_head_init(&p->plugin_opts);

	list_add_tail(&plugins->plugins, &p->list);
	tal_add_destructor(p, destroy_plugin);
	list_head_init(&p->pending_rpccalls);

	p->important = important;
	p->parambuf = tal_steal(p, parambuf);
	p->params = tal_steal(p, params);
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

void plugin_blacklist(struct plugins *plugins, const char *name)
{
	struct plugin *p, *next;

	log_debug(plugins->log, "blacklist for %s", name);
	list_for_each_safe(&plugins->plugins, p, next, list) {
		if (plugin_paths_match(p->cmd, name)) {
			log_info(plugins->log, "%s: disabled via disable-plugin",
				 p->cmd);
			list_del_from(&plugins->plugins, &p->list);
			/* disable-plugin overrides important-plugin.  */
			p->important = false;
			tal_free(p);
		}
	}

	tal_arr_expand(&plugins->blacklist,
		       tal_strdup(plugins->blacklist, name));
}

bool plugin_blacklisted(struct plugins *plugins, const char *name)
{
	for (size_t i = 0; i < tal_count(plugins->blacklist); i++)
		if (plugin_paths_match(name, plugins->blacklist[i]))
			return true;

	return false;
}

void plugin_kill(struct plugin *plugin, enum log_level loglevel,
		 const char *fmt, ...)
{
	va_list ap;
	const char *msg;

	va_start(ap, fmt);
	msg = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	log_(plugin->log, loglevel,
	     NULL, loglevel >= LOG_UNUSUAL,
	     "Killing plugin: %s", msg);
	kill(plugin->pid, SIGKILL);
	if (plugin->start_cmd) {
		plugin_cmd_killed(plugin->start_cmd, plugin, msg);
		plugin->start_cmd = NULL;
	}

	/* Don't come back when we free stdout_conn! */
	io_set_finish(plugin->stdout_conn, NULL, NULL);
	tal_free(plugin);
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

/* Returns the error string, or NULL */
static const char *plugin_log_handle(struct plugin *plugin,
				     const jsmntok_t *paramstok)
	WARN_UNUSED_RESULT;
static const char *plugin_log_handle(struct plugin *plugin,
				     const jsmntok_t *paramstok)
{
	const jsmntok_t *msgtok, *leveltok;
	enum log_level level;
	bool call_notifier;
	msgtok = json_get_member(plugin->buffer, paramstok, "message");
	leveltok = json_get_member(plugin->buffer, paramstok, "level");

	if (!msgtok || msgtok->type != JSMN_STRING) {
		return tal_fmt(plugin, "Log notification from plugin doesn't have "
			       "a string \"message\" field");
	}

	if (!leveltok)
		level = LOG_INFORM;
	else if (!log_level_parse(plugin->buffer + leveltok->start,
				  leveltok->end - leveltok->start,
				  &level)
		 /* FIXME: Allow io logging? */
		 || level == LOG_IO_IN
		 || level == LOG_IO_OUT) {
		return tal_fmt(plugin,
			       "Unknown log-level %.*s, valid values are "
			       "\"debug\", \"info\", \"warn\", or \"error\".",
			       json_tok_full_len(leveltok),
			       json_tok_full(plugin->buffer, leveltok));
	}

	call_notifier = (level == LOG_BROKEN || level == LOG_UNUSUAL)? true : false;
	/* FIXME: Let plugin specify node_id? */
	log_(plugin->log, level, NULL, call_notifier, "%.*s", msgtok->end - msgtok->start,
	     plugin->buffer + msgtok->start);
	return NULL;
}

static const char *plugin_notify_handle(struct plugin *plugin,
					const jsmntok_t *methodtok,
					const jsmntok_t *paramstok)
{
	const jsmntok_t *idtok;
	u64 id;
	struct jsonrpc_request *request;

	/* id inside params tells us which id to redirect to. */
	idtok = json_get_member(plugin->buffer, paramstok, "id");
	if (!idtok || !json_to_u64(plugin->buffer, idtok, &id)) {
		return tal_fmt(plugin,
			       "JSON-RPC notify \"id\"-field is not a u64");
	}

	request = uintmap_get(&plugin->plugins->pending_requests, id);
	if (!request) {
		return tal_fmt(
			plugin,
			"Received a JSON-RPC notify for non-existent request");
	}

	/* Ignore if they don't have a callback */
	if (request->notify_cb)
		request->notify_cb(plugin->buffer, methodtok, paramstok, idtok,
				   request->response_cb_arg);
	return NULL;
}

/* Check if the plugin is allowed to send a notification of the
 * specified topic, i.e., whether the plugin has announced the topic
 * correctly in its manifest. */
static bool plugin_notification_allowed(const struct plugin *plugin, const char *topic)
{
	for (size_t i=0; i<tal_count(plugin->notification_topics); i++)
		if (streq(plugin->notification_topics[i], topic))
			return true;

	return false;
}

/* Returns the error string, or NULL */
static const char *plugin_notification_handle(struct plugin *plugin,
					      const jsmntok_t *toks)
	WARN_UNUSED_RESULT;

static const char *plugin_notification_handle(struct plugin *plugin,
					      const jsmntok_t *toks)
{
	const jsmntok_t *methtok, *paramstok;
	const char *methname;
	struct jsonrpc_notification *n;
	methtok = json_get_member(plugin->buffer, toks, "method");
	paramstok = json_get_member(plugin->buffer, toks, "params");

	if (!methtok || !paramstok) {
		return tal_fmt(plugin,
			       "Malformed JSON-RPC notification missing "
			       "\"method\" or \"params\": %.*s",
			       toks->end - toks->start,
			       plugin->buffer + toks->start);
	}

	/* Dispatch incoming notifications. This is currently limited
	 * to just a few method types, should this ever become
	 * unwieldy we can switch to the AUTODATA construction to
	 * register notification handlers in a variety of places. */
	if (json_tok_streq(plugin->buffer, methtok, "log")) {
		return plugin_log_handle(plugin, paramstok);
	} else if (json_tok_streq(plugin->buffer, methtok, "message")
		   || json_tok_streq(plugin->buffer, methtok, "progress")) {
		return plugin_notify_handle(plugin, methtok, paramstok);
	}

	methname = json_strdup(tmpctx, plugin->buffer, methtok);

	if (!plugin_notification_allowed(plugin, methname)) {
		log_unusual(plugin->log,
			    "Plugin attempted to send a notification to topic "
			    "\"%s\" it hasn't declared in its manifest, not "
			    "forwarding to subscribers.",
			    methname);
	} else if (notifications_have_topic(plugin->plugins, methname)) {
		n = jsonrpc_notification_start(NULL, methname);
		json_add_string(n->stream, "origin", plugin->shortname);
		json_add_tok(n->stream, "payload", paramstok, plugin->buffer);
		jsonrpc_notification_end(n);

		plugins_notify(plugin->plugins, take(n));
	}
	return NULL;
}

struct plugin_destroyed {
	const struct plugin *plugin;
};

static void mark_plugin_destroyed(const struct plugin *unused,
				  struct plugin_destroyed *pd)
{
	pd->plugin = NULL;
}

static struct plugin_destroyed *
plugin_detect_destruction(const struct plugin *plugin)
{
	struct plugin_destroyed *pd = tal(NULL, struct plugin_destroyed);
	pd->plugin = plugin;
	tal_add_destructor2(plugin, mark_plugin_destroyed, pd);
	return pd;
}

static bool was_plugin_destroyed(struct plugin_destroyed *pd)
{
	if (pd->plugin) {
		tal_del_destructor2(pd->plugin, mark_plugin_destroyed, pd);
		tal_free(pd);
		return false;
	}
	tal_free(pd);
	return true;
}

/* Returns the error string, or NULL */
static const char *plugin_response_handle(struct plugin *plugin,
					  const jsmntok_t *toks,
					  const jsmntok_t *idtok)
	WARN_UNUSED_RESULT;

static const char *plugin_response_handle(struct plugin *plugin,
					  const jsmntok_t *toks,
					  const jsmntok_t *idtok)
{
	struct plugin_destroyed *pd;
	struct jsonrpc_request *request;
	u64 id;
	/* We only send u64 ids, so if this fails it's a critical error (note
	 * that this also works if id is inside a JSON string!). */
	if (!json_to_u64(plugin->buffer, idtok, &id)) {
		return tal_fmt(plugin,
			       "JSON-RPC response \"id\"-field is not a u64");
	}

	request = uintmap_get(&plugin->plugins->pending_requests, id);

	if (!request) {
		return tal_fmt(
			plugin,
			"Received a JSON-RPC response for non-existent request");
	}

	/* Ignore responses when shutting down */
	if (plugin->plugins->ld->state == LD_STATE_SHUTDOWN) {
		return NULL;
	}

	/* We expect the request->cb to copy if needed */
	pd = plugin_detect_destruction(plugin);
	request->response_cb(plugin->buffer, toks, idtok, request->response_cb_arg);

	/* Note that in the case of 'plugin stop' this can free request (since
	 * plugin is parent), so detect that case */
	if (!was_plugin_destroyed(pd))
		tal_free(request);

	return NULL;
}

/**
 * Try to parse a complete message from the plugin's buffer.
 *
 * Returns NULL if there was no error.
 * If it can parse a JSON message, sets *@complete, and returns any error
 * from the callback.
 *
 * If @destroyed was set, it means the plugin called plugin stop on itself.
 */
static const char *plugin_read_json_one(struct plugin *plugin,
					bool *complete,
					bool *destroyed)
{
	const jsmntok_t *jrtok, *idtok;
	struct plugin_destroyed *pd;
	const char *err;

	*destroyed = false;
	/* Note that in the case of 'plugin stop' this can free request (since
	 * plugin is parent), so detect that case */

	if (!json_parse_input(&plugin->parser, &plugin->toks,
			      plugin->buffer, plugin->used,
			      complete)) {
		return tal_fmt(plugin,
			       "Failed to parse JSON response '%.*s'",
			       (int)plugin->used, plugin->buffer);
	}

	if (!*complete) {
		/* We need more. */
		return NULL;
	}

	/* Empty buffer? (eg. just whitespace). */
	if (tal_count(plugin->toks) == 1) {
		plugin->used = 0;
		jsmn_init(&plugin->parser);
		toks_reset(plugin->toks);
		/* We need more. */
		*complete = false;
		return NULL;
	}

	jrtok = json_get_member(plugin->buffer, plugin->toks, "jsonrpc");
	idtok = json_get_member(plugin->buffer, plugin->toks, "id");

	if (!jrtok) {
		return tal_fmt(
		    plugin,
		    "JSON-RPC message does not contain \"jsonrpc\" field");
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
		err = plugin_notification_handle(plugin, plugin->toks);

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
		err = plugin_response_handle(plugin, plugin->toks, idtok);
	}

	/* Corner case: rpc_command hook can destroy plugin for 'plugin
	 * stop'! */
	if (was_plugin_destroyed(pd)) {
		*destroyed = true;
	} else {
		/* Move this object out of the buffer */
		memmove(plugin->buffer, plugin->buffer + plugin->toks[0].end,
			tal_count(plugin->buffer) - plugin->toks[0].end);
		plugin->used -= plugin->toks[0].end;
		jsmn_init(&plugin->parser);
		toks_reset(plugin->toks);
	}
	return err;
}

static struct io_plan *plugin_read_json(struct io_conn *conn,
					struct plugin *plugin)
{
	bool success;
	bool have_full;

	log_io(plugin->log, LOG_IO_IN, NULL, "",
	       plugin->buffer + plugin->used, plugin->len_read);

	/* Our JSON parser is pretty good at incremental parsing, but
	 * `getrawblock` gives a giant 2MB token, which forces it to re-parse
	 * every time until we have all of it. However, we can't complete a
	 * JSON object without a '}', so we do a cheaper check here.
	 */
	have_full = memchr(plugin->buffer + plugin->used, '}',
			   plugin->len_read);

	plugin->used += plugin->len_read;
	if (plugin->used == tal_count(plugin->buffer))
		tal_resize(&plugin->buffer, plugin->used * 2);

	/* Read and process all messages from the connection */
	if (have_full) {
		do {
			bool destroyed;
			const char *err;
			err =
			    plugin_read_json_one(plugin, &success, &destroyed);

			/* If it's destroyed, conn is already freed! */
			if (destroyed)
				return io_close(NULL);

			if (err) {
				plugin_kill(plugin, LOG_UNUSUAL,
					    "%s", err);
				/* plugin_kill frees plugin */
				return io_close(NULL);
			}
		} while (success);
	}

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
	}

	return io_out_wait(conn, plugin, plugin_write_json, plugin);
}

/* This catches the case where their stdout closes (usually they're dead). */
static void plugin_conn_finish(struct io_conn *conn, struct plugin *plugin)
{
	/* This is expected at shutdown of course. */
	plugin_kill(plugin,
		    plugin->plugins->ld->state == LD_STATE_SHUTDOWN
		    ? LOG_DBG : LOG_INFORM,
		    "exited %s", state_desc(plugin));
}

struct io_plan *plugin_stdin_conn_init(struct io_conn *conn,
                                       struct plugin *plugin)
{
	/* We write to their stdin */
	/* We don't have anything queued yet, wait for notification */
	return io_wait(conn, plugin, plugin_write_json, plugin);
}

struct io_plan *plugin_stdout_conn_init(struct io_conn *conn,
                                        struct plugin *plugin)
{
	/* We read from their stdout */
	io_set_finish(conn, plugin_conn_finish, plugin);
	return io_read_partial(conn, plugin->buffer,
			       tal_bytelen(plugin->buffer), &plugin->len_read,
			       plugin_read_json, plugin);
}


/* Returns NULL if invalid value for that type */
static struct plugin_opt_value *plugin_opt_value(const tal_t *ctx,
						 const char *type,
						 const char *arg)
{
	struct plugin_opt_value *v = tal(ctx, struct plugin_opt_value);

	v->as_str = tal_strdup(v, arg);
	if (streq(type, "int")) {
		long long l;
		char *endp;

		errno = 0;
		l = strtoll(arg, &endp, 0);
		if (errno || *endp)
			return tal_free(v);
		v->as_int = l;

		/* Check if the number did not fit in `s64` (in case `long long`
		 * is a bigger type). */
		if (v->as_int != l)
			return tal_free(v);
	} else if (streq(type, "bool")) {
		/* valid values are 'true', 'True', '1', '0', 'false', 'False', or '' */
		if (streq(arg, "true") || streq(arg, "True") || streq(arg, "1")) {
			v->as_bool = true;
		} else if (streq(arg, "false") || streq(arg, "False")
				|| streq(arg, "0")) {
			v->as_bool = false;
		} else
			return tal_free(v);
	} else if (streq(type, "flag")) {
		v->as_bool = true;
	}

	return v;
}

char *plugin_opt_flag_set(struct plugin_opt *popt)
{
	/* A set flag is a true */
	tal_free(popt->values);
	popt->values = tal_arr(popt, struct plugin_opt_value *, 1);
	popt->values[0] = plugin_opt_value(popt->values, popt->type, "true");
	return NULL;
}

char *plugin_opt_set(const char *arg, struct plugin_opt *popt)
{
	struct plugin_opt_value *v;

	/* Warn them that this is deprecated */
	if (popt->deprecated && !deprecated_apis)
		return tal_fmt(tmpctx, "deprecated option (will be removed!)");

	if (!popt->multi) {
		tal_free(popt->values);
		popt->values = tal_arr(popt, struct plugin_opt_value *, 0);
	}

	v = plugin_opt_value(popt->values, popt->type, arg);
	if (!v)
		return tal_fmt(tmpctx, "%s does not parse as type %s",
			       arg, popt->type);
	tal_arr_expand(&popt->values, v);

	return NULL;
}

static void destroy_plugin_opt(struct plugin_opt *opt)
{
	if (!opt_unregister(opt->name))
		fatal("Could not unregister %s", opt->name);
	list_del(&opt->list);
}

/* Add a single plugin option to the plugin as well as registering it with the
 * command line options. */
static const char *plugin_opt_add(struct plugin *plugin, const char *buffer,
				  const jsmntok_t *opt)
{
	const jsmntok_t *nametok, *typetok, *defaulttok, *desctok, *deptok, *multitok;
	struct plugin_opt *popt;
	nametok = json_get_member(buffer, opt, "name");
	typetok = json_get_member(buffer, opt, "type");
	desctok = json_get_member(buffer, opt, "description");
	defaulttok = json_get_member(buffer, opt, "default");
	deptok = json_get_member(buffer, opt, "deprecated");
	multitok = json_get_member(buffer, opt, "multi");

	if (!typetok || !nametok || !desctok) {
		return tal_fmt(plugin,
			    "An option is missing either \"name\", \"description\" or \"type\"");
	}

	popt = tal(plugin, struct plugin_opt);
	popt->values = tal_arr(popt, struct plugin_opt_value *, 0);

	popt->name = tal_fmt(popt, "--%.*s", nametok->end - nametok->start,
			     buffer + nametok->start);
	popt->description = NULL;
	if (deptok) {
		if (!json_to_bool(buffer, deptok, &popt->deprecated))
			return tal_fmt(plugin,
				       "%s: invalid \"deprecated\" field %.*s",
				       popt->name,
				       deptok->end - deptok->start,
				       buffer + deptok->start);
	} else
		popt->deprecated = false;

	if (multitok) {
		if (!json_to_bool(buffer, multitok, &popt->multi))
			return tal_fmt(plugin,
				       "%s: invalid \"multi\" field %.*s",
				       popt->name,
				       multitok->end - multitok->start,
				       buffer + multitok->start);
	} else
		popt->multi = false;

	popt->def = NULL;
	if (json_tok_streq(buffer, typetok, "string")) {
		popt->type = "string";
	} else if (json_tok_streq(buffer, typetok, "int")) {
		popt->type = "int";
	} else if (json_tok_streq(buffer, typetok, "bool")
		   || json_tok_streq(buffer, typetok, "flag")) {
		popt->type = json_strdup(popt, buffer, typetok);
		if (popt->multi)
			return tal_fmt(plugin,
				       "%s type \"%s\" cannot have multi",
				       popt->name, popt->type);
		/* We default flags to false, the default token is ignored */
		if (json_tok_streq(buffer, typetok, "flag"))
			defaulttok = NULL;
	} else {
		return tal_fmt(plugin,
			       "Only \"string\", \"int\", \"bool\", and \"flag\" options are supported");
	}

	if (defaulttok) {
		popt->def = plugin_opt_value(popt, popt->type,
					     json_strdup(tmpctx, buffer, defaulttok));
		if (!popt->def)
			return tal_fmt(tmpctx, "default %.*s is not a valid %s",
				       json_tok_full_len(defaulttok),
				       json_tok_full(buffer, defaulttok),
				       popt->type);
	}

	if (!popt->description)
		popt->description = json_strdup(popt, buffer, desctok);

	list_add_tail(&plugin->plugin_opts, &popt->list);

	if (streq(popt->type, "flag"))
		opt_register_noarg(popt->name, plugin_opt_flag_set, popt,
				   popt->description);

	else
		opt_register_arg(popt->name, plugin_opt_set, NULL, popt,
				 popt->description);

	tal_add_destructor(popt, destroy_plugin_opt);
	return NULL;
}

/* Iterate through the options in the manifest response, and add them
 * to the plugin and the command line options */
static const char *plugin_opts_add(struct plugin *plugin,
				   const char *buffer,
				   const jsmntok_t *resulttok)
{
	const jsmntok_t *options = json_get_member(buffer, resulttok, "options");

	if (!options) {
		return tal_fmt(plugin,
			    "\"result.options\" was not found in the manifest");
	}

	if (options->type != JSMN_ARRAY) {
		return tal_fmt(plugin, "\"result.options\" is not an array");
	}

	for (size_t i = 0; i < options->size; i++) {
		const char *err;
		err = plugin_opt_add(plugin, buffer, json_get_arr(options, i));
		if (err)
			return err;
	}

	return NULL;
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
}

static void plugin_rpcmethod_cb(const char *buffer,
				const jsmntok_t *toks,
				const jsmntok_t *idtok,
				struct plugin_rpccall *call)
{
	struct command *cmd = call->cmd;
	struct json_stream *response;

	response = json_stream_raw_for_cmd(cmd);
	json_stream_forward_change_id(response, buffer, toks, idtok, cmd->id);
	json_stream_double_cr(response);
	command_raw_complete(cmd, response);

	list_del(&call->list);
	tal_free(call);
}

static void plugin_notify_cb(const char *buffer,
			     const jsmntok_t *methodtok,
			     const jsmntok_t *paramtoks,
			     const jsmntok_t *idtok,
			     struct plugin_rpccall *call)
{
	struct command *cmd = call->cmd;
	struct json_stream *response;

	if (!cmd->jcon || !cmd->send_notifications)
		return;

	response = json_stream_raw_for_cmd(cmd);
	json_object_start(response, NULL);
	json_add_string(response, "jsonrpc", "2.0");
	json_add_tok(response, "method", methodtok, buffer);
	json_stream_append(response, ",\"params\":", strlen(",\"params\":"));
	json_stream_forward_change_id(response, buffer,
				      paramtoks, idtok, cmd->id);
	json_object_end(response);

	json_stream_double_cr(response);
	json_stream_flush(response);
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
	struct plugin_rpccall *call;

	if (cmd->mode == CMD_CHECK)
		return command_param_failed();

	plugin = find_plugin_for_command(cmd->ld, cmd->json_cmd->name);
	if (!plugin)
		fatal("No plugin for %s ?", cmd->json_cmd->name);

	/* Find ID again (We've parsed them before, this should not fail!) */
	idtok = json_get_member(buffer, toks, "id");
	assert(idtok != NULL);

	call = tal(plugin, struct plugin_rpccall);
	call->cmd = cmd;

	req = jsonrpc_request_start(plugin, NULL, plugin->log,
				    plugin_notify_cb,
				    plugin_rpcmethod_cb, call);
	call->request = req;
	call->plugin = plugin;
	list_add_tail(&plugin->pending_rpccalls, &call->list);

	snprintf(id, ARRAY_SIZE(id), "%"PRIu64, req->id);

	json_stream_forward_change_id(req->stream, buffer, toks, idtok, id);
	json_stream_double_cr(req->stream);
	plugin_request_send(plugin, req);
	req->stream = NULL;

	return command_still_pending(cmd);
}

static const char *plugin_rpcmethod_add(struct plugin *plugin,
					const char *buffer,
					const jsmntok_t *meth)
{
	const jsmntok_t *nametok, *categorytok, *desctok, *longdesctok,
		*usagetok, *deptok;
	struct json_command *cmd;
	const char *usage;

	nametok = json_get_member(buffer, meth, "name");
	categorytok = json_get_member(buffer, meth, "category");
	desctok = json_get_member(buffer, meth, "description");
	longdesctok = json_get_member(buffer, meth, "long_description");
	usagetok = json_get_member(buffer, meth, "usage");
	deptok = json_get_member(buffer, meth, "deprecated");

	if (!nametok || nametok->type != JSMN_STRING) {
		return tal_fmt(plugin,
			    "rpcmethod does not have a string \"name\": %.*s",
			    meth->end - meth->start, buffer + meth->start);
	}

	if (!desctok || desctok->type != JSMN_STRING) {
		return tal_fmt(plugin,
			    "rpcmethod does not have a string "
			    "\"description\": %.*s",
			    meth->end - meth->start, buffer + meth->start);
	}

	if (longdesctok && longdesctok->type != JSMN_STRING) {
		return tal_fmt(plugin,
			    "\"long_description\" is not a string: %.*s",
			    meth->end - meth->start, buffer + meth->start);
	}

	if (usagetok && usagetok->type != JSMN_STRING) {
		return tal_fmt(plugin,
			    "\"usage\" is not a string: %.*s",
			    meth->end - meth->start, buffer + meth->start);
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
		return tal_fmt(plugin,
			    "\"usage\" not provided by plugin");
	} else
		usage = "[params]";

	if (deptok) {
		if (!json_to_bool(buffer, deptok, &cmd->deprecated))
			return tal_fmt(plugin,
				       "%s: invalid \"deprecated\" field %.*s",
				       cmd->name,
			               deptok->end - deptok->start,
				       buffer + deptok->start);
	} else
		cmd->deprecated = false;

	cmd->dispatch = plugin_rpcmethod_dispatch;
	if (!jsonrpc_command_add(plugin->plugins->ld->jsonrpc, cmd, usage)) {
		struct plugin *p =
		    find_plugin_for_command(plugin->plugins->ld, cmd->name);
		return tal_fmt(
		    plugin,
		    "Could not register method \"%s\", a method with "
		    "that name is already registered by plugin %s",
		    cmd->name, p->cmd);
	}
	tal_arr_expand(&plugin->methods, cmd->name);
	return NULL;
}

static const char *plugin_rpcmethods_add(struct plugin *plugin,
					 const char *buffer,
					 const jsmntok_t *resulttok)
{
	const jsmntok_t *methods =
		json_get_member(buffer, resulttok, "rpcmethods");

	if (!methods)
		return tal_fmt(plugin, "\"result.rpcmethods\" missing");

	if (methods->type != JSMN_ARRAY) {
		return tal_fmt(plugin,
			    "\"result.rpcmethods\" is not an array");
	}

	for (size_t i = 0; i < methods->size; i++) {
		const char *err;
		err = plugin_rpcmethod_add(plugin, buffer,
					   json_get_arr(methods, i));
		if (err)
			return err;
	}

	return NULL;
}

static const char *plugin_subscriptions_add(struct plugin *plugin,
					    const char *buffer,
					    const jsmntok_t *resulttok)
{
	const jsmntok_t *subscriptions =
	    json_get_member(buffer, resulttok, "subscriptions");

	if (!subscriptions) {
		plugin->subscriptions = NULL;
		return NULL;
	}
	plugin->subscriptions = tal_arr(plugin, char *, 0);
	if (subscriptions->type != JSMN_ARRAY) {
		return tal_fmt(plugin, "\"result.subscriptions\" is not an array");
	}

	for (int i = 0; i < subscriptions->size; i++) {
		char *topic;
		const jsmntok_t *s = json_get_arr(subscriptions, i);
		if (s->type != JSMN_STRING) {
			return tal_fmt(plugin,
				       "result.subscriptions[%d] is not a string: '%.*s'", i,
					json_tok_full_len(s),
					json_tok_full(buffer, s));
		}

		/* We add all subscriptions while parsing the
		 * manifest, without checking that they exist, since
		 * later plugins may also emit notifications of custom
		 * types that we don't know about yet. */
		topic = json_strdup(plugin, plugin->buffer, s);
		tal_arr_expand(&plugin->subscriptions, topic);
	}
	return NULL;
}

static const char *plugin_hooks_add(struct plugin *plugin, const char *buffer,
				    const jsmntok_t *resulttok)
{
	const jsmntok_t *t, *hookstok, *beforetok, *aftertok;
	size_t i;

	hookstok = json_get_member(buffer, resulttok, "hooks");
	if (!hookstok)
		return NULL;

	json_for_each_arr(i, t, hookstok) {
		char *name;
		struct plugin_hook *hook;

		if (t->type == JSMN_OBJECT) {
			const jsmntok_t *nametok;

			nametok = json_get_member(buffer, t, "name");
			if (!nametok)
				return tal_fmt(plugin, "no name in hook obj %.*s",
					       json_tok_full_len(t),
					       json_tok_full(buffer, t));
			name = json_strdup(tmpctx, buffer, nametok);
			beforetok = json_get_member(buffer, t, "before");
			aftertok = json_get_member(buffer, t, "after");
		} else {
			/* FIXME: deprecate in 3 releases after v0.9.2! */
			name = json_strdup(tmpctx, plugin->buffer, t);
			beforetok = aftertok = NULL;
		}

		hook = plugin_hook_register(plugin, name);
		if (!hook) {
			return tal_fmt(plugin,
				    "could not register hook '%s', either the "
				    "name doesn't exist or another plugin "
				    "already registered it.",
				    name);
		}

		plugin_hook_add_deps(hook, plugin, buffer, beforetok, aftertok);
		tal_free(name);
	}
	return NULL;
}

static struct plugin_opt *plugin_opt_find(struct plugin *plugin,
					  const char *name, size_t namelen)
{
	struct plugin_opt *opt;

	list_for_each(&plugin->plugin_opts, opt, list) {
		/* Trim the `--` that we added before */
		if (memeqstr(name, namelen, opt->name + 2))
			return opt;
	}
	return NULL;
}

/* start command might have included plugin-specific parameters */
static const char *plugin_add_params(struct plugin *plugin)
{
	size_t i;
	const jsmntok_t *t;

	if (!plugin->params)
		return NULL;

	json_for_each_obj(i, t, plugin->params) {
		struct plugin_opt *popt;
		char *err;

		popt = plugin_opt_find(plugin,
				       plugin->parambuf + t->start,
				       t->end - t->start);
		if (!popt) {
			return tal_fmt(plugin, "unknown parameter %.*s",
				       json_tok_full_len(t),
				       json_tok_full(plugin->parambuf, t));
		}
		err = plugin_opt_set(json_strdup(tmpctx, plugin->parambuf,
						 t + 1), popt);
		if (err)
			return err;
	}
	return NULL;
}

static void plugin_manifest_timeout(struct plugin *plugin)
{
	bool startup = plugin->plugins->startup;

	plugin_kill(plugin, LOG_UNUSUAL,
		    "timed out %s", state_desc(plugin));

	if (startup)
		fatal("Can't recover from plugin failure, terminating.");
}

static const char *plugin_notifications_add(const char *buffer,
					    const jsmntok_t *result,
					    struct plugin *plugin)
{
	char *name;
	size_t i;
	const jsmntok_t *method, *obj;
	const jsmntok_t *notifications =
	    json_get_member(buffer, result, "notifications");

	if (!notifications)
		return NULL;

	if (notifications->type != JSMN_ARRAY)
		return tal_fmt(plugin,
			       "\"result.notifications\" is not an array");

	json_for_each_arr(i, obj, notifications) {
		if (obj->type != JSMN_OBJECT)
			return tal_fmt(
			    plugin,
			    "\"result.notifications[%zu]\" is not an object",
			    i);

		method = json_get_member(buffer, obj, "method");
		if (method == NULL || method->type != JSMN_STRING)
			return tal_fmt(plugin,
				       "\"result.notifications[%zu].name\" "
				       "missing or not a string.",
				       i);

		name = json_strdup(plugin, buffer, method);

		if (notifications_topic_is_native(name))
			return tal_fmt(plugin,
				       "plugin attempted to register a native "
				       "notification topic \"%s\", these may "
				       "however only be sent by lightningd",
				       name);

		tal_arr_expand(&plugin->notification_topics, name);
	}

	return NULL;
}

static const char *plugin_parse_getmanifest_response(const char *buffer,
						     const jsmntok_t *toks,
						     const jsmntok_t *idtok,
						     struct plugin *plugin,
	const char **disabled)
{
	const jsmntok_t *resulttok, *dynamictok, *featurestok, *tok;
	const char *err;

	*disabled = NULL;

	resulttok = json_get_member(buffer, toks, "result");
	if (!resulttok || resulttok->type != JSMN_OBJECT)
		return tal_fmt(plugin, "Invalid/missing result tok in '%.*s'",
			       json_tok_full_len(toks),
			       json_tok_full(buffer, toks));

	/* Plugin can disable itself: returns why it's disabled. */
	tok = json_get_member(buffer, resulttok, "disable");
	if (tok) {
		/* Don't get upset if this was a built-in! */
		plugin->important = false;
		*disabled = json_strdup(plugin, buffer, tok);
		return NULL;
	}

	dynamictok = json_get_member(buffer, resulttok, "dynamic");
	if (dynamictok && !json_to_bool(buffer, dynamictok, &plugin->dynamic)) {
		return tal_fmt(plugin, "Bad 'dynamic' field ('%.*s')",
			    json_tok_full_len(dynamictok),
			    json_tok_full(buffer, dynamictok));
	}

	featurestok = json_get_member(buffer, resulttok, "featurebits");

	if (featurestok) {
		bool have_featurebits = false;
		struct feature_set *fset = talz(tmpctx, struct feature_set);

		BUILD_ASSERT(ARRAY_SIZE(feature_place_names)
			     == ARRAY_SIZE(fset->bits));

		for (int i = 0; i < ARRAY_SIZE(fset->bits); i++) {
			/* We don't allow setting the obs global init */
			if (!feature_place_names[i])
				continue;

			tok = json_get_member(buffer, featurestok,
					      feature_place_names[i]);

			if (!tok)
				continue;

			fset->bits[i] = json_tok_bin_from_hex(fset, buffer, tok);
			have_featurebits |= tal_bytelen(fset->bits[i]) > 0;

			if (!fset->bits[i]) {
				return tal_fmt(
				    plugin,
				    "Featurebits returned by plugin is not a "
				    "valid hexadecimal string: %.*s",
				    tok->end - tok->start, buffer + tok->start);
			}
		}

		if (plugin->dynamic && have_featurebits) {
			return tal_fmt(plugin,
				    "Custom featurebits only allows for non-dynamic "
				    "plugins: dynamic=%d, featurebits=%.*s",
				    plugin->dynamic,
				    featurestok->end - featurestok->start,
				    buffer + featurestok->start);
		}

		if (!feature_set_or(plugin->plugins->ld->our_features, fset)) {
			return tal_fmt(plugin,
				    "Custom featurebits already present");
		}
	}

	err = plugin_notifications_add(buffer, resulttok, plugin);
	if (!err)
		err = plugin_opts_add(plugin, buffer, resulttok);
	if (!err)
		err = plugin_rpcmethods_add(plugin, buffer, resulttok);
	if (!err)
		err = plugin_subscriptions_add(plugin, buffer, resulttok);
	if (!err)
		err = plugin_hooks_add(plugin, buffer, resulttok);
	if (!err)
		err = plugin_add_params(plugin);

	plugin->plugin_state = NEEDS_INIT;
	return err;
}

/**
 * Callback for the plugin_manifest request.
 */
static void plugin_manifest_cb(const char *buffer,
			       const jsmntok_t *toks,
			       const jsmntok_t *idtok,
			       struct plugin *plugin)
{
	const char *err, *disabled;
	err = plugin_parse_getmanifest_response(buffer, toks, idtok, plugin, &disabled);

	if (err) {
		plugin_kill(plugin, LOG_UNUSUAL, "%s", err);
		return;
	}

	if (disabled) {
		plugin_kill(plugin, LOG_DBG,
			    "disabled itself: %s", disabled);
		return;
	}

	/* Reset timer, it'd kill us otherwise. */
	plugin->timeout_timer = tal_free(plugin->timeout_timer);

	if (!plugin->plugins->startup && !plugin->dynamic)
		plugin_kill(plugin, LOG_INFORM,
			    "Not a dynamic plugin");
	else
		check_plugins_manifests(plugin->plugins);
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
		if (!error_ok && errno == ENOENT)
			return NULL;
		return tal_fmt(NULL, "Failed to open plugin-dir %s: %s",
			       dir, strerror(errno));
	}

	while ((di = readdir(d)) != NULL) {
		const char *fullpath;

		if (streq(di->d_name, ".") || streq(di->d_name, ".."))
			continue;
		fullpath = plugin_fullpath(tmpctx, dir, di->d_name);
		if (!fullpath)
			continue;
		if (plugin_blacklisted(plugins, fullpath)) {
			log_info(plugins->log, "%s: disabled via disable-plugin",
				 fullpath);
		} else {
			p = plugin_register(plugins, fullpath, NULL, false,
					    NULL, NULL);
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

static void plugin_set_timeout(struct plugin *p)
{
	bool debug = false;

#if DEVELOPER
	if (p->plugins->ld->dev_debug_subprocess
	    && strends(p->cmd, p->plugins->ld->dev_debug_subprocess))
		debug = true;
#endif

	/* Don't timeout if they're running a debugger. */
	if (debug)
		p->timeout_timer = NULL;
	else {
		p->timeout_timer
			= new_reltimer(p->plugins->ld->timers, p,
				       time_from_sec(PLUGIN_MANIFEST_TIMEOUT),
				       plugin_manifest_timeout, p);
	}
}

const char *plugin_send_getmanifest(struct plugin *p)
{
	char **cmd;
	int stdinfd, stdoutfd;
	struct jsonrpc_request *req;
	bool debug = false;

#if DEVELOPER
	if (p->plugins->ld->dev_debug_subprocess
	    && strends(p->cmd, p->plugins->ld->dev_debug_subprocess))
		debug = true;
#endif
	cmd = tal_arrz(tmpctx, char *, 2 + debug);
	cmd[0] = p->cmd;
	if (debug)
		cmd[1] = "--debugger";
	p->pid = pipecmdarr(&stdinfd, &stdoutfd, &pipecmd_preserve, cmd);
	if (p->pid == -1)
		return tal_fmt(p, "opening pipe: %s", strerror(errno));

	log_debug(p->plugins->log, "started(%u) %s", p->pid, p->cmd);
	p->buffer = tal_arr(p, char, 64);
	jsmn_init(&p->parser);
	p->toks = toks_alloc(p);

	/* Create two connections, one read-only on top of p->stdout, and one
	 * write-only on p->stdin */
	p->stdout_conn = io_new_conn(p, stdoutfd, plugin_stdout_conn_init, p);
	p->stdin_conn = io_new_conn(p, stdinfd, plugin_stdin_conn_init, p);
	req = jsonrpc_request_start(p, "getmanifest", p->log,
				    NULL, plugin_manifest_cb, p);
	json_add_bool(req->stream, "allow-deprecated-apis", deprecated_apis);
	jsonrpc_request_end(req);
	plugin_request_send(p, req);
	p->plugin_state = AWAITING_GETMANIFEST_RESPONSE;

	plugin_set_timeout(p);
	return NULL;
}

bool plugins_send_getmanifest(struct plugins *plugins)
{
	struct plugin *p, *next;
	bool sent = false;

	/* Spawn the plugin processes before entering the io_loop */
	list_for_each_safe(&plugins->plugins, p, next, list) {
		const char *err;

		if (p->plugin_state != UNCONFIGURED)
			continue;
		err = plugin_send_getmanifest(p);
		if (!err) {
			sent = true;
			continue;
		}
		if (plugins->startup)
			fatal("error starting plugin '%s': %s", p->cmd, err);
		plugin_kill(p, LOG_UNUSUAL, "%s", err);
	}

	return sent;
}

void plugins_init(struct plugins *plugins)
{
	plugins->default_dir = path_join(plugins, plugins->ld->config_basedir, "plugins");
	plugins_add_default_dir(plugins);

#if DEVELOPER
	if (plugins->dev_builtin_plugins_unimportant) {
		size_t i;

		log_debug(plugins->log, "Builtin plugins now unimportant");

		/* For each builtin plugin, check for a matching plugin
		 * and make it unimportant.  */
		for (i = 0; list_of_builtin_plugins[i]; ++i) {
			const char *name = list_of_builtin_plugins[i];
			struct plugin *p;
			list_for_each(&plugins->plugins, p, list) {
				if (plugin_paths_match(p->cmd, name)) {
					p->important = false;
					break;
				}
			}
		}
	}
#endif /* DEVELOPER */

	setenv("LIGHTNINGD_PLUGIN", "1", 1);
	setenv("LIGHTNINGD_VERSION", version(), 1);

	if (plugins_send_getmanifest(plugins))
		io_loop_with_timers(plugins->ld);
}

static void plugin_config_cb(const char *buffer,
			     const jsmntok_t *toks,
			     const jsmntok_t *idtok,
			     struct plugin *plugin)
{
	const char *disable;

	/* Plugin can also disable itself at this stage. */
	if (json_scan(tmpctx, buffer, toks, "{result:{disable:%}}",
		      JSON_SCAN_TAL(tmpctx, json_strdup, &disable)) == NULL) {
		/* Don't get upset if this was a built-in! */
		plugin->important = false;
		plugin_kill(plugin, LOG_DBG,
			    "disabled itself at init: %s",
			    disable);
		return;
	}

	plugin->plugin_state = INIT_COMPLETE;
	plugin->timeout_timer = tal_free(plugin->timeout_timer);
	if (plugin->start_cmd) {
		plugin_cmd_succeeded(plugin->start_cmd, plugin);
		plugin->start_cmd = NULL;
	}
	check_plugins_initted(plugin->plugins);
}

static void json_add_plugin_opt(struct json_stream *stream,
				const char *name,
				const char *type,
				const struct plugin_opt_value *value)
{
	if (streq(type, "flag")) {
		/* We don't include 'flag' types if they're not
		 * flagged on */
		if (value->as_bool)
			json_add_bool(stream, name, value->as_bool);
	} else if (streq(type, "bool")) {
		json_add_bool(stream, name, value->as_bool);
	} else if (streq(type, "string")) {
		json_add_string(stream, name, value->as_str);
	} else if (streq(type, "int")) {
		json_add_s64(stream, name, value->as_int);
	}
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

		/* If no values, assign default (if any!) */
		if (tal_count(opt->values) == 0) {
			if (opt->def)
				tal_arr_expand(&opt->values, opt->def);
			else
				continue;
		}

		if (opt->multi) {
			json_array_start(req->stream, name);
			for (size_t i = 0; i < tal_count(opt->values); i++)
				json_add_plugin_opt(req->stream, NULL,
						    opt->type, opt->values[i]);
			json_array_end(req->stream);
		} else {
			json_add_plugin_opt(req->stream, name,
					    opt->type, opt->values[0]);
		}
	}
	json_object_end(req->stream); /* end of .params.options */

	/* Add .params.configuration */
	json_object_start(req->stream, "configuration");
	json_add_string(req->stream, "lightning-dir", ld->config_netdir);
	json_add_string(req->stream, "rpc-file", ld->rpc_filename);
	json_add_bool(req->stream, "startup", plugin->plugins->startup);
	json_add_string(req->stream, "network", chainparams->network_name);
	if (ld->proxyaddr) {
		json_add_address(req->stream, "proxy", ld->proxyaddr);
		json_add_bool(req->stream, "torv3-enabled", ld->config.use_v3_autotor);
		json_add_bool(req->stream, "always_use_proxy", ld->always_use_proxy);
		if (deprecated_apis)
			json_add_bool(req->stream, "use_proxy_always",
				      ld->always_use_proxy);
	}
	json_object_start(req->stream, "feature_set");
	for (enum feature_place fp = 0; fp < NUM_FEATURE_PLACE; fp++) {
		if (feature_place_names[fp]) {
			json_add_hex_talarr(req->stream,
					    feature_place_names[fp],
					    ld->our_features->bits[fp]);
		}
	}
	json_object_end(req->stream);
	json_object_end(req->stream);
}

static void
plugin_config(struct plugin *plugin)
{
	struct jsonrpc_request *req;

	plugin_set_timeout(plugin);
	req = jsonrpc_request_start(plugin, "init", plugin->log,
	                            NULL, plugin_config_cb, plugin);
	plugin_populate_init_request(plugin, req);
	jsonrpc_request_end(req);
	plugin_request_send(plugin, req);
	plugin->plugin_state = AWAITING_INIT_RESPONSE;
}

void plugins_config(struct plugins *plugins)
{
	struct plugin *p;
	list_for_each(&plugins->plugins, p, list) {
		if (p->plugin_state == NEEDS_INIT)
			plugin_config(p);
	}

	plugins->startup = false;
}

/** json_add_opt_plugins_array
 *
 * @brief add a named array of plugins to the given response,
 * depending on whether it is important or not important.
 *
 * @param response - the `json_stream` to write into.
 * @param name - the field name of the array.
 * @param plugins - the plugins object to query.
 * @param important - match the `important` setting of the
 * plugins to be added.
 */
static
void json_add_opt_plugins_array(struct json_stream *response,
				const char *name,
				const struct plugins *plugins,
				bool important)
{
	struct plugin *p;
	struct plugin_opt *opt;
	const char *opt_name;

	/* we output 'plugins' and their options as an array of substructures */
	json_array_start(response, name);
	list_for_each(&plugins->plugins, p, list) {
		/* Skip if not matching.  */
		if (p->important != important)
			continue;

		json_object_start(response, NULL);
		json_add_string(response, "path", p->cmd);

		/* FIXME: use executables basename until plugins can define their names */
		json_add_string(response, "name", p->shortname);

		if (!list_empty(&p->plugin_opts)) {
			json_object_start(response, "options");
			list_for_each(&p->plugin_opts, opt, list) {
				if (!deprecated_apis && opt->deprecated)
					continue;

				/* Trim the `--` that we added before */
				opt_name = opt->name + 2;
				if (opt->multi) {
					json_array_start(response, opt_name);
					for (size_t i = 0; i < tal_count(opt->values); i++)
						json_add_plugin_opt(response,
								    NULL,
								    opt->type,
								    opt->values[i]);
					json_array_end(response);
				} else if (tal_count(opt->values)) {
					json_add_plugin_opt(response,
							    opt_name,
							    opt->type,
							    opt->values[0]);
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

void json_add_opt_plugins(struct json_stream *response,
			  const struct plugins *plugins)
{
	json_add_opt_plugins_array(response, "plugins", plugins, false);
	json_add_opt_plugins_array(response, "important-plugins", plugins, true);
}

void json_add_opt_disable_plugins(struct json_stream *response,
				  const struct plugins *plugins)
{
	json_array_start(response, "disable-plugin");
	for (size_t i = 0; i < tal_count(plugins->blacklist); i++)
		json_add_string(response, NULL, plugins->blacklist[i]);
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

bool plugin_single_notify(struct plugin *p,
			  const struct jsonrpc_notification *n TAKES)
{
	bool interested;
	if (plugin_subscriptions_contains(p, n->method)) {
		plugin_send(p, json_stream_dup(p, n->stream, p->log));
		interested = true;
	} else
		interested = false;

	if (taken(n))
		tal_free(n);

	return interested;
}

void plugins_notify(struct plugins *plugins,
		    const struct jsonrpc_notification *n TAKES)
{
	struct plugin *p;

	if (taken(n))
		tal_steal(tmpctx, n);

	/* If we're shutting down, ld->plugins will be NULL */
	if (plugins) {
		list_for_each(&plugins->plugins, p, list) {
			plugin_single_notify(p, n);
		}
	}
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

void *plugins_exclusive_loop(struct plugin **plugins)
{
	void *ret;
	size_t i;
	bool last = false;
	assert(tal_count(plugins) != 0);

	for (i = 0; i < tal_count(plugins); ++i) {
		io_conn_out_exclusive(plugins[i]->stdin_conn, true);
		io_conn_exclusive(plugins[i]->stdout_conn, true);
	}

	/* We don't service timers here, either! */
	ret = io_loop(NULL, NULL);

	for (i = 0; i < tal_count(plugins); ++i) {
		io_conn_out_exclusive(plugins[i]->stdin_conn, false);
		last = io_conn_exclusive(plugins[i]->stdout_conn, false);
	}
	if (last)
		fatal("Still io_exclusive after removing plugin %s?",
		      plugins[tal_count(plugins) - 1]->cmd);

	return ret;
}

struct log *plugin_get_log(struct plugin *plugin)
{
	return plugin->log;
}

void plugins_set_builtin_plugins_dir(struct plugins *plugins,
				     const char *dir)
{
	/*~ Load the builtin plugins as important.  */
	for (size_t i = 0; list_of_builtin_plugins[i]; ++i)
		plugin_register(plugins,
				take(path_join(NULL, dir,
					       list_of_builtin_plugins[i])),
				NULL,
				/* important = */ true,
				NULL, NULL);
}

void shutdown_plugins(struct lightningd *ld)
{
	struct plugin *p, *next;

	/* The next io_loop does not need db access, close it. */
	ld->wallet->db = tal_free(ld->wallet->db);

	/* Tell them all to shutdown; if they care. */
	list_for_each_safe(&ld->plugins->plugins, p, next, list) {
		/* Kill immediately, deletes self from list. */
		if (p->plugin_state != INIT_COMPLETE || !notify_plugin_shutdown(ld, p))
			tal_free(p);
	}

	/* If anyone was interested in shutdown, give them time. */
	if (!list_empty(&ld->plugins->plugins)) {
		struct timers *timer;
		struct timer *expired;

		/* 30 seconds should do it, use a clean timers struct */
		timer = tal(NULL, struct timers);
		timers_init(timer, time_mono());
		new_reltimer(timer, timer, time_from_sec(30), NULL, NULL);

		void *ret = io_loop(timer, &expired);
		assert(ret == NULL || ret == destroy_plugin);

		/* Report and free remaining plugins. */
		while (!list_empty(&ld->plugins->plugins)) {
			p = list_pop(&ld->plugins->plugins, struct plugin, list);
			log_debug(ld->log,
				  "%s: failed to self-terminate in time, killing.",
				  p->shortname);
			tal_free(p);
		}
	}
}
