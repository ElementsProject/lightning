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
#include <common/configvar.h>
#include <common/deprecation.h>
#include <common/features.h>
#include <common/json_command.h>
#include <common/memleak.h>
#include <common/plugin.h>
#include <common/timeout.h>
#include <common/version.h>
#include <connectd/connectd_wiregen.h>
#include <db/exec.h>
#include <dirent.h>
#include <errno.h>
#include <lightningd/io_loop_with_timers.h>
#include <lightningd/notification.h>
#include <lightningd/plugin.h>
#include <lightningd/plugin_control.h>
#include <lightningd/plugin_hook.h>
#include <lightningd/subd.h>
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

static void memleak_help_pending_requests(struct htable *memtable,
					  struct plugin *plugin)
{
	memleak_scan_strmap(memtable, &plugin->pending_requests);
}

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
	p->log = new_logger(p, log_book, NULL, "plugin-manager");
	p->ld = ld;
	p->startup = true;
	p->plugin_cmds = tal_arr(p, struct plugin_command *, 0);
	p->blacklist = tal_arr(p, const char *, 0);
	p->plugin_idx = 0;
	p->dev_builtin_plugins_unimportant = false;
	p->want_db_transaction = true;

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
		if (!streq(topic, "*")
		    && !notifications_have_topic(plugins, topic))
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
	if (plugins->startup) {
		log_debug(plugins->ld->log, "io_break: %s", __func__);
		io_break(plugins);
	} else
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

	if (plugins->startup)
		io_break(plugins);
}

struct command_result *plugin_register_all_complete(struct lightningd *ld,
						    struct plugin_command *pcmd)
{
	if (plugins_all_in_state(ld->plugins, INIT_COMPLETE))
		return plugin_cmd_all_complete(ld->plugins, pcmd);

	tal_arr_expand(&ld->plugins->plugin_cmds, pcmd);
	return NULL;
}

static void tell_connectd_custommsgs(struct plugins *plugins)
{
	struct plugin *p;
	size_t n = 0;
	u16 *all_msgs = tal_arr(tmpctx, u16, n);

	/* Not when shutting down */
	if (!plugins->ld->connectd)
		return;

	/* Gather from all plugins. */
	list_for_each(&plugins->plugins, p, list) {
		size_t num = tal_count(p->custom_msgs);
		/* Blah blah blah memcpy NULL blah blah */
		if (num == 0)
			continue;
		tal_resize(&all_msgs, n + num);
		memcpy(all_msgs + n, p->custom_msgs, num * sizeof(*p->custom_msgs));
		n += num;
	}

	/* Don't bother sorting or uniquifying.  If plugins are dumb, they deserve it. */
	subd_send_msg(plugins->ld->connectd,
		      take(towire_connectd_set_custommsgs(NULL, all_msgs)));
}

/* Steal req onto reqs. */
static bool request_add(const char *reqid, struct jsonrpc_request *req,
			struct jsonrpc_request ***reqs)
{
	tal_arr_expand(reqs, tal_steal(*reqs, req));
	/* Keep iterating */
	return true;
}

/* FIXME: reorder */
static const char *plugin_read_json_one(struct plugin *plugin,
					bool want_transaction,
					bool *complete,
					bool *destroyed);

/* We act as if the plugin itself said "I'm dead!" */
static void plugin_terminated_fail_req(struct plugin *plugin,
				       struct jsonrpc_request *req)
{
	bool complete, destroyed;
	const char *err;

	jsmn_init(&plugin->parser);
	toks_reset(plugin->toks);
	tal_free(plugin->buffer);
	plugin->buffer = tal_fmt(plugin,
				 "{\"jsonrpc\": \"2.0\","
				 "\"id\": %s,"
				 "\"error\":"
				 " {\"code\":%i, \"message\":\"%s\"}"
				 "}\n\n",
				 req->id,
				 PLUGIN_TERMINATED,
				 "Plugin terminated before replying to RPC call.");
	plugin->used = strlen(plugin->buffer);

	/* We're already in a transaction, don't do it again! */
	err = plugin_read_json_one(plugin, false, &complete, &destroyed);
	assert(!err);
	assert(complete);
}

static void destroy_plugin(struct plugin *p)
{
	struct jsonrpc_request **reqs;

	list_del(&p->list);

	/* Don't have p->conn destructor run. */
	if (p->stdout_conn)
		io_set_finish(p->stdout_conn, NULL, NULL);

	/* Gather all pending RPC calls (we can't iterate as we delete!) */
	reqs = tal_arr(NULL, struct jsonrpc_request *, 0);
	strmap_iterate(&p->pending_requests, request_add, &reqs);

	/* Don't fail requests if we're exiting anyway! */
	if (p->plugins->ld->state != LD_STATE_SHUTDOWN) {
		for (size_t i = 0; i < tal_count(reqs); i++)
			plugin_terminated_fail_req(p, reqs[i]);
	}
	/* Now free all the requests */
	tal_free(reqs);

	/* If this was last one manifests were waiting for, handle deps */
	if (p->plugin_state == AWAITING_GETMANIFEST_RESPONSE)
		check_plugins_manifests(p->plugins);

	/* Daemon shutdown overrules plugin's importance; aborts init checks */
	if (p->plugins->ld->state == LD_STATE_SHUTDOWN) {
		/* But return if this was the last plugin! */
		if (list_empty(&p->plugins->plugins)) {
			log_debug(p->plugins->ld->log, "io_break: %s", __func__);
			io_break(destroy_plugin);
		}
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

	if (tal_count(p->custom_msgs))
		tell_connectd_custommsgs(p->plugins);
}

static u32 file_checksum(struct lightningd *ld, const char *path)
{
	char *content;

	if (ld->dev_no_plugin_checksum)
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
	char* abspath;
	u32 chksum;

	abspath = path_canon(tmpctx, path);
	if (!abspath) {
		return NULL;
	}
	/* Don't register an already registered plugin */
	list_for_each(&plugins->plugins, p_temp, list) {
		if (streq(abspath, p_temp->cmd)) {
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
	p->cmd = tal_steal(p, abspath);
	p->checksum = file_checksum(plugins->ld, p->cmd);
	p->shortname = path_basename(p, p->cmd);
	p->start_cmd = start_cmd;
	p->can_check = false;

	p->plugin_state = UNCONFIGURED;
	p->js_arr = tal_arr(p, struct json_stream *, 0);
	p->used = 0;
	p->notification_topics = tal_arr(p, const char *, 0);
	p->subscriptions = NULL;
	p->dynamic = false;
	p->non_numeric_ids = false;
	p->index = plugins->plugin_idx++;
	p->stdout_conn = NULL;

	p->log = new_logger(p, plugins->ld->log_book, NULL, "plugin-%s", p->shortname);
	p->methods = tal_arr(p, const char *, 0);
	list_head_init(&p->plugin_opts);

	list_add_tail(&plugins->plugins, &p->list);
	tal_add_destructor(p, destroy_plugin);
	strmap_init(&p->pending_requests);
	memleak_add_helper(p, memleak_help_pending_requests);

	p->important = important;
	p->parambuf = tal_steal(p, parambuf);
	p->params = tal_steal(p, params);
	p->custom_msgs = NULL;

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
	/* Unless, maybe, plugin was *really* important? */
	assert(plugin->pid != -1);
	kill(plugin->pid, SIGKILL);
	if (plugin->start_cmd) {
		plugin_cmd_killed(plugin->start_cmd, plugin, msg);
		plugin->start_cmd = NULL;
	}

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
	struct jsonrpc_request *request;

	/* id inside params tells us which id to redirect to. */
	idtok = json_get_member(plugin->buffer, paramstok, "id");
	if (!idtok) {
		return tal_fmt(plugin,
			       "JSON-RPC notify \"id\"-field is not present");
	}

	/* Include any "" in id */
	request = strmap_getn(&plugin->pending_requests,
			      json_tok_full(plugin->buffer, idtok),
			      json_tok_full_len(idtok));
	if (!request) {
		return NULL;
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

static void destroy_request(struct jsonrpc_request *req,
                            struct plugin *plugin)
{
	strmap_del(&plugin->pending_requests, req->id, NULL);
}

static void plugin_response_handle(struct plugin *plugin,
				   const jsmntok_t *toks,
				   const jsmntok_t *idtok)
{
	struct jsonrpc_request *request;
	const tal_t *ctx;

	request = strmap_getn(&plugin->pending_requests,
			      json_tok_full(plugin->buffer, idtok),
			      json_tok_full_len(idtok));
	/* Can happen if request was freed before plugin responded */
	if (!request) {
		return;
	}


	/* Request callback often frees request: if not, we do. */
	ctx = tal(NULL, char);
	tal_steal(ctx, request);
	/* Don't keep track of this request; we will terminate it */
	tal_del_destructor2(request, destroy_request, plugin);
	destroy_request(request, plugin);
	request->response_cb(plugin->buffer, toks, idtok, request->response_cb_arg);
	tal_free(ctx);
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
					bool want_transaction,
					bool *complete,
					bool *destroyed)
{
	const jsmntok_t *jrtok, *idtok;
	struct plugin_destroyed *pd;
	const char *err;
	struct wallet *wallet = plugin->plugins->ld->wallet;

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

	if (plugin->toks->type != JSMN_OBJECT)
		return tal_fmt(
		    plugin,
		    "JSON-RPC message is not a valid JSON object type");

	jrtok = json_get_member(plugin->buffer, plugin->toks, "jsonrpc");
	idtok = json_get_member(plugin->buffer, plugin->toks, "id");

	if (!jrtok) {
		return tal_fmt(
		    plugin,
		    "JSON-RPC message does not contain \"jsonrpc\" field");
	}

	/* We can be called extremely early, or as db hook, or for
	 * fake "terminated" request. */
	if (want_transaction)
		db_begin_transaction(wallet->db);

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
		plugin_response_handle(plugin, plugin->toks, idtok);
		err = NULL;
	}
	if (want_transaction)
		db_commit_transaction(wallet->db);

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
	/* wallet is NULL in really early code */
	bool want_transaction = (plugin->plugins->want_db_transaction
				 && plugin->plugins->ld->wallet != NULL);

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

			err = plugin_read_json_one(plugin, want_transaction,
						   &success, &destroyed);

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
	struct db *db = plugin->plugins->ld->wallet->db;
	db_begin_transaction(db);
	/* This is expected at shutdown of course. */
	plugin_kill(plugin,
		    plugin->plugins->ld->state == LD_STATE_SHUTDOWN
		    ? LOG_DBG : LOG_INFORM,
		    "exited %s", state_desc(plugin));
	db_commit_transaction(db);
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

static char *plugin_opt_check(struct plugin_opt *popt)
{
	/* Fail if this is deprecated */
	if (!lightningd_deprecated_in_ok(popt->plugin->plugins->ld,
					 popt->plugin->plugins->log,
					 popt->plugin->plugins->ld->deprecated_ok,
					 popt->plugin->shortname,
					 popt->name,
					 popt->depr_start,
					 popt->depr_end, NULL))
		return tal_fmt(tmpctx, "deprecated option (will be removed!)");
	return NULL;
}

static bool plugin_opt_deprecated_out_ok(struct plugin_opt *popt)
{
	return lightningd_deprecated_out_ok(popt->plugin->plugins->ld,
					    popt->plugin->plugins->ld->deprecated_ok,
					    popt->plugin->shortname,
					    /* Skip --prefix  */
					    popt->name + 2,
					    popt->depr_start,
					    popt->depr_end);
}

/* We merely check they're valid: the values stay in configvars */
static char *plugin_opt_string_check(const char *arg, struct plugin_opt *popt)
{
	return plugin_opt_check(popt);
}

static char *plugin_opt_long_check(const char *arg, struct plugin_opt *popt)
{
	long v;
	char *ret = opt_set_longval(arg, &v);
	if (ret)
		return ret;
	return plugin_opt_check(popt);
}

static char *plugin_opt_bool_check(const char *arg, struct plugin_opt *popt)
{
	/* FIXME: For some reason, '1' and '0' were allowed here? */
	if (streq(arg, "1") || streq(arg, "0")) {
		struct lightningd *ld = popt->plugin->plugins->ld;
		if (!lightningd_deprecated_in_ok(ld, ld->log, ld->deprecated_ok,
						 popt->name + 2, "0-or-1",
						 "v23.08", "v24.08", NULL)) {
			return "boolean plugin arguments must be true or false";
		}
	} else {
		bool v;
		char *ret = opt_set_bool_arg(arg, &v);
		if (ret)
			return ret;
	}
	return plugin_opt_check(popt);
}

static char *plugin_opt_flag_check(struct plugin_opt *popt)
{
	return plugin_opt_check(popt);
}

static bool popt_show_default(char *buf, size_t len,
			      const struct plugin_opt *popt)
{
	if (!popt->def)
		return false;
	strncpy(buf, popt->def, len);
	return true;
}

static void destroy_plugin_opt(struct plugin_opt *opt,
			       struct plugin *plugin)
{
	opt_unregister(opt->name);
	list_del_from(&plugin->plugin_opts, &opt->list);
	/* If any configvars were added on `plugin start`, remove now */
	configvar_remove(&plugin->plugins->ld->configvars,
			 opt->name + 2, /* Skip -- */
			 CONFIGVAR_PLUGIN_START, NULL);
}

bool is_plugin_opt(const struct opt_table *ot)
{
	if (ot->type & OPT_NOARG)
		return ot->cb == (void *)plugin_opt_flag_check;

	return ot->cb_arg == (void *)plugin_opt_string_check
		|| ot->cb_arg == (void *)plugin_opt_long_check
		|| ot->cb_arg == (void *)plugin_opt_bool_check;
}

/* Sets *ret to false if it doesn't appear, otherwise, sets to value */
static char *bool_setting(tal_t *ctx,
			  const char *optname,
			  const char *buffer,
			  const jsmntok_t *opt,
			  const char *tokname,
			  bool *ret)
{
	const jsmntok_t *tok = json_get_member(buffer, opt, tokname);
	if (!tok) {
		*ret = false;
		return NULL;
	}
	if (!json_to_bool(buffer, tok, ret))
		return tal_fmt(ctx,
			       "%s: invalid \"%s\" field %.*s",
			       optname, tokname,
			       tok->end - tok->start,
			       buffer + tok->start);
	return NULL;
}

/* Parse deprecated field, as either bool or an array of strings */
static const char *json_parse_deprecated(const tal_t *ctx,
					 const char *buffer,
					 const jsmntok_t *deprtok,
					 const char **depr_start,
					 const char **depr_end)
{
	bool is_depr;

	*depr_start = *depr_end = NULL;

	if (!deprtok)
		return NULL;

	/* Not every plugin will track deprecation cycles (and that's OK!):
	 * pretend it's just been deprecated. */
	if (json_to_bool(buffer, deprtok, &is_depr)) {
		if (is_depr)
			*depr_start = CLN_NEXT_VERSION;
		return NULL;
	}

	if (deprtok->type != JSMN_ARRAY || deprtok->size > 2) {
		return tal_fmt(ctx, "\"deprecated\" must be an array of 1 or 2 elements, not %.*s",
			       deprtok->end - deprtok->start,
			       buffer + deprtok->start);
	}

	*depr_start = json_strdup(ctx, buffer, deprtok + 1);
	if (version_to_number(*depr_start) == 0)
		return tal_fmt(ctx,
			       "invalid \"deprecated\" start version %s",
			       *depr_start);

	if (deprtok->size == 2) {
		*depr_end = json_strdup(ctx, buffer, deprtok + 2);
		if (version_to_number(*depr_end) == 0)
			return tal_fmt(ctx,
				       "invalid \"deprecated\" end version %s",
				       *depr_end);
	}
	return NULL;
}

/* Add a single plugin option to the plugin as well as registering it with the
 * command line options. */
static const char *plugin_opt_add(struct plugin *plugin, const char *buffer,
				  const jsmntok_t *opt)
{
	const jsmntok_t *nametok, *typetok, *defaulttok, *desctok, *deprtok;
	struct plugin_opt *popt;
	const char *name, *err;
	enum opt_type optflags = 0;
	bool set;
	struct lightningd *ld = plugin->plugins->ld;

	nametok = json_get_member(buffer, opt, "name");
	typetok = json_get_member(buffer, opt, "type");
	desctok = json_get_member(buffer, opt, "description");
	defaulttok = json_get_member(buffer, opt, "default");
	deprtok = json_get_member(buffer, opt, "deprecated");

	if (!typetok || !nametok || !desctok) {
		return tal_fmt(plugin,
			    "An option is missing either \"name\", \"description\" or \"type\"");
	}

	popt = tal(plugin, struct plugin_opt);
	popt->plugin = plugin;
	popt->name = tal_fmt(popt, "--%s",
			     json_strdup(tmpctx, buffer, nametok));
	name = popt->name + 2;
	popt->def = NULL;
	popt->depr_start = popt->depr_end = NULL;

	/* Only allow sane option names  */
	if (strspn(name, "0123456789" "abcdefghijklmnopqrstuvwxyz" "_-")
	    != strlen(name))
		return tal_fmt(plugin, "Option \"name\" must be lowercase alphanumeric, plus _ or -'");

	/* Don't allow duplicate names! */
	if (opt_find_long(name, NULL)) {
		/* Fail hard on startup */
		if (plugin->plugins->startup)
			fatal("error starting plugin '%s':"
			      " option name '%s' is already taken",
			      plugin->cmd, name);
		return tal_fmt(plugin, "Option \"%s\" already registered",
			       name);
	}

	popt->description = json_strdup(popt, buffer, desctok);

	err = json_parse_deprecated(popt, buffer, deprtok,
				    &popt->depr_start, &popt->depr_end);
	if (err)
		return tal_steal(plugin, err);

	err = bool_setting(plugin, popt->name, buffer, opt, "multi", &set);
	if (err)
		return err;
	if (set)
		optflags |= OPT_MULTI;

	err = bool_setting(plugin, popt->name, buffer, opt, "dynamic", &set);
	if (err)
		return err;
	if (set)
		optflags |= OPT_DYNAMIC;

	if (json_tok_streq(buffer, typetok, "flag")) {
		if (defaulttok) {
			bool val;
			/* We used to allow (ignore) anything, now make sure it's 'false' */
			if (!json_to_bool(buffer, defaulttok, &val)
			    || val != false) {
				if (!lightningd_deprecated_in_ok(ld, plugin->log,
								 ld->deprecated_ok,
								 "options.flag", "default-not-false",
								 "v23.08", "v24.08", NULL)) {
					return tal_fmt(plugin, "%s type flag default must be 'false' not %.*s",
						       popt->name,
						       json_tok_full_len(defaulttok),
						       json_tok_full(buffer, defaulttok));
				}
			}
			defaulttok = NULL;
		}
		if (optflags & OPT_MULTI)
			return tal_fmt(plugin, "flag type cannot be multi");
		clnopt_noarg(popt->name,
			     optflags,
			     plugin_opt_flag_check, popt,
			     /* Don't document if it's deprecated */
			     popt->depr_start ? opt_hidden : popt->description);
	} else {
		/* These all take an arg. */
		char *(*cb_arg)(const char *optarg, void *arg);

		if (json_tok_streq(buffer, typetok, "string")) {
			cb_arg = (void *)plugin_opt_string_check;
		} else if (json_tok_streq(buffer, typetok, "int")) {
			cb_arg = (void *)plugin_opt_long_check;
			optflags |= OPT_SHOWINT;
		} else if (json_tok_streq(buffer, typetok, "bool")) {
			if (optflags & OPT_MULTI)
				return tal_fmt(plugin, "bool type cannot be multi");
			optflags |= OPT_SHOWBOOL;
			cb_arg = (void *)plugin_opt_bool_check;
		} else {
			return tal_fmt(plugin,
				       "Only \"string\", \"int\", \"bool\", and \"flag\" options are supported");
		}

		/* Now we know how to parse defaulttok */
		if (defaulttok && !json_tok_is_null(buffer, defaulttok)) {
			const char *problem;
			popt->def = json_strdup(popt, buffer, defaulttok);
			/* Parse it exactly like the normal code path. */
			problem = cb_arg(popt->def, popt);
			if (problem)
				return tal_fmt(plugin, "Invalid default '%s': %s",
					       popt->def, tal_steal(tmpctx, problem));
		}
		/* show is only used for defaults: listconfigs uses
		 * configvar if it's set. */
		clnopt_witharg(popt->name,
			       optflags, cb_arg, popt_show_default, popt,
			       /* Don't document if it's deprecated */
			       popt->depr_start ? opt_hidden : popt->description);
	}

	list_add_tail(&plugin->plugin_opts, &popt->list);
	tal_add_destructor2(popt, destroy_plugin_opt, plugin);
	return NULL;
}

/* Iterate through the options in the manifest response, and add them
 * to the plugin and the command line options */
static const char *plugin_opts_add(struct plugin *plugin,
				   const char *buffer,
				   const jsmntok_t *resulttok)
{
	const jsmntok_t *options = json_get_member(buffer, resulttok, "options");
	size_t i;
	const jsmntok_t *t;

	if (!options) {
		return tal_fmt(plugin,
			    "\"result.options\" was not found in the manifest");
	}

	if (options->type != JSMN_ARRAY) {
		return tal_fmt(plugin, "\"result.options\" is not an array");
	}

	json_for_each_arr(i, t, options) {
		const char *err = plugin_opt_add(plugin, buffer, t);
		if (err)
			return err;
	}

	return NULL;
}

static void json_stream_forward_change_id(struct json_stream *stream,
					  const char *buffer,
					  const jsmntok_t *toks,
					  const jsmntok_t *idtok,
					  /* Full token, including "" */
					  const char *new_id)
{
	/* We copy everything, but replace the id. Special care has to
	 * be taken when the id that is being replaced is a string. If
	 * we don't crop the quotes off we'll transform a numeric
	 * new_id into a string, or even worse, quote a string id
	 * twice. */
	const char *id_start, *id_end;

	id_start = json_tok_full(buffer, idtok);
	id_end = id_start + json_tok_full_len(idtok);

	json_stream_append(stream, buffer + toks->start,
			   id_start - (buffer + toks->start));
	json_stream_append(stream, new_id, strlen(new_id));
	json_stream_append(stream, id_end, (buffer + toks->end) - id_end);
}

static void plugin_rpcmethod_cb(const char *buffer,
				const jsmntok_t *toks,
				const jsmntok_t *idtok,
				struct command *cmd)
{
	struct json_stream *response;

	response = json_stream_raw_for_cmd(cmd);
	json_stream_forward_change_id(response, buffer, toks, idtok, cmd->id);
	json_stream_double_cr(response);
	command_raw_complete(cmd, response);
}

static void plugin_notify_cb(const char *buffer,
			     const jsmntok_t *methodtok,
			     const jsmntok_t *paramtoks,
			     const jsmntok_t *idtok,
			     struct command *cmd)
{
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

static struct command_result *plugin_rpcmethod_check(struct command *cmd,
						     const char *buffer,
						     const jsmntok_t *toks,
						     const jsmntok_t *params)
{
	const jsmntok_t *idtok;
	struct plugin *plugin;
	struct jsonrpc_request *req;

	plugin = find_plugin_for_command(cmd->ld, cmd->json_cmd->name);
	if (!plugin)
		fatal("No plugin for %s ?", cmd->json_cmd->name);

	assert(command_check_only(cmd));

	if (!plugin->can_check) {
		log_unusual(plugin->log, "Plugin does not support check command for %s (id %s)",
			    cmd->json_cmd->name, cmd->id);
		return command_check_done(cmd);
	}

	/* Find id again (we've parsed them before, this should not fail!) */
	idtok = json_get_member(buffer, toks, "id");
	assert(idtok != NULL);

	/* Send check command through, it says it can handle it! */
	req = jsonrpc_request_start_raw(plugin, "check",
					cmd->id, plugin->non_numeric_ids,
					plugin->log,
					plugin_notify_cb,
					plugin_rpcmethod_cb, cmd);

	json_stream_forward_change_id(req->stream, buffer, toks, idtok, req->id);
	json_stream_double_cr(req->stream);
	plugin_request_send(plugin, req);
	req->stream = NULL;

	return command_still_pending(cmd);
}

static struct command_result *plugin_rpcmethod_dispatch(struct command *cmd,
							const char *buffer,
							const jsmntok_t *toks,
							const jsmntok_t *params UNNEEDED)
{
	const jsmntok_t *idtok;
	struct plugin *plugin;
	struct jsonrpc_request *req;
	bool cmd_ok;

	plugin = find_plugin_for_command(cmd->ld, cmd->json_cmd->name);
	if (!plugin)
		fatal("No plugin for %s ?", cmd->json_cmd->name);

	/* This should go to plugin_rpcmethod_check! */
	assert(!command_check_only(cmd));

	/* Find ID again (We've parsed them before, this should not fail!) */
	idtok = json_get_member(buffer, toks, "id");
	assert(idtok != NULL);

	/* If they've changed deprecation status for this cmd, tell plugin */
	cmd_ok = command_deprecated_ok_flag(cmd);
	if (cmd_ok != cmd->ld->deprecated_ok) {
		if (!notify_deprecated_oneshot(cmd->ld, plugin, cmd_ok)) {
			log_debug(plugin->log,
				  "Plugin does not support deprecation setting for cmd %s (id %s)",
				  cmd->json_cmd->name, cmd->id);
		}
	}
	req = jsonrpc_request_start_raw(plugin, cmd->json_cmd->name,
					cmd->id, plugin->non_numeric_ids,
					plugin->log,
					plugin_notify_cb,
					plugin_rpcmethod_cb, cmd);

	json_stream_forward_change_id(req->stream, buffer, toks, idtok, req->id);
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
		*usagetok, *deprtok;
	struct json_command *cmd;
	const char *usage, *err;

	nametok = json_get_member(buffer, meth, "name");
	categorytok = json_get_member(buffer, meth, "category");
	desctok = json_get_member(buffer, meth, "description");
	longdesctok = json_get_member(buffer, meth, "long_description");
	usagetok = json_get_member(buffer, meth, "usage");
	deprtok = json_get_member(buffer, meth, "deprecated");

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
	else
		return tal_fmt(plugin,
			    "\"usage\" not provided by plugin");

	err = json_parse_deprecated(cmd, buffer, deprtok, &cmd->depr_start, &cmd->depr_end);
	if (err)
		return tal_steal(plugin, err);

	cmd->dev_only = false;
	cmd->dispatch = plugin_rpcmethod_dispatch;
	cmd->check = plugin_rpcmethod_check;
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
	size_t i;
	const jsmntok_t *s, *subscriptions =
	    json_get_member(buffer, resulttok, "subscriptions");

	if (!subscriptions) {
		plugin->subscriptions = NULL;
		return NULL;
	}
	plugin->subscriptions = tal_arr(plugin, char *, 0);
	if (subscriptions->type != JSMN_ARRAY) {
		return tal_fmt(plugin, "\"result.subscriptions\" is not an array");
	}

	json_for_each_arr(i, s, subscriptions) {
		char *topic;
		if (s->type != JSMN_STRING) {
			return tal_fmt(plugin,
				       "result.subscriptions[%zu] is not a string: '%.*s'", i,
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

static struct plugin_opt *plugin_opt_find(const struct plugin *plugin,
					  const char *name)
{
	struct plugin_opt *opt;

	list_for_each(&plugin->plugin_opts, opt, list) {
		if (streq(opt->name + 2, name))
			return opt;
	}
	return NULL;
}

/* Find the plugin_opt for this ot */
static struct plugin *plugin_opt_find_any(const struct plugins *plugins,
					  const struct opt_table *ot,
					  struct plugin_opt **poptp)
{
	struct plugin *plugin;

	/* Find the plugin that registered this RPC call */
	list_for_each(&plugins->plugins, plugin, list) {
		struct plugin_opt *popt = plugin_opt_find(plugin, ot->names+2);
		if (popt) {
			if (poptp)
				*poptp = popt;
			return plugin;
		}
	}

	/* Reaching here is possible, if a plugin was stopped! */
	return NULL;
}

void json_add_config_plugin(struct json_stream *stream,
			    const struct plugins *plugins,
			    const char *fieldname,
			    const struct opt_table *ot)
{
	struct plugin *plugin;

	/* Shortcut */
	if (!is_plugin_opt(ot))
		return;

	/* Find the plugin that registered this RPC call */
	plugin = plugin_opt_find_any(plugins, ot, NULL);
	if (plugin)
		json_add_string(stream, fieldname, plugin->cmd);
}

/* Start command might have included plugin-specific parameters.
 * We make sure they *are* parameters for this plugin, then add them
 * to our configvars. */
static const char *plugin_add_params(const struct plugin *plugin)
{
	size_t i;
	const jsmntok_t *t;

	if (!plugin->params)
		return NULL;

	json_for_each_obj(i, t, plugin->params) {
		struct opt_table *ot;
		const char *name = json_strdup(tmpctx, plugin->parambuf, t);
		struct configvar *cv;
		const char *err;

		/* This serves two purposes; make sure we don't set an option
		 * for a different pligin on the plugin start cmdline, and
		 * make sure we clean it up, since we only clean our own
		 * configvars in destroy_plugin_opt */
		if (!plugin_opt_find(plugin, name))
			return tal_fmt(plugin, "unknown parameter %s", name);

		ot = opt_find_long(name, NULL);
		if (ot->type & OPT_HASARG) {
			name = tal_fmt(NULL, "%s=%.*s",
				       name,
				       t[1].end - t[1].start,
				       plugin->parambuf + t[1].start);
		}
		cv = configvar_new(plugin->plugins->ld->configvars,
				   CONFIGVAR_PLUGIN_START,
				   NULL, 0, take(name));
		tal_arr_expand(&plugin->plugins->ld->configvars, cv);

		/* If this fails, we free plugin and unregister the configvar */
		err = configvar_parse(cv, false, true,
				      plugin->plugins->ld->developer);
		if (err)
			return err;
	}

	/* We might have overridden previous configvars */
	configvar_finalize_overrides(plugin->plugins->ld->configvars);
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
	const jsmntok_t *resulttok, *featurestok, *custommsgtok, *tok;
	const char *err;
	struct lightningd *ld = plugin->plugins->ld;

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

	err = bool_setting(plugin, "getmanifest", buffer, resulttok, "dynamic",
			   &plugin->dynamic);
	if (err)
		return err;

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

		if (!feature_set_or(ld->our_features, fset)) {
			return tal_fmt(plugin,
				    "Custom featurebits already present");
		}
	}

	custommsgtok = json_get_member(buffer, resulttok, "custommessages");
	if (custommsgtok) {
		size_t i;
		const jsmntok_t *t;

		if (custommsgtok->type != JSMN_ARRAY)
			return tal_fmt(plugin, "custommessages must be array, not '%.*s'",
				       json_tok_full_len(custommsgtok),
				       json_tok_full(buffer, custommsgtok));
		plugin->custom_msgs = tal_arr(plugin, u16, custommsgtok->size);
		json_for_each_arr(i, t, custommsgtok) {
			if (!json_to_u16(buffer, t, &plugin->custom_msgs[i]))
				return tal_fmt(plugin, "custommessages %zu not a u16: '%.*s'",
					       i,
					       json_tok_full_len(t),
					       json_tok_full(buffer, t));
		}
	}

	tok = json_get_member(buffer, resulttok, "nonnumericids");
	if (tok) {
		if (!json_to_bool(buffer, tok, &plugin->non_numeric_ids))
			return tal_fmt(plugin,
				       "Invalid nonnumericids: %.*s",
				       json_tok_full_len(tok),
				       json_tok_full(buffer, tok));
		if (!plugin->non_numeric_ids
		    && !lightningd_deprecated_in_ok(ld, ld->log, ld->deprecated_ok,
						    "plugin", "nonnumericids",
						    "v23.08", "v24.08", NULL)) {
			return tal_fmt(plugin,
				       "Plugin does not allow nonnumericids");
		}
	} else {
		/* Default is false in deprecated mode */
		plugin->non_numeric_ids = !lightningd_deprecated_out_ok(ld, ld->deprecated_ok,
									"plugin", "nonnumericids",
									"v23.08", "v24.08");
	}

	tok = json_get_member(buffer, resulttok, "cancheck");
	if (tok) {
		if (!json_to_bool(buffer, tok, &plugin->can_check))
			return tal_fmt(plugin,
				       "Invalid cancheck: %.*s",
				       json_tok_full_len(tok),
				       json_tok_full(buffer, tok));
	} else {
		plugin->can_check = false;
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

	if (!err)
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
		plugin_kill(plugin, LOG_INFORM,
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
		return tal_fmt(tmpctx, "Failed to open plugin-dir %s: %s",
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
			if (!p && !error_ok) {
				closedir(d);
				return tal_fmt(tmpctx, "Failed to register %s: %s",
				               fullpath, strerror(errno));
			}
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

static bool debugging(struct plugin *p)
{
	if (p->plugins->ld->dev_debug_subprocess == NULL)
		return false;
	return strends(p->cmd, p->plugins->ld->dev_debug_subprocess);
}

static void plugin_set_timeout(struct plugin *p)
{
	/* Don't timeout if they're running a debugger. */
	if (debugging(p))
		p->timeout_timer = NULL;
	else {
		p->timeout_timer
			= new_reltimer(p->plugins->ld->timers, p,
				       time_from_sec(PLUGIN_MANIFEST_TIMEOUT),
				       plugin_manifest_timeout, p);
	}
}

const char *plugin_send_getmanifest(struct plugin *p, const char *cmd_id)
{
	char **cmd;
	int stdinfd, stdoutfd;
	struct jsonrpc_request *req;

	cmd = tal_arr(tmpctx, char *, 1);
	cmd[0] = p->cmd;
	if (debugging(p))
		tal_arr_expand(&cmd, "--dev-debug-self");
	if (p->plugins->ld->developer)
		tal_arr_expand(&cmd, "--developer");
	tal_arr_expand(&cmd, NULL);
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
	req = jsonrpc_request_start(p, "getmanifest", cmd_id, p->non_numeric_ids,
				    p->log, NULL, plugin_manifest_cb, p);
	json_add_bool(req->stream, "allow-deprecated-apis",
		      p->plugins->ld->deprecated_ok);
	jsonrpc_request_end(req);
	plugin_request_send(p, req);
	p->plugin_state = AWAITING_GETMANIFEST_RESPONSE;

	plugin_set_timeout(p);
	return NULL;
}

bool plugins_send_getmanifest(struct plugins *plugins, const char *cmd_id)
{
	struct plugin *p, *next;
	bool sent = false;

	/* Spawn the plugin processes before entering the io_loop */
	list_for_each_safe(&plugins->plugins, p, next, list) {
		const char *err;

		if (p->plugin_state != UNCONFIGURED)
			continue;
		err = plugin_send_getmanifest(p, cmd_id);
		if (!err) {
			sent = true;
			continue;
		}
		if (plugins->startup)
			fatal("error starting plugin '%s': %s", p->cmd, err);
		tal_free(p);
	}

	return sent;
}

void plugins_init(struct plugins *plugins)
{
	plugins->default_dir = path_join(plugins, plugins->ld->config_basedir, "plugins");
	plugins_add_default_dir(plugins);

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

	setenv("LIGHTNINGD_PLUGIN", "1", 1);
	setenv("LIGHTNINGD_VERSION", version(), 1);

	if (plugins_send_getmanifest(plugins, NULL)) {
		void *ret;
		ret = io_loop_with_timers(plugins->ld);
		log_debug(plugins->ld->log, "io_loop_with_timers: %s", __func__);
		assert(ret == plugins);
	}
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
	if (tal_count(plugin->custom_msgs))
		tell_connectd_custommsgs(plugin->plugins);
	check_plugins_initted(plugin->plugins);
}

static void json_add_plugin_val(struct json_stream *stream,
				const struct opt_table *ot,
				const char *name,
				const char *val)
{
	if ((ot->type & OPT_SHOWINT) || (ot->type & OPT_SHOWMSATS)) {
		json_add_primitive(stream, name, val);
	} else if (ot->type & OPT_SHOWBOOL) {
		/* We allow variants here.  Json-ize */
		json_add_bool(stream, name, opt_canon_bool(val));
	} else {
		json_add_string(stream, name, val);
	}
}

static void json_add_plugin_options(struct json_stream *stream,
				    const char *fieldname,
				    struct plugin *plugin,
				    bool include_deprecated)
{
	/* We don't allow multiple option names in plugins */
	struct lightningd *ld = plugin->plugins->ld;
	const char **namesarr = tal_arr(tmpctx, const char *, 1);
	struct plugin_opt *popt;

	json_object_start(stream, fieldname);
	list_for_each(&plugin->plugin_opts, popt, list) {
		struct configvar *cv;
		const struct opt_table *ot;

		if (!include_deprecated && !plugin_opt_deprecated_out_ok(popt))
			continue;

		namesarr[0] = popt->name + 2;
		cv = configvar_first(ld->configvars, namesarr);
		if (!cv && !popt->def)
			continue;

		ot = opt_find_long(namesarr[0], NULL);
		if (ot->type & OPT_MULTI) {
			json_array_start(stream, namesarr[0]);
			if (!cv) {
				json_add_plugin_val(stream, ot, NULL,
						    popt->def);
			} else {
				while (cv) {
					json_add_plugin_val(stream,
							    ot, NULL,
							    cv->optarg);
					cv = configvar_next(ld->configvars,
							    cv, namesarr);
				}
			}
			json_array_end(stream);
		} else {
			if (!cv) {
				json_add_plugin_val(stream, ot,
						    namesarr[0],
						    popt->def);
			} else if (cv->optarg) {
				json_add_plugin_val(stream,
						    ot,
						    namesarr[0],
						    cv->optarg);
			} else {
				/* We specify non-arg options as 'true' */
				json_add_bool(stream, namesarr[0], true);
			}
		}
	}
	json_object_end(stream);
}

void
plugin_populate_init_request(struct plugin *plugin, struct jsonrpc_request *req)
{
	struct lightningd *ld = plugin->plugins->ld;

	/* Add .params.options */
	json_add_plugin_options(req->stream, "options", plugin, true);
	/* Add .params.configuration */
	json_object_start(req->stream, "configuration");
	json_add_string(req->stream, "lightning-dir", ld->config_netdir);
	json_add_string(req->stream, "rpc-file", ld->rpc_filename);
	json_add_bool(req->stream, "startup", plugin->plugins->startup);
	json_add_string(req->stream, "network", chainparams->network_name);
	if (ld->proxyaddr) {
		json_add_address(req->stream, "proxy", ld->proxyaddr);
		json_add_bool(req->stream, "torv3-enabled", true);
		json_add_bool(req->stream, "always_use_proxy", ld->always_use_proxy);
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
	req = jsonrpc_request_start(plugin, "init", NULL, plugin->non_numeric_ids,
				    plugin->log, NULL, plugin_config_cb, plugin);
	plugin_populate_init_request(plugin, req);
	jsonrpc_request_end(req);
	plugin_request_send(plugin, req);
	plugin->plugin_state = AWAITING_INIT_RESPONSE;
}

bool plugins_config(struct plugins *plugins)
{
	struct plugin *p;
	list_for_each(&plugins->plugins, p, list) {
		if (p->plugin_state == NEEDS_INIT)
			plugin_config(p);
	}

	/* Wait for them to configure, before continuing: large
	 * nodes can take a while to startup! */
	if (plugins->startup) {
		/* This happens if an important plugin fails init,
		 * or if they call shutdown now. */
		if (io_loop_with_timers(plugins->ld) == plugins->ld)
			return false;
	}

	plugins->startup = false;
	return true;
}

struct plugin_set_return {
	struct command *cmd;
	const char *val;
	const char *optname;
	struct command_result *(*success)(struct command *,
					  const struct opt_table *,
					  const char *);
};

static void plugin_setconfig_done(const char *buffer,
				  const jsmntok_t *toks,
				  const jsmntok_t *idtok UNUSED,
				  struct plugin_set_return *psr)
{
	const jsmntok_t *t;
	const struct opt_table *ot;

	t = json_get_member(buffer, toks, "error");
	if (t) {
		const jsmntok_t *e;
		int ecode;

		e = json_get_member(buffer, t, "code");
		if (!e || !json_to_int(buffer, e, &ecode))
			goto bad_response;
		e = json_get_member(buffer, t, "message");
		if (!e)
			goto bad_response;
		was_pending(command_fail(psr->cmd, ecode, "%.*s",
					 e->end - e->start, buffer + e->start));
		return;
	}

	/* We have to look this up again, since a new plugin could have added some
	 * while we were in callback, and moved opt_table! */
	ot = opt_find_long(psr->optname, NULL);
	if (!ot) {
		log_broken(command_log(psr->cmd),
			   "Missing opt %s on plugin return?", psr->optname);
		was_pending(command_fail(psr->cmd, LIGHTNINGD,
					 "Missing opt %s on plugin return?", psr->optname));
		return;
	}

	t = json_get_member(buffer, toks, "result");
	if (!t)
		goto bad_response;
	was_pending(psr->success(psr->cmd, ot, psr->val));
	return;

bad_response:
	log_broken(command_log(psr->cmd),
		   "Invalid setconfig %s response from plugin: %.*s",
		   psr->optname,
		   json_tok_full_len(toks), json_tok_full(buffer, toks));
	was_pending(command_fail(psr->cmd, LIGHTNINGD,
				 "Malformed setvalue %s plugin return", psr->optname));
}

struct command_result *plugin_set_dynamic_opt(struct command *cmd,
					      const struct opt_table *ot,
					      const char *val,
					      struct command_result *(*success)
					      (struct command *,
					       const struct opt_table *,
					       const char *))
{
	struct plugin_opt *popt;
	struct plugin *plugin;
	struct jsonrpc_request *req;
	struct plugin_set_return *psr;

	plugin = plugin_opt_find_any(cmd->ld->plugins, ot, &popt);
	assert(plugin);

	assert(ot->type & OPT_DYNAMIC);

	psr = tal(cmd, struct plugin_set_return);
	psr->cmd = cmd;
	/* val is a child of cmd, so no copy needed. */
	psr->val = val;
	psr->optname = tal_strdup(psr, ot->names + 2);
	psr->success = success;

	if (command_check_only(cmd)) {
		/* If plugin doesn't support check, we can't check */
		if (!plugin->can_check)
			return command_check_done(cmd);
		req = jsonrpc_request_start(cmd, "check",
					    cmd->id,
					    plugin->non_numeric_ids,
					    command_log(cmd),
					    NULL, plugin_setconfig_done,
					    psr);
		json_add_string(req->stream, "command_to_check", "setconfig");
	} else {
		req = jsonrpc_request_start(cmd, "setconfig",
					    cmd->id,
					    plugin->non_numeric_ids,
					    command_log(cmd),
					    NULL, plugin_setconfig_done,
					    psr);
	}
	json_add_string(req->stream, "config", psr->optname);
	if (psr->val)
		json_add_string(req->stream, "val", psr->val);
	jsonrpc_request_end(req);
	plugin_request_send(plugin, req);
	return command_still_pending(cmd);
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
			json_add_plugin_options(response, "options", p, false);
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
	for (size_t i = 0; i < tal_count(plugin->subscriptions); i++) {
		if (streq(method, plugin->subscriptions[i])
		    || is_asterix_notification(method,
					       plugin->subscriptions[i]))
			return true;
	}

	return false;
}

bool plugin_single_notify(struct plugin *p,
			  const struct jsonrpc_notification *n TAKES)
{
	bool interested;
	if (p->plugin_state == INIT_COMPLETE && plugin_subscriptions_contains(p, n->method)) {
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

void plugin_request_send(struct plugin *plugin,
			 struct jsonrpc_request *req)
{
	/* Add to map so we can find it later when routing the response */
	strmap_add(&plugin->pending_requests, req->id, req);
	/* Add destructor in case request is freed. */
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

	/* We don't want to try to open another transaction: we're in one! */
	plugins[0]->plugins->want_db_transaction = false;
	/* We don't service timers here, either! */
	ret = io_loop(NULL, NULL);
	plugins[0]->plugins->want_db_transaction = true;
	log_debug(plugins[0]->plugins->ld->log, "io_loop: %s", __func__);

	for (i = 0; i < tal_count(plugins); ++i) {
		io_conn_out_exclusive(plugins[i]->stdin_conn, false);
		last = io_conn_exclusive(plugins[i]->stdout_conn, false);
	}
	if (last)
		fatal("Still io_exclusive after removing plugin %s?",
		      plugins[tal_count(plugins) - 1]->cmd);

	return ret;
}

struct logger *plugin_get_logger(struct plugin *plugin)
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
				/* important = */
				!streq(list_of_builtin_plugins[i], "cln-renepay"),
				NULL, NULL);
}

void shutdown_plugins(struct lightningd *ld)
{
	struct plugin *p, *next;

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
