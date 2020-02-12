#include <ccan/io/io.h>
#include <ccan/list/list.h>
#include <common/configdir.h>
#include <common/memleak.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/plugin_hook.h>
#include <wallet/db.h>
#include <wallet/db_common.h>

/* Struct containing all the information needed to deserialize and
 * dispatch an eventual plugin_hook response. */
struct plugin_hook_request {
	struct list_head call_chain;
	struct plugin *plugin;
	int current_plugin;
	const struct plugin_hook *hook;
	void *cb_arg;
	void *payload;
	struct db *db;
};

/* A link in the plugin_hook call chain (there's a joke in there about
 * computer scientists and naming...). The purpose is to act both as a list
 * from which elements can be popped off as we progress along the chain as
 * well as have a way for plugins to notify about their untimely demise during
 * a hook call.
 */
struct plugin_hook_call_link {
	struct list_node list;
	struct plugin *plugin;
	struct plugin_hook_request *req;
};

static struct plugin_hook *plugin_hook_by_name(const char *name)
{
	static struct plugin_hook **hooks = NULL;
	static size_t num_hooks;
	if (!hooks)
		hooks = autodata_get(hooks, &num_hooks);

	for (size_t i=0; i<num_hooks; i++)
		if (streq(hooks[i]->name, name))
			return hooks[i];
	return NULL;
}

bool plugin_hook_register(struct plugin *plugin, const char *method)
{
	struct plugin_hook *hook = plugin_hook_by_name(method);
	if (!hook) {
		/* No such hook name registered */
		return false;
	}

	/* Make sure the plugins array is initialized. */
	if (hook->plugins == NULL)
		hook->plugins = notleak(tal_arr(NULL, struct plugin *, 0));

	/* If this is a single type hook and we have a plugin registered we
	 * must fail this attempt to add the plugin to the hook. */
	if (hook->type == PLUGIN_HOOK_SINGLE && tal_count(hook->plugins) > 0)
		return false;

	/* Ensure we don't register the same plugin multple times. */
	for (size_t i=0; i<tal_count(hook->plugins); i++)
		if (hook->plugins[i] == plugin)
			return true;

	/* Ok, we're sure they can register and they aren't yet registered, so
	 * register them. */
	tal_arr_expand(&hook->plugins, plugin);
	return true;
}

bool plugin_hook_unregister(struct plugin *plugin, const char *method)
{
	struct plugin_hook *hook = plugin_hook_by_name(method);

	if (!hook || !hook->plugins) {
		/* No such hook name registered */
		return false;
	}

	for (size_t i = 0; i < tal_count(hook->plugins); i++) {
		if (hook->plugins[i] == plugin) {
			tal_arr_remove(&hook->plugins, i);
			return true;
		}
	}
	return false;
}

void plugin_hook_unregister_all(struct plugin *plugin)
{
	static struct plugin_hook **hooks = NULL;
	static size_t num_hooks;
	if (!hooks)
		hooks = autodata_get(hooks, &num_hooks);

	for (size_t i = 0; i < num_hooks; i++)
		plugin_hook_unregister(plugin, hooks[i]->name);
}

/* Mutual recursion */
static void plugin_hook_call_next(struct plugin_hook_request *ph_req);
static void plugin_hook_callback(const char *buffer, const jsmntok_t *toks,
				 const jsmntok_t *idtok,
				 struct plugin_hook_request *r);

/* We get notified if a plugin was killed while it was part of a call
 * chain. If it was still to be called we just remove it from the list,
 * otherwise it was the plugin that was currently handling the hook call, and
 * we need to fail over to the next plugin.
*/
static void plugin_hook_killed(struct plugin_hook_call_link *link)
{
	struct plugin_hook_call_link *head;

	head = list_top(&link->req->call_chain, struct plugin_hook_call_link,
			list);

	/* If we are the head of the call chain, then the plugin died while it
	 * was handling the hook call. Pretend it didn't get the memo by
	 * calling the next one instead. This is correct since it is
	 * equivalent to the plugin dying before the hook invokation, assuming
	 * the plugin has not commmitted any changes internally. This is the
	 * weakest assumption we can make short of restarting the plugin and
	 * calling the hook again (potentially crashing the plugin the same
	 * way again.
	 */
	if (link == head) {
		/* Call next will unlink, so we don't need to. This is treated
		 * equivalent to the plugin returning a continue-result.
		 */
		link->req->current_plugin--;
		plugin_hook_callback(NULL, NULL, NULL, link->req);
	} else {
		/* The plugin is in the list waiting to be called, just remove
		 * it from the list. */
		list_del(&link->list);
	}
}

/**
 * Callback to be passed to the jsonrpc_request.
 *
 * Unbundles the arguments, deserializes the response and dispatches
 * it to the hook callback.
 */
static void plugin_hook_callback(const char *buffer, const jsmntok_t *toks,
				 const jsmntok_t *idtok,
				 struct plugin_hook_request *r)
{
	const jsmntok_t *resulttok, *resrestok;
	struct db *db = r->db;
	bool more_plugins, cont;
	struct plugin_hook_call_link *last;

	/* Pop the head off the call chain and continue with the next */
	last = list_pop(&r->call_chain, struct plugin_hook_call_link, list);
	assert(last != NULL);
	tal_del_destructor(last, plugin_hook_killed);
	tal_free(last);

	if (buffer) {
		resulttok = json_get_member(buffer, toks, "result");

		if (!resulttok)
			fatal("Plugin for %s returned non-result response %.*s",
			      r->hook->name, toks->end - toks->start,
			      buffer + toks->start);

		resrestok = json_get_member(buffer, resulttok, "result");
	} else {
		/* Buffer and / or resulttok could be used by the reponse_cb
		 * to identify no-result responses. So make sure both are
		 * set */
		resulttok = NULL;
		/* cppcheck isn't smart enough to notice that `resrestok`
		 * doesn't need to be initialized in the expression
		 * initializing `cont`, so set it to NULL to shut it up. */
		resrestok = NULL;
	}

	more_plugins = r->current_plugin + 1 < tal_count(r->hook->plugins);
	cont = buffer == NULL || (resrestok && json_tok_streq(buffer, resrestok, "continue"));

	/* If this is a hook response containing a `continue` and we have more
	 * plugins queue the next call. In that case we discard the remainder
	 * of the result, and let the next plugin decide. */
	if (cont && more_plugins) {
		plugin_hook_call_next(r);
	} else {
		db_begin_transaction(db);
		r->hook->response_cb(r->cb_arg, buffer, resulttok);
		db_commit_transaction(db);
		tal_free(r);
	}
}

static void plugin_hook_call_next(struct plugin_hook_request *ph_req)
{
	struct jsonrpc_request *req;
	const struct plugin_hook *hook = ph_req->hook;
	ph_req->current_plugin++;
	assert(ph_req->current_plugin < tal_count(hook->plugins));
	ph_req->plugin = ph_req->hook->plugins[ph_req->current_plugin];

	req = jsonrpc_request_start(NULL, hook->name,
				    plugin_get_log(ph_req->plugin),
				    plugin_hook_callback, ph_req);

	hook->serialize_payload(ph_req->payload, req->stream);
	jsonrpc_request_end(req);
	plugin_request_send(ph_req->plugin, req);
}

void plugin_hook_call_(struct lightningd *ld, const struct plugin_hook *hook,
		       void *payload, void *cb_arg)
{
	struct plugin_hook_request *ph_req;
	struct plugin_hook_call_link *link;
	if (tal_count(hook->plugins)) {
		/* If we have a plugin that has registered for this
		 * hook, serialize and call it */
		/* FIXME: technically this is a leak, but we don't
		 * currently have a list to store these. We might want
		 * to eventually to inspect in-flight requests. */
		ph_req = notleak(tal(hook->plugins, struct plugin_hook_request));
		ph_req->hook = hook;
		ph_req->cb_arg = cb_arg;
		ph_req->db = ld->wallet->db;
		ph_req->payload = tal_steal(ph_req, payload);
		ph_req->current_plugin = -1;

		list_head_init(&ph_req->call_chain);
		for (size_t i=0; i<tal_count(hook->plugins); i++) {
			/* We allocate this off of the plugin so we get notified if the plugin dies. */
			link = tal(hook->plugins[i], struct plugin_hook_call_link);
			link->plugin = hook->plugins[i];
			link->req = ph_req;
			tal_add_destructor(link, plugin_hook_killed);
			list_add_tail(&ph_req->call_chain, &link->list);
		}
		plugin_hook_call_next(ph_req);
	} else {
		/* If no plugin has registered for this hook, just
		 * call the callback with a NULL result. Saves us the
		 * roundtrip to the serializer and deserializer. If we
		 * were expecting a default response it should have
		 * been part of the `cb_arg`. */
		hook->response_cb(cb_arg, NULL, NULL);
	}
}

/* We open-code this, because it's just different and special enough to be
 * annoying, and to make it clear that it's totally synchronous. */

/* Special synchronous hook for db */
static struct plugin_hook db_write_hook = {"db_write", PLUGIN_HOOK_SINGLE, NULL,
					   NULL, NULL};
AUTODATA(hooks, &db_write_hook);

static void db_hook_response(const char *buffer, const jsmntok_t *toks,
			     const jsmntok_t *idtok,
			     struct plugin_hook_request *ph_req)
{
	const jsmntok_t *resulttok;

	resulttok = json_get_member(buffer, toks, "result");
	if (!resulttok)
		fatal("Plugin returned an invalid response to the db_write "
		      "hook: %s", buffer);

#ifdef COMPAT_V080
	/* For back-compatibility we allow to return a simple Boolean true.  */
	if (deprecated_apis) {
		bool resp;
		if (json_to_bool(buffer, resulttok, &resp)) {
			static bool warned = false;
			/* If it fails, we must not commit to our db. */
			if (!resp)
				fatal("Plugin returned failed db_write: %s.",
				      buffer);
			if (!warned) {
				warned = true;
				log_unusual(ph_req->db->log,
					    "Plugin returned 'true' to "
					    "'db_hook'.  "
					    "This is now deprecated and "
					    "you should return "
					    "{'result': 'continue'} "
					    "instead.");
			}
			/* Resume.  */
			io_break(ph_req);
			return;
		}
	}
#endif /* defined(COMPAT_V080) */

	/* We expect result: { 'result' : 'continue' }.
	 * Anything else we abort.
	 */
	resulttok = json_get_member(buffer, resulttok, "result");
	if (resulttok) {
		if (!json_tok_streq(buffer, resulttok, "continue"))
			fatal("Plugin returned failed db_write: %s.", buffer);
	} else
		fatal("Plugin returned an invalid result to the db_write "
		      "hook: %s", buffer);

	/* We're done, exit exclusive loop. */
	io_break(ph_req);
}

void plugin_hook_db_sync(struct db *db)
{
	const struct plugin_hook *hook = &db_write_hook;
	struct jsonrpc_request *req;
	struct plugin_hook_request *ph_req;
	void *ret;
	struct plugin *plugin;

	const char **changes = db_changes(db);
	if (tal_count(hook->plugins) == 0)
		return;

	ph_req = notleak(tal(hook->plugins, struct plugin_hook_request));
	/* FIXME: do IO logging for this! */
	req = jsonrpc_request_start(NULL, hook->name, NULL, db_hook_response,
				    ph_req);

	ph_req->hook = hook;
	ph_req->db = db;
	ph_req->current_plugin = 0;
	plugin = ph_req->plugin = hook->plugins[ph_req->current_plugin];

	json_add_num(req->stream, "data_version", db_data_version_get(db));

	json_array_start(req->stream, "writes");
	for (size_t i = 0; i < tal_count(changes); i++)
		json_add_string(req->stream, NULL, changes[i]);
	json_array_end(req->stream);
	jsonrpc_request_end(req);

	plugin_request_send(ph_req->plugin, req);

	/* We can be called on way out of an io_loop, which is already breaking.
	 * That will make this immediately return; save the break value and call
	 * again, then hand it onwards. */
	ret = plugin_exclusive_loop(plugin);
	if (ret != ph_req) {
		void *ret2 = plugin_exclusive_loop(plugin);
		assert(ret2 == ph_req);
		io_break(ret);
	}
}
