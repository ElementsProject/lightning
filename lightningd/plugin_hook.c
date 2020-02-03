#include <ccan/io/io.h>
#include <common/configdir.h>
#include <common/memleak.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/plugin_hook.h>
#include <wallet/db.h>
#include <wallet/db_common.h>

/* Struct containing all the information needed to deserialize and
 * dispatch an eventual plugin_hook response. */
struct plugin_hook_request {
	const struct plugin_hook *hook;
	void *cb_arg;
	struct db *db;
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
	} else if (hook->plugin != NULL) {
		/* Another plugin already registered for this name */
		return false;
	}
	hook->plugin = plugin;
	return true;
}

bool plugin_hook_unregister(struct plugin *plugin, const char *method)
{
	struct plugin_hook *hook = plugin_hook_by_name(method);
	if (!hook) {
		/* No such hook name registered */
		return false;
	} else if (hook->plugin == NULL) {
		/* This name is not registered */
		return false;
	}
	hook->plugin = NULL;
	return true;
}

void plugin_hook_unregister_all(struct plugin *plugin)
{
	static struct plugin_hook **hooks = NULL;
	static size_t num_hooks;
	if (!hooks)
		hooks = autodata_get(hooks, &num_hooks);

	for (size_t i = 0; i < num_hooks; i++)
		if (hooks[i]->plugin == plugin)
			hooks[i]->plugin = NULL;
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
	const jsmntok_t *resulttok = json_get_member(buffer, toks, "result");
	struct db *db = r->db;
	struct plugin_destroyed *pd;

	if (!resulttok)
		fatal("Plugin for %s returned non-result response %.*s",
		      r->hook->name,
		      toks->end - toks->start, buffer + toks->start);

	/* If command is "plugin stop", this can free r! */
	pd = plugin_detect_destruction(r->hook->plugin);
	db_begin_transaction(db);
	r->hook->response_cb(r->cb_arg, buffer, resulttok);
	db_commit_transaction(db);
	if (!was_plugin_destroyed(pd))
		tal_free(r);
}

void plugin_hook_call_(struct lightningd *ld, const struct plugin_hook *hook,
		       void *payload, void *cb_arg)
{
	struct jsonrpc_request *req;
	struct plugin_hook_request *ph_req;
	if (hook->plugin) {
		/* If we have a plugin that has registered for this
		 * hook, serialize and call it */
		/* FIXME: technically this is a leak, but we don't
		 * currently have a list to store these. We might want
		 * to eventually to inspect in-flight requests. */
		ph_req = notleak(tal(hook->plugin, struct plugin_hook_request));
		req = jsonrpc_request_start(NULL, hook->name,
					    plugin_get_log(hook->plugin),
					    plugin_hook_callback, ph_req);
		ph_req->hook = hook;
		ph_req->cb_arg = cb_arg;
		ph_req->db = ld->wallet->db;
		hook->serialize_payload(payload, req->stream);
		jsonrpc_request_end(req);
		plugin_request_send(hook->plugin, req);
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
static struct plugin_hook db_write_hook = { "db_write", NULL, NULL, NULL };
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

	const char **changes = db_changes(db);
	if (!hook->plugin)
		return;

	ph_req = notleak(tal(hook->plugin, struct plugin_hook_request));
	/* FIXME: do IO logging for this! */
	req = jsonrpc_request_start(NULL, hook->name, NULL, db_hook_response,
				    ph_req);

	ph_req->hook = hook;
	ph_req->db = db;

	json_add_num(req->stream, "data_version", db_data_version_get(db));

	json_array_start(req->stream, "writes");
	for (size_t i = 0; i < tal_count(changes); i++)
		json_add_string(req->stream, NULL, changes[i]);
	json_array_end(req->stream);
	jsonrpc_request_end(req);

	plugin_request_send(hook->plugin, req);

	/* We can be called on way out of an io_loop, which is already breaking.
	 * That will make this immediately return; save the break value and call
	 * again, then hand it onwards. */
	ret = plugin_exclusive_loop(hook->plugin);
	if (ret != ph_req) {
		void *ret2 = plugin_exclusive_loop(hook->plugin);
		assert(ret2 == ph_req);
		io_break(ret);
	}
}
