#include <common/memleak.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/plugin_hook.h>
#include <wallet/db.h>

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
	void *response = r->hook->deserialize_response(r, buffer, toks);
	db_begin_transaction(r->db);
	r->hook->response_cb(r->cb_arg, response);
	db_commit_transaction(r->db);
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
					    plugin_hook_callback, ph_req);
		ph_req->hook = hook;
		ph_req->cb_arg = cb_arg;
		ph_req->db = ld->db;
		hook->serialize_payload(payload, req->stream);
		jsonrpc_request_end(req);
		plugin_request_send(hook->plugin, req);
	} else {
		/* If no plugin has registered for this hook, just
		 * call the callback with a NULL result. Safes us the
		 * roundtrip to the serializer and deserializer. If we
		 * were expecting a default response it should have
		 * been part of the `cb_arg`. */
		hook->response_cb(cb_arg, NULL);
	}
}
