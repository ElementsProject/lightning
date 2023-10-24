#include "config.h"
#include <ccan/io/io.h>
#include <ccan/tal/str/str.h>
#include <common/json_parse.h>
#include <common/memleak.h>
#include <db/exec.h>
#include <db/utils.h>
#include <lightningd/plugin_hook.h>

/* Struct containing all the information needed to deserialize and
 * dispatch an eventual plugin_hook response. */
struct plugin_hook_request {
	const char *cmd_id;
	const struct plugin_hook *hook;
	void *cb_arg;
	/* db_hook doesn't have ld yet */
	struct db *db;
	struct lightningd *ld;

	/* Where are we up to in the hooks[] array below */
	size_t hook_index;
	/* A snapshot taken at the start: destructors may NULL some out! */
	struct hook_instance **hooks;
};

static void destroy_hook_in_ph_req(struct hook_instance *hook,
				   struct plugin_hook_request *ph_req)
{
	for (size_t i = 0; i < tal_count(ph_req->hooks); i++) {
		if (ph_req->hooks[i] == hook) {
			ph_req->hooks[i] = NULL;
			return;
		}
	}
	abort();
}

struct hook_instance {
	/* What plugin registered */
	struct plugin *plugin;

	/* Dependencies it asked for. */
	const char **before, **after;
};

static struct plugin_hook **get_hooks(size_t *num)
{
	static struct plugin_hook **hooks = NULL;
	static size_t num_hooks;
	if (!hooks)
		hooks = autodata_get(hooks, &num_hooks);
	*num = num_hooks;
	return hooks;
}

static struct plugin_hook *plugin_hook_by_name(const char *name)
{
	size_t num_hooks;
	struct plugin_hook **hooks = get_hooks(&num_hooks);

	for (size_t i=0; i<num_hooks; i++)
		if (streq(hooks[i]->name, name))
			return hooks[i];
	return NULL;
}

/* When we destroy a plugin, we remove its hooks */
static void destroy_hook_instance(struct hook_instance *h,
				  struct plugin_hook *hook)
{
	for (size_t i = 0; i < tal_count(hook->hooks); i++) {
		if (h == hook->hooks[i]) {
			tal_arr_remove(&hook->hooks, i);
			return;
		}
	}
	abort();
}

struct plugin_hook *plugin_hook_register(struct plugin *plugin, const char *method)
{
	struct hook_instance *h;
	struct plugin_hook *hook = plugin_hook_by_name(method);
	if (!hook) {
		/* No such hook name registered */
		return NULL;
	}

	/* Make sure the hook_elements array is initialized. */
	if (hook->hooks == NULL)
		hook->hooks = notleak(tal_arr(NULL, struct hook_instance *, 0));

	/* Ensure we don't register the same plugin multple times. */
	for (size_t i=0; i<tal_count(hook->hooks); i++)
		if (hook->hooks[i]->plugin == plugin)
			return NULL;

	/* Ok, we're sure they can register and they aren't yet registered, so
	 * register them. */
	h = tal(plugin, struct hook_instance);
	h->plugin = plugin;
	h->before = tal_arr(h, const char *, 0);
	h->after = tal_arr(h, const char *, 0);
	tal_add_destructor2(h, destroy_hook_instance, hook);

	tal_arr_expand(&hook->hooks, h);
	return hook;
}

/* Mutual recursion */
static void plugin_hook_call_next(struct plugin_hook_request *ph_req);
static void plugin_hook_callback(const char *buffer, const jsmntok_t *toks,
				 const jsmntok_t *idtok,
				 struct plugin_hook_request *r);

bool plugin_hook_continue(void *unused, const char *buffer, const jsmntok_t *toks)
{
	const jsmntok_t *resrestok = json_get_member(buffer, toks, "result");
	return resrestok && json_tok_streq(buffer, resrestok, "continue");
}

/**
 * Callback to be passed to the jsonrpc_request.
 *
 * Unbundles the arguments, deserializes the response and dispatches
 * it to the hook callback.
 */
static void plugin_hook_callback(const char *buffer, const jsmntok_t *toks,
				 const jsmntok_t *idtok,
				 struct plugin_hook_request *ph_req)
{
	const jsmntok_t *resulttok;
	const struct hook_instance *h;
	enum jsonrpc_errcode ecode;

	assert(ph_req->hook_index < tal_count(ph_req->hooks));
	h = ph_req->hooks[ph_req->hook_index];

	/* destructor NULLs out hooks[], but we get called first at the moment.
	 * We handle either */
	ecode = 0;
	json_scan(tmpctx, buffer, toks, "{error:{code:%}}",
		  JSON_SCAN(json_to_jsonrpc_errcode, &ecode));
	if (ecode == PLUGIN_TERMINATED)
		h = NULL;

	/* We really only handle plugins dying: other errors are fatal. */
	if (h) {
		log_debug(ph_req->ld->log,
			  "Plugin %s returned from %s hook call",
			  h->plugin->shortname, ph_req->hook->name);
		resulttok = json_get_member(buffer, toks, "result");
		if (!resulttok)
			fatal("Plugin %s for %s returned non-result response %.*s",
			      h->plugin->shortname,
			      ph_req->hook->name, toks->end - toks->start,
			      buffer + toks->start);

		if (!ph_req->hook->deserialize_cb(ph_req->cb_arg,
						  buffer, resulttok)) {
			tal_free(ph_req->cb_arg);
			goto cleanup;
		}
	} else {
		log_debug(ph_req->ld->log, "Plugin died from %s hook call",
			  ph_req->hook->name);
	}

	plugin_hook_call_next(ph_req);
	return;

cleanup:
	/* We need to remove the destructors from the remaining
	 * call-chain, otherwise they'd still be called when the
	 * plugin dies or we shut down. */
	for (size_t i=0; i<tal_count(ph_req->hooks); i++) {
		tal_del_destructor2(ph_req->hooks[i],
				    destroy_hook_in_ph_req, ph_req);
	}

	tal_free(ph_req);
}

static void plugin_hook_call_next(struct plugin_hook_request *ph_req)
{
	struct jsonrpc_request *req;
	const struct plugin_hook *hook = ph_req->hook;
	struct plugin *plugin;

	/* Find next non-NULL hook: call final if we're done */
	do {
		ph_req->hook_index++;
		if (ph_req->hook_index >= tal_count(ph_req->hooks)) {
			ph_req->hook->final_cb(ph_req->cb_arg);
			return;
		}
	} while (ph_req->hooks[ph_req->hook_index] == NULL);

	plugin = ph_req->hooks[ph_req->hook_index]->plugin;
	log_debug(ph_req->ld->log, "Calling %s hook of plugin %s",
		  ph_req->hook->name, plugin->shortname);
	req = jsonrpc_request_start(NULL, hook->name, ph_req->cmd_id,
				    plugin->non_numeric_ids,
				    plugin_get_logger(plugin),
				    NULL,
				    plugin_hook_callback, ph_req);

	hook->serialize_payload(ph_req->cb_arg, req->stream, plugin);
	jsonrpc_request_end(req);
	plugin_request_send(plugin, req);
}

bool plugin_hook_call_(struct lightningd *ld, const struct plugin_hook *hook,
		       const char *cmd_id TAKES,
		       tal_t *cb_arg STEALS)
{
	if (tal_count(hook->hooks)) {
		/* If we have a plugin that has registered for this
		 * hook, serialize and call it */
		/* FIXME: technically this is a leak, but we don't
		 * currently have a list to store these. We might want
		 * to eventually to inspect in-flight requests. */
		struct plugin_hook_request *ph_req;

		ph_req = notleak(tal(hook->hooks, struct plugin_hook_request));
		ph_req->hook = hook;
		ph_req->cb_arg = tal_steal(ph_req, cb_arg);
		ph_req->db = ld->wallet->db;
		ph_req->ld = ld;
		ph_req->cmd_id = tal_strdup_or_null(ph_req, cmd_id);
		ph_req->hooks = tal_dup_talarr(ph_req,
					       struct hook_instance *,
					       hook->hooks);
		/* If hook goes away, NULL out our snapshot */
		for (size_t i=0; i<tal_count(ph_req->hooks); i++)
			tal_add_destructor2(ph_req->hooks[i],
					    destroy_hook_in_ph_req, ph_req);
		ph_req->hook_index = -1;
		plugin_hook_call_next(ph_req);
		return false;
	} else {
		/* If no plugin has registered for this hook, just
		 * call the callback with a NULL result. Saves us the
		 * roundtrip to the serializer and deserializer. If we
		 * were expecting a default response it should have
		 * been part of the `cb_arg`. */
		hook->final_cb(cb_arg);
		return true;
	}
}

/* We open-code this, because it's just different and special enough to be
 * annoying, and to make it clear that it's totally synchronous. */

/* Special synchronous hook for db */
static struct plugin_hook db_write_hook = {"db_write", NULL, NULL};
AUTODATA(hooks, &db_write_hook);

/* A `db_write` for one particular plugin hook.  */
struct db_write_hook_req {
	struct plugin *plugin;
	struct plugin_hook_request *ph_req;
	size_t *num_hooks;
};

static void db_hook_response(const char *buffer, const jsmntok_t *toks,
			     const jsmntok_t *idtok,
			     struct db_write_hook_req *dwh_req)
{
	const jsmntok_t *resulttok;

	resulttok = json_get_member(buffer, toks, "result");
	if (!resulttok)
		fatal("Plugin '%s' returned an invalid response to the "
		      "db_write hook: %.*s",
		      dwh_req->plugin->cmd,
		      json_tok_full_len(toks),
		      json_tok_full(buffer, toks));

	/* We expect result: { 'result' : 'continue' }.
	 * Anything else we abort.
	 */
	resulttok = json_get_member(buffer, resulttok, "result");
	if (resulttok) {
		if (!json_tok_streq(buffer, resulttok, "continue"))
			fatal("Plugin '%s' returned failed db_write: %.*s.",
			      dwh_req->plugin->cmd,
			      json_tok_full_len(toks),
			      json_tok_full(buffer, toks));
	} else
		fatal("Plugin '%s' returned an invalid result to the db_write "
		      "hook: %.*s",
		      dwh_req->plugin->cmd,
		      json_tok_full_len(toks),
		      json_tok_full(buffer, toks));

	assert((*dwh_req->num_hooks) != 0);
	--(*dwh_req->num_hooks);
	/* If there are other runners, do not exit yet.  */
	if ((*dwh_req->num_hooks) != 0)
		return;

	/* We're done, exit exclusive loop. */
	log_debug(dwh_req->plugin->plugins->ld->log, "io_break: %s", __func__);
	io_break(dwh_req->ph_req);
}

void plugin_hook_db_sync(struct db *db)
{
	const struct plugin_hook *hook = &db_write_hook;
	struct jsonrpc_request *req;
	struct plugin_hook_request *ph_req;
	void *ret;
	struct plugin **plugin_arr;
	struct plugins *plugins;
	size_t i;
	size_t num_hooks;

	const char **changes = db_changes(db);
	num_hooks = tal_count(hook->hooks);
	if (num_hooks == 0)
		return;

	plugin_arr = notleak(tal_arr(NULL, struct plugin *,
				  num_hooks));
	for (i = 0; i < num_hooks; ++i)
		plugin_arr[i] = hook->hooks[i]->plugin;

	plugins = plugin_arr[0]->plugins;
	ph_req = notleak(tal(hook->hooks, struct plugin_hook_request));
	ph_req->hook = hook;
	ph_req->db = db;
	ph_req->cb_arg = &num_hooks;

	for (i = 0; i < num_hooks; ++i) {
		/* Create an object for this plugin.  */
		struct db_write_hook_req *dwh_req;
		dwh_req = tal(ph_req, struct db_write_hook_req);
		dwh_req->plugin = plugin_arr[i];
		dwh_req->ph_req = ph_req;
		dwh_req->num_hooks = &num_hooks;

		/* FIXME: id_prefix from caller? */
		/* FIXME: do IO logging for this! */
		req = jsonrpc_request_start(NULL, hook->name, NULL,
					    dwh_req->plugin->non_numeric_ids,
					    NULL, NULL,
					    db_hook_response,
					    dwh_req);

		json_add_num(req->stream, "data_version",
			     db_data_version_get(db));

		json_array_start(req->stream, "writes");
		for (size_t j = 0; j < tal_count(changes); j++)
			json_add_string(req->stream, NULL, changes[j]);
		json_array_end(req->stream);
		jsonrpc_request_end(req);

		plugin_request_send(plugin_arr[i], req);
	}

	ret = plugins_exclusive_loop(plugin_arr);

	/* We can be called on way out of an io_loop, which is already breaking.
	 * That will make this immediately return; save the break value and call
	 * again, then hand it onwards. */
	if (ret != ph_req) {
		void *ret2 = plugins_exclusive_loop(plugin_arr);
		assert(ret2 == ph_req);
		log_debug(plugins->ld->log, "io_break: %s", __func__);
		io_break(ret);
	}
	assert(num_hooks == 0);
	tal_free(plugin_arr);
	tal_free(ph_req);
}

static void add_deps(const char ***arr,
		     const char *buffer,
		     const jsmntok_t *arrtok)
{
	const jsmntok_t *t;
	size_t i;

	if (!arrtok)
		return;

	json_for_each_arr(i, t, arrtok)
		tal_arr_expand(arr, json_strdup(*arr, buffer, t));
}

void plugin_hook_add_deps(struct plugin_hook *hook,
			  struct plugin *plugin,
			  const char *buffer,
			  const jsmntok_t *before,
			  const jsmntok_t *after)
{
	struct hook_instance *h = NULL;

	/* We just added this, it must exist */
	for (size_t i = 0; i < tal_count(hook->hooks); i++) {
		if (hook->hooks[i]->plugin == plugin) {
			h = hook->hooks[i];
			break;
		}
	}
	assert(h);

	add_deps(&h->before, buffer, before);
	add_deps(&h->after, buffer, after);
}

struct hook_node {
	/* Is this copied into the ordered array yet? */
	bool finished;
	struct hook_instance *hook;
	size_t num_incoming;
	struct hook_node **outgoing;
};

static struct hook_node *find_hook(struct hook_node *graph, const char *name)
{
	for (size_t i = 0; i < tal_count(graph); i++) {
		if (plugin_paths_match(graph[i].hook->plugin->cmd, name))
			return graph + i;
	}
	return NULL;
}

/* Sometimes naive is best. */
static struct hook_node *get_best_candidate(struct hook_node *graph)
{
	struct hook_node *best = NULL;

	for (size_t i = 0; i < tal_count(graph); i++) {
		if (graph[i].finished)
			continue;
		if (graph[i].num_incoming != 0)
			continue;
		if (!best
		    || best->hook->plugin->index > graph[i].hook->plugin->index)
			best = &graph[i];
	}
	return best;
}

static struct plugin **plugin_hook_make_ordered(const tal_t *ctx,
						struct plugin_hook *hook)
{
	struct hook_node *graph, *n;
	struct hook_instance **done;

	/* Populate graph nodes */
	graph = tal_arr(tmpctx, struct hook_node, tal_count(hook->hooks));
	for (size_t i = 0; i < tal_count(graph); i++) {
		graph[i].finished = false;
		graph[i].hook = hook->hooks[i];
		graph[i].num_incoming = 0;
		graph[i].outgoing = tal_arr(graph, struct hook_node *, 0);
	}

	/* Add edges. */
	for (size_t i = 0; i < tal_count(graph); i++) {
		for (size_t j = 0; j < tal_count(graph[i].hook->before); j++) {
			n = find_hook(graph, graph[i].hook->before[j]);
			if (!n) {
				/* This is useful for typos! */
				log_debug(graph[i].hook->plugin->log,
					  "hook %s before unknown plugin %s",
					  hook->name,
					  graph[i].hook->before[j]);
				continue;
			}
			tal_arr_expand(&graph[i].outgoing, n);
			n->num_incoming++;
		}
		for (size_t j = 0; j < tal_count(graph[i].hook->after); j++) {
			n = find_hook(graph, graph[i].hook->after[j]);
			if (!n) {
				/* This is useful for typos! */
				log_debug(graph[i].hook->plugin->log,
					  "hook %s after unknown plugin %s",
					  hook->name,
					  graph[i].hook->after[j]);
				continue;
			}
			tal_arr_expand(&n->outgoing, &graph[i]);
			graph[i].num_incoming++;
		}
	}

	done = tal_arr(tmpctx, struct hook_instance *, 0);
	while ((n = get_best_candidate(graph)) != NULL) {
		tal_arr_expand(&done, n->hook);
		n->finished = true;
		for (size_t i = 0; i < tal_count(n->outgoing); i++)
			n->outgoing[i]->num_incoming--;
	}

	if (tal_count(done) != tal_count(hook->hooks)) {
		struct plugin **ret = tal_arr(ctx, struct plugin *, 0);
		for (size_t i = 0; i < tal_count(graph); i++) {
			if (!graph[i].finished)
				tal_arr_expand(&ret, graph[i].hook->plugin);
		}
		return ret;
	}

	/* Success!  Copy ordered hooks back. */
	if (hook->hooks)
		memcpy(hook->hooks, done, tal_bytelen(hook->hooks));
	return NULL;
}

/* Plugins could fail due to multiple hooks, but only add once. */
static void append_plugin_once(struct plugin ***ret, struct plugin *p)
{
	for (size_t i = 0; i < tal_count(*ret); i++) {
		if ((*ret)[i] == p)
			return;
	}
	tal_arr_expand(ret, p);
}

struct plugin **plugin_hooks_make_ordered(const tal_t *ctx)
{
	size_t num_hooks;
	struct plugin_hook **hooks = get_hooks(&num_hooks);
	struct plugin **ret = tal_arr(ctx, struct plugin *, 0);

	for (size_t i=0; i<num_hooks; i++) {
		struct plugin **these = plugin_hook_make_ordered(ctx, hooks[i]);
		for (size_t j = 0; j < tal_count(these); j++)
			append_plugin_once(&ret, these[j]);
	}

	return ret;
}
