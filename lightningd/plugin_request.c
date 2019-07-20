#include <ccan/io/io.h>
#include <ccan/time/time.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <common/utils.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/plugin_request.h>
#include <wallet/db.h>

/* the same as BITCOIND_MAX_PARALLEL */
#define LIGHTNINGD_PLUGIN_REQUEST_MAX_PARALLEL 4

static struct plugin_request *plugin_request_by_name(const char *name)
{
	static struct plugin_request **requests = NULL;
	static size_t num_requests;
	if (!requests)
		requests = autodata_get(requests, &num_requests);

	for (size_t i=0; i<num_requests; i++)
		if (streq(requests[i]->name, name))
			return requests[i];
	return NULL;
}

bool plugin_request_register(struct plugin *plugin, const char *method)
{
	struct plugin_request *request = plugin_request_by_name(method);
	if (!request) {
		/* No such request name registered */
		return false;
	} else if (request->plugin != NULL) {
		/* Another plugin already registered for this name */
		return false;
	}
	request->plugin = plugin;
	return true;
}

/* FIXME: Remove dummy hook, once we have a real one */
REGISTER_PLUGIN_REQUEST(hello, NULL, void *, NULL, void *);

/* Struct containing all the information needed to deserialize and
 * dispatch an eventual plugin_request response. */
struct plugin_request_req {
	struct list_node list;
	struct plugin_request_manager *req_manager;
	const struct plugin_request *request;
	void *payload;
	struct timeabs start;
	enum request_async_prio prio;
	void *cb_arg;
	bool (*process)(void *arg, const char *buffer, const jsmntok_t *resulttoks);
	struct db *db;
	struct plugin_request_req **stopper;
	struct oneshot *reply_timer;
	/* It is also used as stopper */
	u64 *reply_timeout;
};

static void next_plugin_request(struct plugin_request_manager *manager,
				enum request_async_prio prio);

static void retry_plugin_request(struct plugin_request_req *req)
{
	list_add_tail(&req->req_manager->pending[req->prio], &req->list);
	next_plugin_request(req->req_manager, req->prio);
}

static bool process_donothing(void *arg UNUSED, const char *buffer UNUSED,
			      const jsmntok_t *resulttoks UNUSED)
{
	return true;
}

/* If stopper gets freed first, set process() to a noop. */
static void stop_process_plugin_request(struct plugin_request_req **stopper)
{
	(*stopper)->process = process_donothing;
	(*stopper)->stopper = NULL;
}

/* It command finishes first, free stopper. */
static void remove_stopper(struct plugin_request_req *req)
{
	/* Calls stop_process_bcli, but we don't care. */
	tal_free(req->stopper);
}

/* We allow 60 seconds of spurious errors, eg. reorg. */
static void plugin_request_failure(struct plugin_request_req *req)
{
	struct timerel t;
	struct plugin_request_manager *manager = req->req_manager;

	if (!manager->error_count)
		manager->first_error_time = time_mono();

	t = timemono_between(time_mono(), manager->first_error_time);
	if (time_greater(t, time_from_sec(manager->retry_timeout)))
		fatal("plugin_request %s: plugin connect error "
		      "(after %u other errors) for %"PRIu64" seconds",
		      req->request->name,
		      manager->error_count,
		      manager->retry_timeout);

	log_unusual(req->request->plugin->log,
		    "plugin_request %s: plugin connect error",
		    req->request->name);

	manager->error_count++;

	/* Retry in 1 second (not a leak!) */
	new_reltimer(manager->plugins->ld->timers, notleak(req),
		     time_from_sec(1),
		     retry_plugin_request, req);
}

static struct plugin_request_req *plugin_request_dup(const tal_t *ctx,
				      struct plugin_request_req *req)
{
	struct plugin_request_req *new_req;
	/* FIXME: technically this is a leak, but we don't
	 * currently have a list to store these. We might want
	 * to eventually to inspect in-flight requests. */
	new_req = notleak(tal(ctx, struct plugin_request_req));
	new_req->req_manager = req->req_manager;
	new_req->prio = req->prio;
	new_req->request = req->request;
	new_req->payload = req->payload;
	new_req->cb_arg = req->cb_arg;
	new_req->process = new_req->process;
	new_req->db = req->db;

	/* Use reply_timeout as stopper! */
	if(req->reply_timeout) {
		new_req->reply_timeout = tal_dup(new_req,
						 u64,
						 req->reply_timeout);
		/* Create child whose destructor will stop us calling */
		new_req->stopper = tal_dup(new_req->reply_timeout,
					   struct plugin_request_req *,
					   req->stopper);
		tal_add_destructor(new_req->stopper,
				   stop_process_plugin_request);
		tal_add_destructor(new_req, remove_stopper);
	} else {
		new_req->reply_timeout = NULL;
		new_req->stopper = NULL;
	}
	new_req->reply_timer = NULL;

	return new_req;
}

static void plugin_request_timeout(struct plugin_request_req *req)
{
	struct plugin_request_manager *manager = req->req_manager;
	struct plugin_request_req *new_req;

	req->reply_timer = NULL;
	manager->error_count++;
	if (manager->error_count >= 3) {
		tal_del_destructor(req->stopper,
				   stop_process_plugin_request);
		tal_del_destructor(req, remove_stopper);
		/* Clean stopper. */
		req->reply_timeout = tal_free(req->reply_timeout);
		req->stopper = NULL;
		plugin_request_failure(req);
	}
	new_req = plugin_request_dup(req->request->plugin, req);
	/* Stop original req and try the new one after 1 second*/
	tal_free(req->reply_timeout);
	new_reltimer(manager->plugins->ld->timers, notleak(new_req),
		     time_from_sec(1),
		     retry_plugin_request, new_req);
}

static void send_plugin_request(struct plugin_request_req *pr_req);

static void next_plugin_request(struct plugin_request_manager *manager,
			        enum request_async_prio prio)
{
	struct plugin_request_req *req;
	struct timers *timers = manager->plugins->ld->timers;

	if (manager->num_requests[prio] >=
			LIGHTNINGD_PLUGIN_REQUEST_MAX_PARALLEL)
		return;

	req = list_pop(&manager->pending[prio],
		       struct plugin_request_req,
		       list);
	if (!req)
		return;

	send_plugin_request(req);

	req->start = time_now();
	if (req->reply_timeout)
		req->reply_timer = new_reltimer(timers,
						notleak(req),
						time_from_sec(*req->reply_timeout),
						plugin_request_timeout, req);
	manager->num_requests[prio]++;
}

/**
 * Callback to be passed to the jsonrpc_request.
 *
 * Unbundles the arguments, deserializes the response and dispatches
 * it to the request callback.
 */
static void plugin_request_callback(const char *buffer,
				    const jsmntok_t *toks,
				    const jsmntok_t *idtok,
				    struct plugin_request_req *req)
{
	bool ok;
	enum request_async_prio prio = req->prio;
	struct plugin_request_manager *manager = req->req_manager;
	bool (*process)(void *arg, const char *buffer,
			const jsmntok_t *toks) = req->process;
	u64 msec = time_to_msec(time_between(time_now(), req->start));

	if (req->reply_timer)
		req->reply_timer = tal_free(req->reply_timer);

	/* If it took over 10 seconds, that's rather strange. */
	if (msec > 10000)
		log_unusual(req->request->plugin->log,
			    "plugin_request %s: finished"
			    " (%"PRIu64" ms)",
			    req->request->name, msec);

	assert(manager->num_requests[prio] > 0);
	manager->num_requests[prio]--;

	const jsmntok_t *resulttok = json_get_member(buffer,
						     toks,
						     "result");

	if (!resulttok)
		fatal("Plugin for %s returned neither non-result %.*s",
		      req->request->name,
		      toks->end - toks->start,
		      buffer + toks->start);

	if (manager->shutdown)
		return;

	db_begin_transaction(req->db);
	ok = process(req->cb_arg, buffer, resulttok);
	db_commit_transaction(req->db);

	if (!ok)
		plugin_request_failure(req);
	else
		tal_free(req);

	next_plugin_request(manager, prio);
}

static void send_plugin_request(struct plugin_request_req *pr_req)
{
	struct jsonrpc_request *req;
	const struct plugin_request *request = pr_req->request;

	req = jsonrpc_request_start(NULL, request->name,
				    plugin_get_log(request->plugin),
				    plugin_request_callback, pr_req);
	request->serialize_payload(pr_req->payload, req->stream);
	jsonrpc_request_end(req);
	plugin_method_send(request->plugin, req);
}

/* If ctx is non-NULL, and is freed before we return, we don't call process().
 * process returns false() if it's a spurious error, and we should retry. */
void plugin_request_call_(struct lightningd *ld,
			  const struct plugin_request *request,
			  void *payload, void *cb_arg,
			  enum request_async_prio prio,
			  u64 *reply_timeout)
{
	struct plugin_request_manager *manager;
	struct plugin_request_req *req;

	if (!request->plugin) {
		/* Must return true if no plugin regists. */
		if(request->response_cb(cb_arg, NULL, NULL))
			return;
	}

	/* If we have a plugin that has registered for this
	 * request, serialize and call it */

	manager = request->plugin->plugins->pr_manager;
	/* FIXME: technically this is a leak, but we don't
	 * currently have a list to store these. We might want
	 * to eventually to inspect in-flight requests. */
	req = notleak(tal(request->plugin,
		      struct plugin_request_req));
	req->req_manager = manager;
	req->prio = prio;
	req->request = request;
	req->payload = payload;
	req->cb_arg = cb_arg;
	req->process = request->response_cb;
	req->db = ld->wallet->db;

	/* Use reply_timeout as stopper! */
	if(reply_timeout) {
		req->reply_timeout = tal_steal(req, reply_timeout);
		/* Create child whose destructor will stop us calling */
		req->stopper = tal(req->reply_timeout,
				   struct plugin_request_req *);
		*req->stopper = req;
		tal_add_destructor(req->stopper,
				   stop_process_plugin_request);
		tal_add_destructor(req, remove_stopper);
	} else {
		req->reply_timeout = NULL;
		req->stopper = NULL;
	}
	req->reply_timer = NULL;

	list_add_tail(&manager->pending[req->prio], &req->list);
	next_plugin_request(manager, req->prio);
}

static void
destroy_plugin_request_manager(struct plugin_request_manager *manager)
{
	/* Suppresses the callbacks from plugin_request_callback as we free conns. */
	manager->shutdown = true;
}

struct plugin_request_manager *new_plugin_request_manager(
			       const tal_t *ctx,
			       struct plugins *plugins)
{
	struct plugin_request_manager *manager;

	manager = tal(ctx, struct plugin_request_manager);
	manager->plugins = plugins;
	for (size_t i = 0; i < LIGHTNINGD_PLUGIN_REQUEST_NUM_PRIO; i++) {
		manager->num_requests[i] = 0;
		list_head_init(&manager->pending[i]);
	}
	manager->shutdown = false;
	manager->error_count = 0;
	manager->retry_timeout = 60;

	tal_add_destructor(manager, destroy_plugin_request_manager);

	return manager;
}
