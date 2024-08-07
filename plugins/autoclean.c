#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/mem/mem.h>
#include <ccan/ptrint/ptrint.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <plugins/libplugin.h>

static u64 cycle_seconds = 3600;
static struct clean_info *timer_cinfo;
static struct plugin *plugin;
/* This is NULL if it's running now. */
static struct plugin_timer *cleantimer;
static u64 max_entries_per_call = 10000;

enum subsystem_type {
	FORWARDS,
	PAYS,
	INVOICES,
#define NUM_SUBSYSTEM_TYPES (INVOICES + 1)
};

enum subsystem_variant {
	SUCCESS,
	FAILURE
#define NUM_SUBSYSTEM_VARIANTS (FAILURE + 1)
};

struct per_subsystem;

/* About each subsystem.  Each one has two variants. */
struct subsystem_ops {
	/* "success" and "failure" names for JSON formatting. */
	const char *names[NUM_SUBSYSTEM_VARIANTS];

	/* name of system for wait and "list" */
	const char *system_name;

	/* Name of array inside "list" command return */
	const char *arr_name;

	/* Filter to use to restrict list to only necessary fields. */
	const char *list_filter;

	/* name of "del" command */
	const char *del_command;

	/* Figure out if this is a "success" or "failure" JSON entry,
	 * or neither.  Also grab timestamp */
	struct per_variant *(*get_variant)(const char *buf,
					   const jsmntok_t *t,
					   struct per_subsystem *subsystem,
					   u64 *timestamp);

	/* Add fields to delete this record */
	void (*add_del_fields)(struct out_req *req,
			       const char *buf,
			       const jsmntok_t *t);
};

struct subsystem_and_variant {
	enum subsystem_type type;
	enum subsystem_variant variant;
};

/* Forward declarations so we can put them in the table */
static struct per_variant *get_listinvoices_variant(const char *buf,
						    const jsmntok_t *t,
						    struct per_subsystem *subsystem,
						    u64 *timestamp);
static struct per_variant *get_listsendpays_variant(const char *buf,
						    const jsmntok_t *t,
						    struct per_subsystem *subsystem,
						    u64 *timestamp);
static struct per_variant *get_listforwards_variant(const char *buf,
						    const jsmntok_t *t,
						    struct per_subsystem *subsystem,
						    u64 *timestamp);
static void add_invoice_del_fields(struct out_req *req,
				   const char *buf,
				   const jsmntok_t *t);
static void add_sendpays_del_fields(struct out_req *req,
				    const char *buf,
				    const jsmntok_t *t);
static void add_forward_del_fields(struct out_req *req,
				   const char *buf,
				   const jsmntok_t *t);

static const struct subsystem_ops subsystem_ops[NUM_SUBSYSTEM_TYPES] = {
	{ {"succeededforwards", "failedforwards"},
	  "forwards",
	  "forwards",
	  "\"in_channel\":true,\"in_htlc_id\":true,\"resolved_time\":true,\"received_time\":true,\"status\":true",
	  "delforward",
	  get_listforwards_variant,
	  add_forward_del_fields,
	},
	{ {"succeededpays", "failedpays"},
	  "sendpays",
	  "payments",
	  "\"created_at\":true,\"status\":true,\"payment_hash\":true,\"groupid\":true,\"partid\":true",
	  "delpay",
	  get_listsendpays_variant,
	  add_sendpays_del_fields,
	},
	{ {"paidinvoices", "expiredinvoices"},
	  "invoices",
	  "invoices",
	  "\"label\":true,\"status\":true,\"expires_at\":true,\"paid_at\":true",
	  "delinvoice",
	  get_listinvoices_variant,
	  add_invoice_del_fields,
	},
};

static const char *subsystem_to_str(const struct subsystem_and_variant *sv)
{
	assert(sv->type >= 0 && sv->type < NUM_SUBSYSTEM_TYPES);
	assert(sv->variant >= 0 && sv->variant < NUM_SUBSYSTEM_VARIANTS);
	return subsystem_ops[sv->type].names[sv->variant];
}

/* Iterator helpers */
static struct subsystem_and_variant first_sv(void)
{
	struct subsystem_and_variant sv;
	sv.type = 0;
	sv.variant = 0;
	return sv;
}

static bool next_sv(struct subsystem_and_variant *sv)
{
	if (sv->variant == NUM_SUBSYSTEM_VARIANTS - 1) {
		sv->variant = 0;
		if (sv->type == NUM_SUBSYSTEM_TYPES - 1)
			return false;
		sv->type++;
		return true;
	}
	sv->variant++;
	return true;
}

static bool json_to_subsystem(const char *buffer, const jsmntok_t *tok,
			      struct subsystem_and_variant *sv)
{
	*sv = first_sv();
	do {
		if (memeqstr(buffer + tok->start, tok->end - tok->start,
			     subsystem_to_str(sv))) {
			return true;
		}
	} while (next_sv(sv));
	return false;
}

struct per_variant {
	/* Who are we?  Back pointer, so we can just pass this around */
	struct per_subsystem *per_subsystem;
	enum subsystem_variant variant;

	u64 age;
	u64 num_cleaned;
};

struct per_subsystem {
	/* Who are we?  Back pointer, so we can just pass this around */
	struct clean_info *cinfo;
	enum subsystem_type type;

	/* How far are we through the listing? */
	u64 offset, max;

	/* How many did we ignore? */
	u64 num_uncleaned;
	struct per_variant variants[NUM_SUBSYSTEM_VARIANTS];
};

/* Usually this refers to the global one, but for autoclean-once
 * it's a temporary. */
struct clean_info {
	struct command *cmd;
	size_t cleanup_reqs_remaining;

	struct per_subsystem per_subsystem[NUM_SUBSYSTEM_TYPES];
};

static struct per_subsystem *get_per_subsystem(struct clean_info *cinfo,
					       const struct subsystem_and_variant *sv)
{
	return &cinfo->per_subsystem[sv->type];
}

static struct per_variant *get_per_variant(struct clean_info *cinfo,
					   const struct subsystem_and_variant *sv)
{
	return &get_per_subsystem(cinfo, sv)->variants[sv->variant];
}

static const struct subsystem_ops *get_subsystem_ops(const struct per_subsystem *ps)
{
	return &subsystem_ops[ps->type];
}

/* Mutual recursion */
static void do_clean_timer(void *unused);
static struct command_result *do_clean(struct clean_info *cinfo);

static struct clean_info *new_clean_info(const tal_t *ctx,
					 struct command *cmd)
{
	struct clean_info *cinfo = tal(ctx, struct clean_info);
	cinfo->cmd = cmd;
	cinfo->cleanup_reqs_remaining = 0;

	for (enum subsystem_type i = 0; i < NUM_SUBSYSTEM_TYPES; i++) {
		struct per_subsystem *ps = &cinfo->per_subsystem[i];
		ps->cinfo = cinfo;
		ps->type = i;

		for (enum subsystem_variant j = 0; j < NUM_SUBSYSTEM_VARIANTS; j++) {
			struct per_variant *pv = &ps->variants[j];
			pv->per_subsystem = ps;
			pv->variant = j;

			pv->age = 0;
		}
	}
	return cinfo;
}

static u64 *total_cleaned(const struct subsystem_and_variant *sv)
{
	static u64 totals[NUM_SUBSYSTEM_TYPES][NUM_SUBSYSTEM_VARIANTS];

	return &totals[sv->type][sv->variant];
}

static const char *datastore_path(const tal_t *ctx,
				  const struct subsystem_and_variant *sv,
				  const char *field)
{
	return tal_fmt(ctx, "autoclean/%s/%s",
		       subsystem_to_str(sv), field);
}

static struct command_result *clean_finished(struct clean_info *cinfo)
{
	struct subsystem_and_variant sv = first_sv();
	do {
		size_t num_cleaned = get_per_variant(cinfo, &sv)->num_cleaned;

		if (!num_cleaned)
			continue;

		plugin_log(plugin, LOG_DBG, "cleaned %zu from %s",
			   num_cleaned, subsystem_to_str(&sv));
		*total_cleaned(&sv) += num_cleaned;
		jsonrpc_set_datastore_string(plugin, cinfo->cmd,
					     datastore_path(tmpctx, &sv, "num"),
					     tal_fmt(tmpctx, "%"PRIu64,
						     *total_cleaned(&sv)),
					     "create-or-replace", NULL, NULL, NULL);
	} while (next_sv(&sv));

	/* autoclean-once? */
	if (cinfo->cmd) {
		struct json_stream *response = jsonrpc_stream_success(cinfo->cmd);

		json_object_start(response, "autoclean");

		sv = first_sv();
		do {
			const struct per_variant *pv = get_per_variant(cinfo, &sv);
			if (pv->age == 0)
				continue;
			json_object_start(response, subsystem_to_str(&sv));
			json_add_u64(response, "cleaned", pv->num_cleaned);
			json_add_u64(response, "uncleaned",
				     get_per_subsystem(cinfo, &sv)->num_uncleaned);
			json_object_end(response);
		} while (next_sv(&sv));
		json_object_end(response);
		return command_finished(cinfo->cmd, response);
	} else { /* timer */
		plugin_log(plugin, LOG_DBG, "setting next timer");
		cleantimer = plugin_timer(plugin, time_from_sec(cycle_seconds),
					  do_clean_timer, NULL);
		return timer_complete(plugin);
	}
}

static struct command_result *clean_finished_one(struct clean_info *cinfo)
{
	assert(cinfo->cleanup_reqs_remaining != 0);
	if (--cinfo->cleanup_reqs_remaining > 0)
		return command_still_pending(cinfo->cmd);

	/* See if there are more entries we need to list. */
	return do_clean(cinfo);
}

static struct command_result *del_done(struct command *cmd,
				       const char *buf,
				       const jsmntok_t *result,
				       struct per_variant *variant)
{
	variant->num_cleaned++;
	return clean_finished_one(variant->per_subsystem->cinfo);
}

static struct command_result *del_failed(struct command *cmd,
					 const char *buf,
					 const jsmntok_t *result,
					 struct per_variant *variant)
{
	struct subsystem_and_variant sv;
	sv.variant = variant->variant;
	sv.type = variant->per_subsystem->type;

	plugin_log(plugin, LOG_UNUSUAL, "%s del failed: %.*s",
		   subsystem_to_str(&sv),
		   json_tok_full_len(result),
		   json_tok_full(buf, result));
	return clean_finished_one(variant->per_subsystem->cinfo);
}

static struct per_variant *get_listinvoices_variant(const char *buf,
						    const jsmntok_t *t,
						    struct per_subsystem *subsystem,
						    u64 *timestamp)
{
	struct per_variant *variant;
	const jsmntok_t *time, *status = json_get_member(buf, t, "status");

	if (json_tok_streq(buf, status, "expired")) {
		variant = &subsystem->variants[FAILURE];
		time = json_get_member(buf, t, "expires_at");
	} else if (json_tok_streq(buf, status, "paid")) {
		variant = &subsystem->variants[SUCCESS];
		time = json_get_member(buf, t, "paid_at");
	} else {
		return NULL;
	}

	if (!json_to_u64(buf, time, timestamp)) {
		plugin_err(plugin, "Bad invoice time '%.*s'",
			   json_tok_full_len(time),
			   json_tok_full(buf, time));
	}
	return variant;
}

static struct per_variant *get_listsendpays_variant(const char *buf,
						    const jsmntok_t *t,
						    struct per_subsystem *subsystem,
						    u64 *timestamp)
{
	struct per_variant *variant;
	const jsmntok_t *time, *status = json_get_member(buf, t, "status");

	if (json_tok_streq(buf, status, "failed")) {
		variant = &subsystem->variants[FAILURE];
	} else if (json_tok_streq(buf, status, "complete")) {
		variant = &subsystem->variants[SUCCESS];
	} else {
		return NULL;
	}

	time = json_get_member(buf, t, "created_at");
	if (!json_to_u64(buf, time, timestamp)) {
		plugin_err(plugin, "Bad created_at '%.*s'",
			   json_tok_full_len(time),
			   json_tok_full(buf, time));
	}
	return variant;
}

static struct per_variant *get_listforwards_variant(const char *buf,
						    const jsmntok_t *t,
						    struct per_subsystem *subsystem,
						    u64 *timestamp)
{
	struct per_variant *variant;
	const jsmntok_t *status = json_get_member(buf, t, "status");
	const char *timefield;
	jsmntok_t time;

	if (json_tok_streq(buf, status, "settled")) {
		timefield = "resolved_time";
		variant = &subsystem->variants[SUCCESS];
	} else if (json_tok_streq(buf, status, "failed")
		   || json_tok_streq(buf, status, "local_failed")) {
		variant = &subsystem->variants[FAILURE];
		/* There's no resolved_time for these, so use received */
		timefield = "received_time";
	} else {
		return NULL;
	}

	/* Check if we have a resolved_time, before making a decision
	 * on it. This is possible in older nodes that predate our
	 * annotations for forwards.*/
	if (json_get_member(buf, t, timefield) == NULL)
		return NULL;

	time = *json_get_member(buf, t, timefield);
	/* This is a float, so truncate at '.' */
	for (int off = time.start; off < time.end; off++) {
		if (buf[off] == '.')
			time.end = off;
	}

	if (!json_to_u64(buf, &time, timestamp)) {
		plugin_err(plugin, "Bad listforwards time '%.*s'",
			   json_tok_full_len(&time),
			   json_tok_full(buf, &time));
	}
	return variant;
}

static void add_invoice_del_fields(struct out_req *req,
				   const char *buf,
				   const jsmntok_t *t)
{
	const jsmntok_t *label = json_get_member(buf, t, "label");
	const jsmntok_t *status = json_get_member(buf, t, "status");

	json_add_tok(req->js, "label", label, buf);
	json_add_tok(req->js, "status", status, buf);
}

static void add_sendpays_del_fields(struct out_req *req,
				    const char *buf,
				    const jsmntok_t *t)
{
	const jsmntok_t *phash = json_get_member(buf, t, "payment_hash");
	const jsmntok_t *groupid = json_get_member(buf, t, "groupid");
	const jsmntok_t *partidtok = json_get_member(buf, t, "partid");
	const jsmntok_t *status = json_get_member(buf, t, "status");
	u64 partid;

	if (partidtok)
		json_to_u64(buf, partidtok, &partid);
	else
		partid = 0;

	json_add_tok(req->js, "payment_hash", phash, buf);
	json_add_tok(req->js, "status", status, buf);
	json_add_tok(req->js, "groupid", groupid, buf);
	json_add_u64(req->js, "partid", partid);
}

static void add_forward_del_fields(struct out_req *req,
				   const char *buf,
				   const jsmntok_t *t)
{
	const jsmntok_t *status = json_get_member(buf, t, "status");
	const jsmntok_t *inchan = json_get_member(buf, t, "in_channel");
	const jsmntok_t *inid = json_get_member(buf, t, "in_htlc_id");

	json_add_tok(req->js, "in_channel", inchan, buf);
	/* This can be missing if it was a forwards record from an old
	 * closed channel in version <= 0.12.1.  This is a special value
	 * but we will delete them *all*, resulting in some failures! */
#ifdef COMPAT_V0121
	if (!inid)
		json_add_u64(req->js, "in_htlc_id", -1ULL);
	else
#endif
		json_add_tok(req->js, "in_htlc_id", inid, buf);
	json_add_tok(req->js, "status", status, buf);
}

static struct command_result *list_done(struct command *cmd,
					const char *buf,
					const jsmntok_t *result,
					struct per_subsystem *subsystem)
{
	const struct subsystem_ops *ops = get_subsystem_ops(subsystem);
	const jsmntok_t *t, *inv = json_get_member(buf, result, ops->arr_name);
	size_t i;
	u64 now = time_now().ts.tv_sec;

	json_for_each_arr(i, t, inv) {
		struct per_variant *variant;
		u64 timestamp;
		struct out_req *req;

		variant = ops->get_variant(buf, t, subsystem, &timestamp);
		if (!variant) {
			subsystem->num_uncleaned++;
			continue;
		}

		/* Continue if we don't care. */
		if (variant->age == 0) {
			subsystem->num_uncleaned++;
			continue;
		}

		if (timestamp > now - variant->age) {
			subsystem->num_uncleaned++;
			continue;
		}

		subsystem->cinfo->cleanup_reqs_remaining++;
		req = jsonrpc_request_start(plugin, NULL, ops->del_command,
					    del_done, del_failed, variant);
		ops->add_del_fields(req, buf, t);
		send_outreq(plugin, req);
	}

	subsystem->offset += max_entries_per_call;
	return clean_finished_one(subsystem->cinfo);
}

static struct command_result *list_failed(struct command *cmd,
					  const char *buf,
					  const jsmntok_t *result,
					  struct per_subsystem *subsystem)
{
	plugin_err(plugin, "Failed 'list%s': '%.*s'",
		   get_subsystem_ops(subsystem)->system_name,
		   json_tok_full_len(result),
		   json_tok_full(buf, result));
}

static struct command_result *do_clean(struct clean_info *cinfo)
{
	cinfo->cleanup_reqs_remaining = 0;
	for (size_t i = 0; i < NUM_SUBSYSTEM_TYPES; i++) {
		struct per_subsystem *ps = &cinfo->per_subsystem[i];
		struct out_req *req;
		bool have_variant = false;
		const char *filter;
		const struct subsystem_ops *ops = get_subsystem_ops(ps);

		for (size_t j = 0; j < NUM_SUBSYSTEM_VARIANTS; j++) {
			if (ps->variants[j].age)
				have_variant = true;
		}

		/* Don't bother listing if we don't care. */
		if (!have_variant)
			continue;

		/* Don't bother if we're past the end already. */
		if (ps->offset >= ps->max)
			continue;

		filter = tal_fmt(tmpctx, "{\"%s\":[{%s}]}",
				 ops->arr_name, ops->list_filter);
		req = jsonrpc_request_with_filter_start(plugin, NULL,
							tal_fmt(tmpctx,
								"list%s",
								ops->system_name),
							filter,
							list_done, list_failed,
							ps);
		/* Don't overwhelm lightningd or us if there are millions of
		 * entries! */
		json_add_string(req->js, "index", "created");
		json_add_u64(req->js, "start", ps->offset);
		json_add_u64(req->js, "limit", max_entries_per_call);
		send_outreq(plugin, req);
		cinfo->cleanup_reqs_remaining++;
	}

	if (cinfo->cleanup_reqs_remaining)
		return command_still_pending(NULL);
	return clean_finished(cinfo);
}

static struct command_result *wait_done(struct command *cmd,
					const char *buf,
					const jsmntok_t *result,
					struct per_subsystem *ps)
{
	const char *err;

	err = json_scan(tmpctx, buf, result, "{created:%}",
			JSON_SCAN(json_to_u64, &ps->max));
	if (err)
		plugin_err(plugin, "Failed parsing wait response: (%s): '%.*s'",
			   err,
			   json_tok_full_len(result),
			   json_tok_full(buf, result));

	/* We do three of these, make sure they're all complete. */
	assert(ps->cinfo->cleanup_reqs_remaining != 0);
	if (--ps->cinfo->cleanup_reqs_remaining > 0)
		return command_still_pending(ps->cinfo->cmd);

	return do_clean(ps->cinfo);
}

static struct command_result *wait_failed(struct command *cmd,
					  const char *buf,
					  const jsmntok_t *result,
					  struct per_subsystem *subsystem)
{
	plugin_err(plugin, "Failed wait '%s': '%.*s'",
		   get_subsystem_ops(subsystem)->system_name,
		   json_tok_full_len(result),
		   json_tok_full(buf, result));
}

static struct command_result *start_clean(struct clean_info *cinfo)
{
	cinfo->cleanup_reqs_remaining = 0;

	/* We have to get max indexes first. */
	for (size_t i = 0; i < NUM_SUBSYSTEM_TYPES; i++) {
		struct per_subsystem *ps = &cinfo->per_subsystem[i];
		const struct subsystem_ops *ops = get_subsystem_ops(ps);
		struct out_req *req;

		/* Reset counters while we're here */
		ps->num_uncleaned = 0;
		for (enum subsystem_variant j = 0; j < NUM_SUBSYSTEM_VARIANTS; j++) {
			struct per_variant *pv = &ps->variants[j];
			pv->num_cleaned = 0;
		}
		ps->offset = 0;

		req = jsonrpc_request_start(plugin, NULL,
					    "wait",
					    wait_done, wait_failed, ps);
		json_add_string(req->js, "subsystem", ops->system_name);
		json_add_string(req->js, "indexname", "created");
		json_add_u64(req->js, "nextvalue", 0);
		send_outreq(plugin, req);
		cinfo->cleanup_reqs_remaining++;
	}

	return command_still_pending(cinfo->cmd);
}

/* Needs a different signature than do_clean */
static void do_clean_timer(void *unused)
{
	assert(timer_cinfo->cleanup_reqs_remaining == 0);
	cleantimer = NULL;
	start_clean(timer_cinfo);
}

static struct command_result *param_subsystem(struct command *cmd,
					      const char *name,
					      const char *buffer,
					      const jsmntok_t *tok,
					      struct subsystem_and_variant **sv)
{
	*sv = tal(cmd, struct subsystem_and_variant);
	if (json_to_subsystem(buffer, tok, *sv))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be a valid subsystem name");
}

static struct command_result *json_success_subsystems(struct command *cmd,
						      const struct subsystem_and_variant *single)
{
	struct json_stream *response = jsonrpc_stream_success(cmd);
	struct subsystem_and_variant sv = first_sv();

	json_object_start(response, "autoclean");
	do {
		struct per_variant *pv;
		if (single &&
		    (sv.type != single->type || sv.variant != single->variant))
			continue;

		pv = &timer_cinfo->per_subsystem[sv.type].variants[sv.variant];
		json_object_start(response, subsystem_to_str(&sv));
		json_add_bool(response, "enabled", pv->age != 0);
		if (pv->age != 0)
			json_add_u64(response, "age", pv->age);
		json_add_u64(response, "cleaned", *total_cleaned(&sv));
		json_object_end(response);
	} while (next_sv(&sv));
	json_object_end(response);
	return command_finished(cmd, response);
}

static struct command_result *json_autoclean_status(struct command *cmd,
						    const char *buffer,
						    const jsmntok_t *params)
{
	struct subsystem_and_variant *sv;

	if (!param(cmd, buffer, params,
		   p_opt("subsystem", param_subsystem, &sv),
		   NULL))
		return command_param_failed();

	return json_success_subsystems(cmd, sv);
}

static struct command_result *param_u64_nonzero(struct command *cmd,
						const char *name,
						const char *buffer,
						const jsmntok_t *tok,
						u64 **val)
{
	struct command_result *res = param_u64(cmd, name, buffer, tok, val);
	if (res == NULL && *val == 0)
		res = command_fail_badparam(cmd, name, buffer, tok,
					    "Must be non-zero");
	return res;
}

static struct command_result *json_autoclean_once(struct command *cmd,
						  const char *buffer,
						  const jsmntok_t *params)
{
	struct subsystem_and_variant *sv;
	u64 *age;
	struct clean_info *cinfo;

	if (!param(cmd, buffer, params,
		   p_req("subsystem", param_subsystem, &sv),
		   p_req("age", param_u64_nonzero, &age),
		   NULL))
		return command_param_failed();

	cinfo = new_clean_info(cmd, cmd);
	get_per_variant(cinfo, sv)->age = *age;

	return start_clean(cinfo);
}

static void memleak_mark_timer_cinfo(struct plugin *plugin,
				     struct htable *memtable)
{
	memleak_scan_obj(memtable, timer_cinfo);
}

static const char *init(struct plugin *p,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	struct subsystem_and_variant sv;
	plugin = p;

	/* Plugin owns global */
	tal_steal(plugin, timer_cinfo);
	plugin_set_memleak_handler(plugin, memleak_mark_timer_cinfo);

	cleantimer = plugin_timer(p, time_from_sec(cycle_seconds), do_clean_timer, NULL);

	/* We don't care if this fails (it usually does, since entries
	 * don't exist! */
	sv = first_sv();
	do {
		rpc_scan_datastore_str(tmpctx, plugin,
				       datastore_path(tmpctx, &sv, "num"),
				       JSON_SCAN(json_to_u64, total_cleaned(&sv)));
	} while (next_sv(&sv));

	/* Optimization FTW! */
	rpc_enable_batching(p);
	return NULL;
}

static char *cycle_seconds_option(struct plugin *plugin, const char *arg,
				  bool check_only,
				  u64 *cycle_seconds)
{
	char *problem = u64_option(plugin, arg, check_only, cycle_seconds);
	if (problem || check_only)
		return problem;

	/* If timer is not running right now, reset it to new cycle_seconds */
	if (cleantimer) {
		tal_free(cleantimer);
		cleantimer = plugin_timer(plugin, time_from_sec(*cycle_seconds),
					  do_clean_timer, NULL);
	}
	return NULL;
}

static bool u64_jsonfmt_unless_zero(struct plugin *plugin,
				    struct json_stream *js, const char *fieldname, u64 *i)
{
	if (!*i)
		return false;
	return u64_jsonfmt(plugin, js, fieldname, i);
}

static const struct plugin_command commands[] = { {
	"autoclean-status",
	json_autoclean_status,
	}, {
	"autoclean-once",
	json_autoclean_once,
	},
};

int main(int argc, char *argv[])
{
	setup_locale();

	timer_cinfo = new_clean_info(NULL, NULL);
	plugin_main(argv, init, NULL, PLUGIN_STATIC, true, NULL,
		    commands, ARRAY_SIZE(commands),
	            NULL, 0, NULL, 0, NULL, 0,
		    plugin_option_dynamic("autoclean-cycle",
					  "int",
					  "Perform cleanup every"
					  " given seconds",
					  cycle_seconds_option, u64_jsonfmt,
					  &cycle_seconds),
		    plugin_option_dynamic("autoclean-succeededforwards-age",
					  "int",
					  "How old do successful forwards have to be before deletion (0 = never)",
					  u64_option, u64_jsonfmt_unless_zero,
					  &timer_cinfo->per_subsystem[FORWARDS].variants[SUCCESS].age),
		    plugin_option_dynamic("autoclean-failedforwards-age",
					  "int",
					  "How old do failed forwards have to be before deletion (0 = never)",
					  u64_option, u64_jsonfmt_unless_zero,
					  &timer_cinfo->per_subsystem[FORWARDS].variants[FAILURE].age),
		    plugin_option_dynamic("autoclean-succeededpays-age",
					  "int",
					  "How old do successful pays have to be before deletion (0 = never)",
					  u64_option, u64_jsonfmt_unless_zero,
					  &timer_cinfo->per_subsystem[PAYS].variants[SUCCESS].age),
		    plugin_option_dynamic("autoclean-failedpays-age",
					  "int",
					  "How old do failed pays have to be before deletion (0 = never)",
					  u64_option, u64_jsonfmt_unless_zero,
					  &timer_cinfo->per_subsystem[PAYS].variants[FAILURE].age),
		    plugin_option_dynamic("autoclean-paidinvoices-age",
					  "int",
					  "How old do paid invoices have to be before deletion (0 = never)",
					  u64_option, u64_jsonfmt_unless_zero,
					  &timer_cinfo->per_subsystem[INVOICES].variants[SUCCESS].age),
		    plugin_option_dynamic("autoclean-expiredinvoices-age",
					  "int",
					  "How old do expired invoices have to be before deletion (0 = never)",
					  u64_option, u64_jsonfmt_unless_zero,
					  &timer_cinfo->per_subsystem[INVOICES].variants[FAILURE].age),
		    plugin_option_dev_dynamic("dev-autoclean-max-batch",
					      "int",
					      "Maximum cleans to do at a time",
					      u64_option, u64_jsonfmt,
					      &max_entries_per_call),
		    NULL);
}
