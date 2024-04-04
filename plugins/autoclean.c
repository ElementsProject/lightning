#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/mem/mem.h>
#include <ccan/ptrint/ptrint.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <plugins/libplugin.h>

enum subsystem {
	SUCCEEDEDFORWARDS,
	FAILEDFORWARDS,
	SUCCEEDEDPAYS,
	FAILEDPAYS,
	PAIDINVOICES,
	EXPIREDINVOICES,
#define NUM_SUBSYSTEM (EXPIREDINVOICES + 1)
};

static const char *subsystem_str[] = {
	"succeededforwards",
	"failedforwards",
	"succeededpays",
	"failedpays",
	"paidinvoices",
	"expiredinvoices",
};

static const char *subsystem_to_str(enum subsystem subsystem)
{
	assert(subsystem >= 0 && subsystem < NUM_SUBSYSTEM);
	return subsystem_str[subsystem];
}

static bool json_to_subsystem(const char *buffer, const jsmntok_t *tok,
			      enum subsystem *subsystem)
{
	for (size_t i = 0; i < NUM_SUBSYSTEM; i++) {
		if (memeqstr(buffer + tok->start, tok->end - tok->start,
			     subsystem_str[i])) {
			*subsystem = i;
			return true;
		}
	}
	return false;
}

/* Usually this refers to the global one, but for autoclean-once
 * it's a temporary. */
struct clean_info {
	struct command *cmd;
	size_t cleanup_reqs_remaining;
	u64 subsystem_age[NUM_SUBSYSTEM];
	u64 num_cleaned[NUM_SUBSYSTEM];
	u64 num_uncleaned;
};

/* For deprecated API, setting this to zero disabled autoclean */
static u64 deprecated_cycle_seconds = UINT64_MAX;
static u64 cycle_seconds = 3600;
static struct clean_info timer_cinfo;
static u64 total_cleaned[NUM_SUBSYSTEM];
static struct plugin *plugin;
/* This is NULL if it's running now. */
static struct plugin_timer *cleantimer;

static void do_clean_timer(void *unused);

/* Fatal failures */
static struct command_result *cmd_failed(struct command *cmd,
					 const char *buf,
					 const jsmntok_t *result,
					 const char *cmdname)
{
	plugin_err(plugin, "Failed '%s': '%.*s'", cmdname,
		   json_tok_full_len(result),
		   json_tok_full(buf, result));
}

static const char *datastore_path(const tal_t *ctx,
				  enum subsystem subsystem,
				  const char *field)
{
	return tal_fmt(ctx, "autoclean/%s/%s",
		       subsystem_to_str(subsystem), field);
}

static struct command_result *clean_finished(struct clean_info *cinfo)
{
	for (enum subsystem i = 0; i < NUM_SUBSYSTEM; i++) {
		if (!cinfo->num_cleaned[i])
			continue;

		plugin_log(plugin, LOG_DBG, "cleaned %"PRIu64" from %s",
			   cinfo->num_cleaned[i], subsystem_to_str(i));
		total_cleaned[i] += cinfo->num_cleaned[i];
		jsonrpc_set_datastore_string(plugin, cinfo->cmd,
					     datastore_path(tmpctx, i, "num"),
					     tal_fmt(tmpctx, "%"PRIu64, total_cleaned[i]),
					     "create-or-replace", NULL, NULL, NULL);

	}

	/* autoclean-once? */
	if (cinfo->cmd) {
		struct json_stream *response = jsonrpc_stream_success(cinfo->cmd);

		json_object_start(response, "autoclean");
		for (enum subsystem i = 0; i < NUM_SUBSYSTEM; i++) {
			if (cinfo->subsystem_age[i] == 0)
				continue;
			json_object_start(response, subsystem_to_str(i));
			json_add_u64(response, "cleaned", cinfo->num_cleaned[i]);
			json_add_u64(response, "uncleaned", cinfo->num_uncleaned);
			json_object_end(response);
		}
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

	return clean_finished(cinfo);
}

struct del_data {
	enum subsystem subsystem;
	struct clean_info *cinfo;
};

static struct command_result *del_done(struct command *cmd,
				       const char *buf,
				       const jsmntok_t *result,
				       struct del_data *del_data)
{
	struct clean_info *cinfo = del_data->cinfo;

	cinfo->num_cleaned[del_data->subsystem]++;
	tal_free(del_data);
	return clean_finished_one(cinfo);
}

static struct command_result *del_failed(struct command *cmd,
					 const char *buf,
					 const jsmntok_t *result,
					 struct del_data *del_data)
{
	struct clean_info *cinfo = del_data->cinfo;

	plugin_log(plugin, LOG_UNUSUAL, "%s del failed: %.*s",
		   subsystem_to_str(del_data->subsystem),
		   json_tok_full_len(result),
		   json_tok_full(buf, result));
	tal_free(del_data);
	return clean_finished_one(cinfo);
}

static struct out_req *del_request_start(const char *method,
					 struct clean_info *cinfo,
					 enum subsystem subsystem)
{
	struct del_data *del_data = tal(plugin, struct del_data);

	del_data->cinfo = cinfo;
	del_data->subsystem = subsystem;
	cinfo->cleanup_reqs_remaining++;
	return jsonrpc_request_start(plugin, NULL, method,
				     del_done, del_failed, del_data);
}

static struct command_result *listinvoices_done(struct command *cmd,
						const char *buf,
						const jsmntok_t *result,
						struct clean_info *cinfo)
{
	const jsmntok_t *t, *inv = json_get_member(buf, result, "invoices");
	size_t i;
	u64 now = time_now().ts.tv_sec;

	json_for_each_arr(i, t, inv) {
		const jsmntok_t *status = json_get_member(buf, t, "status");
		const jsmntok_t *time;
		enum subsystem subsys;
		u64 invtime;

		if (json_tok_streq(buf, status, "expired")) {
			subsys = EXPIREDINVOICES;
			time = json_get_member(buf, t, "expires_at");
		} else if (json_tok_streq(buf, status, "paid")) {
			subsys = PAIDINVOICES;
			time = json_get_member(buf, t, "paid_at");
		} else {
			cinfo->num_uncleaned++;
			continue;
		}

		/* Continue if we don't care. */
		if (cinfo->subsystem_age[subsys] == 0) {
			cinfo->num_uncleaned++;
			continue;
		}

		if (!json_to_u64(buf, time, &invtime)) {
			plugin_err(plugin, "Bad time '%.*s'",
				   json_tok_full_len(time),
				   json_tok_full(buf, time));
		}

		if (invtime <= now - cinfo->subsystem_age[subsys]) {
			struct out_req *req;
			const jsmntok_t *label = json_get_member(buf, t, "label");

			req = del_request_start("delinvoice", cinfo, subsys);
			json_add_tok(req->js, "label", label, buf);
			json_add_tok(req->js, "status", status, buf);
			send_outreq(plugin, req);
		} else
			cinfo->num_uncleaned++;
	}

	return clean_finished_one(cinfo);
}

static struct command_result *listsendpays_done(struct command *cmd,
						const char *buf,
						const jsmntok_t *result,
						struct clean_info *cinfo)
{
	const jsmntok_t *t, *pays = json_get_member(buf, result, "payments");
	size_t i;
	u64 now = time_now().ts.tv_sec;

	json_for_each_arr(i, t, pays) {
		const jsmntok_t *status = json_get_member(buf, t, "status");
		const jsmntok_t *time;
		enum subsystem subsys;
		u64 paytime;

		if (json_tok_streq(buf, status, "failed")) {
			subsys = FAILEDPAYS;
		} else if (json_tok_streq(buf, status, "complete")) {
			subsys = SUCCEEDEDPAYS;
		} else {
			cinfo->num_uncleaned++;
			continue;
		}

		/* Continue if we don't care. */
		if (cinfo->subsystem_age[subsys] == 0) {
			cinfo->num_uncleaned++;
			continue;
		}

		time = json_get_member(buf, t, "created_at");
		if (!json_to_u64(buf, time, &paytime)) {
			plugin_err(plugin, "Bad created_at '%.*s'",
				   json_tok_full_len(time),
				   json_tok_full(buf, time));
		}

		if (paytime <= now - cinfo->subsystem_age[subsys]) {
			struct out_req *req;
			const jsmntok_t *phash = json_get_member(buf, t, "payment_hash");
			const jsmntok_t *groupid = json_get_member(buf, t, "groupid");
			const jsmntok_t *partidtok = json_get_member(buf, t, "partid");
			u64 partid;
			if (partidtok)
				json_to_u64(buf, partidtok, &partid);
			else
				partid = 0;

			req = del_request_start("delpay", cinfo, subsys);
			json_add_tok(req->js, "payment_hash", phash, buf);
			json_add_tok(req->js, "status", status, buf);
			json_add_tok(req->js, "groupid", groupid, buf);
			json_add_u64(req->js, "partid", partid);
			send_outreq(plugin, req);
		}
	}

	return clean_finished_one(cinfo);
}

static struct command_result *listforwards_done(struct command *cmd,
						const char *buf,
						const jsmntok_t *result,
						struct clean_info *cinfo)
{
	const jsmntok_t *t, *fwds = json_get_member(buf, result, "forwards");
	size_t i;
	u64 now = time_now().ts.tv_sec;

	json_for_each_arr(i, t, fwds) {
		const jsmntok_t *status = json_get_member(buf, t, "status");
		const char *timefield = "resolved_time";
		jsmntok_t time;
		enum subsystem subsys;
		u64 restime;

		if (json_tok_streq(buf, status, "settled")) {
			subsys = SUCCEEDEDFORWARDS;
		} else if (json_tok_streq(buf, status, "failed")
			   || json_tok_streq(buf, status, "local_failed")) {
			subsys = FAILEDFORWARDS;
			/* There's no resolved_time for these, so use received */
			timefield = "received_time";
		} else {
			cinfo->num_uncleaned++;
			continue;
		}

		/* Continue if we don't care. */
		if (cinfo->subsystem_age[subsys] == 0) {
			cinfo->num_uncleaned++;
			continue;
		}

		/* Check if we have a resolved_time, before making a
		 * decision on it. This is possible in older nodes
		 * that predate our annotations for forwards.*/
		if (json_get_member(buf, t, timefield) == NULL) {
			cinfo->num_uncleaned++;
			continue;
		}


		time = *json_get_member(buf, t, timefield);
		/* This is a float, so truncate at '.' */
		for (int off = time.start; off < time.end; off++) {
			if (buf[off] == '.')
				time.end = off;
		}
		if (!json_to_u64(buf, &time, &restime)) {
			plugin_err(plugin, "Bad time '%.*s'",
				   json_tok_full_len(&time),
				   json_tok_full(buf, &time));
		}

		if (restime <= now - cinfo->subsystem_age[subsys]) {
			struct out_req *req;
			const jsmntok_t *inchan, *inid;

			inchan = json_get_member(buf, t, "in_channel");
			inid = json_get_member(buf, t, "in_htlc_id");

			req = del_request_start("delforward", cinfo, subsys);
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
			send_outreq(plugin, req);
		}
	}

	return clean_finished_one(cinfo);
}

static struct command_result *listsendpays_failed(struct command *cmd,
						  const char *buf,
						  const jsmntok_t *result,
						  void *unused)
{
	return cmd_failed(cmd, buf, result, "listsendpays");
}

static struct command_result *listinvoices_failed(struct command *cmd,
						  const char *buf,
						  const jsmntok_t *result,
						  void *unused)
{
	return cmd_failed(cmd, buf, result, "listinvoices");
}

static struct command_result *listforwards_failed(struct command *cmd,
						  const char *buf,
						  const jsmntok_t *result,
						  void *unused)
{
	return cmd_failed(cmd, buf, result, "listforwards");
}

static struct command_result *do_clean(struct clean_info *cinfo)
{
	struct out_req *req;

	cinfo->cleanup_reqs_remaining = 0;
	cinfo->num_uncleaned = 0;
	memset(cinfo->num_cleaned, 0, sizeof(cinfo->num_cleaned));

	if (cinfo->subsystem_age[SUCCEEDEDPAYS] != 0
	    || cinfo->subsystem_age[FAILEDPAYS] != 0) {
		req = jsonrpc_request_start(plugin, NULL, "listsendpays",
					    listsendpays_done, listsendpays_failed,
					    cinfo);
		send_outreq(plugin, req);
		cinfo->cleanup_reqs_remaining++;
	}

	if (cinfo->subsystem_age[EXPIREDINVOICES] != 0
	    || cinfo->subsystem_age[PAIDINVOICES] != 0) {
		req = jsonrpc_request_start(plugin, NULL, "listinvoices",
					    listinvoices_done, listinvoices_failed,
					    cinfo);
		send_outreq(plugin, req);
		cinfo->cleanup_reqs_remaining++;
	}

	if (cinfo->subsystem_age[SUCCEEDEDFORWARDS] != 0
	    || cinfo->subsystem_age[FAILEDFORWARDS] != 0) {
		req = jsonrpc_request_start(plugin, NULL, "listforwards",
					    listforwards_done, listforwards_failed,
					    cinfo);
		send_outreq(plugin, req);
		cinfo->cleanup_reqs_remaining++;
	}

	if (cinfo->cleanup_reqs_remaining)
		return command_still_pending(NULL);
	return clean_finished(cinfo);
}

/* Needs a different signature than do_clean */
static void do_clean_timer(void *unused)
{
	assert(timer_cinfo.cleanup_reqs_remaining == 0);
	cleantimer = NULL;
	do_clean(&timer_cinfo);
}

static struct command_result *json_autocleaninvoice(struct command *cmd,
						    const char *buffer,
						    const jsmntok_t *params)
{
	u64 *cycle;
	u64 *exby;
	struct json_stream *response;

	if (!param(cmd, buffer, params,
		   p_opt_def("cycle_seconds", param_u64, &cycle, 3600),
		   p_opt_def("expired_by", param_u64, &exby, 86400),
		   NULL))
		return command_param_failed();

	cleantimer = tal_free(cleantimer);

	if (*cycle == 0) {
		timer_cinfo.subsystem_age[EXPIREDINVOICES] = 0;
		response = jsonrpc_stream_success(cmd);
		json_add_bool(response, "enabled", false);
		return command_finished(cmd, response);
	}

	cycle_seconds = *cycle;
	timer_cinfo.subsystem_age[EXPIREDINVOICES] = *exby;
	cleantimer = plugin_timer(cmd->plugin, time_from_sec(cycle_seconds),
				  do_clean_timer, NULL);

	response = jsonrpc_stream_success(cmd);
	json_add_bool(response, "enabled", true);
	json_add_u64(response, "cycle_seconds", cycle_seconds);
	json_add_u64(response, "expired_by", timer_cinfo.subsystem_age[EXPIREDINVOICES]);
	return command_finished(cmd, response);
}

static struct command_result *param_subsystem(struct command *cmd,
					      const char *name,
					      const char *buffer,
					      const jsmntok_t *tok,
					      enum subsystem **subsystem)
{
	*subsystem = tal(cmd, enum subsystem);
	if (json_to_subsystem(buffer, tok, *subsystem))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be a valid subsystem name");
}

static struct command_result *json_success_subsystems(struct command *cmd,
						      const enum subsystem *subsystem)
{
	struct json_stream *response = jsonrpc_stream_success(cmd);

	json_object_start(response, "autoclean");
	for (enum subsystem i = 0; i < NUM_SUBSYSTEM; i++) {
		if (subsystem && i != *subsystem)
			continue;
		json_object_start(response, subsystem_to_str(i));
		json_add_bool(response, "enabled", timer_cinfo.subsystem_age[i] != 0);
		if (timer_cinfo.subsystem_age[i] != 0)
			json_add_u64(response, "age", timer_cinfo.subsystem_age[i]);
		json_add_u64(response, "cleaned", total_cleaned[i]);
		json_object_end(response);
	}
	json_object_end(response);
	return command_finished(cmd, response);
}

static struct command_result *json_autoclean_status(struct command *cmd,
						    const char *buffer,
						    const jsmntok_t *params)
{
	enum subsystem *subsystem;

	if (!param(cmd, buffer, params,
		   p_opt("subsystem", param_subsystem, &subsystem),
		   NULL))
		return command_param_failed();

	return json_success_subsystems(cmd, subsystem);
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
	enum subsystem *subsystem;
	u64 *age;
	struct clean_info *cinfo;

	if (!param(cmd, buffer, params,
		   p_req("subsystem", param_subsystem, &subsystem),
		   p_req("age", param_u64_nonzero, &age),
		   NULL))
		return command_param_failed();

	cinfo = tal(cmd, struct clean_info);
	cinfo->cmd = cmd;
	memset(cinfo->subsystem_age, 0, sizeof(cinfo->subsystem_age));
	cinfo->subsystem_age[*subsystem] = *age;

	return do_clean(cinfo);
}

static const char *init(struct plugin *p,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	plugin = p;
	if (deprecated_cycle_seconds != UINT64_MAX) {
		if (deprecated_cycle_seconds == 0) {
			plugin_log(p, LOG_DBG, "autocleaning not active");
			return NULL;
		} else
			cycle_seconds = deprecated_cycle_seconds;
	}

	cleantimer = plugin_timer(p, time_from_sec(cycle_seconds), do_clean_timer, NULL);

	/* We don't care if this fails (it usually does, since entries
	 * don't exist! */
	for (enum subsystem i = 0; i < NUM_SUBSYSTEM; i++) {
		rpc_scan_datastore_str(tmpctx, plugin,
				       datastore_path(tmpctx, i, "num"),
				       JSON_SCAN(json_to_u64, &total_cleaned[i]));
	}

	/* Optimization FTW! */
	rpc_enable_batching(p);
	return NULL;
}

static char *cycle_seconds_option(struct plugin *plugin, const char *arg,
				  bool check_only,
				  void *unused)
{
	char *problem = u64_option(plugin, arg, check_only, &cycle_seconds);
	if (problem || check_only)
		return problem;

	/* If timer is not running right now, reset it to new cycle_seconds */
	if (cleantimer) {
		tal_free(cleantimer);
		cleantimer = plugin_timer(plugin, time_from_sec(cycle_seconds),
					  do_clean_timer, NULL);
	}
	return NULL;
}

static const struct plugin_command commands[] = { {
	"autocleaninvoice",
	"payment",
	"Set up autoclean of expired invoices. ",
	"Perform cleanup every {cycle_seconds} (default 3600), or disable autoclean if 0. "
	"Clean up expired invoices that have expired for {expired_by} seconds (default 86400). ",
	json_autocleaninvoice,
	"v22.11", "v24.02",
	}, {
	"autoclean-status",
	"utility",
	"Show status of autocleaning",
	"Takes optional {subsystem}",
	json_autoclean_status,
	}, {
	"autoclean-once",
	"utility",
	"Perform a single run of autocleaning on one subsystem",
	"Requires {subsystem} and {age}",
	json_autoclean_once,
	},
};

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_STATIC, true, NULL, commands, ARRAY_SIZE(commands),
	            NULL, 0, NULL, 0, NULL, 0,
		    plugin_option_deprecated("autocleaninvoice-cycle",
				  "string",
				  "Perform cleanup of expired invoices every"
				  " given seconds, or do not autoclean if 0",
			          "v22.11", "v24.02",
				  u64_option, &deprecated_cycle_seconds),
		    plugin_option_deprecated("autocleaninvoice-expired-by",
				  "string",
				  "If expired invoice autoclean enabled,"
				  " invoices that have expired for at least"
				  " this given seconds are cleaned",
			          "v22.11", "v24.02",
				  u64_option, &timer_cinfo.subsystem_age[EXPIREDINVOICES]),
		    plugin_option_dynamic("autoclean-cycle",
					  "int",
					  "Perform cleanup every"
					  " given seconds",
					  cycle_seconds_option, NULL),
		    plugin_option_dynamic("autoclean-succeededforwards-age",
					  "int",
					  "How old do successful forwards have to be before deletion (0 = never)",
					  u64_option, &timer_cinfo.subsystem_age[SUCCEEDEDFORWARDS]),
		    plugin_option_dynamic("autoclean-failedforwards-age",
					  "int",
					  "How old do failed forwards have to be before deletion (0 = never)",
					  u64_option, &timer_cinfo.subsystem_age[FAILEDFORWARDS]),
		    plugin_option_dynamic("autoclean-succeededpays-age",
					  "int",
					  "How old do successful pays have to be before deletion (0 = never)",
					  u64_option, &timer_cinfo.subsystem_age[SUCCEEDEDPAYS]),
		    plugin_option_dynamic("autoclean-failedpays-age",
					  "int",
					  "How old do failed pays have to be before deletion (0 = never)",
					  u64_option, &timer_cinfo.subsystem_age[FAILEDPAYS]),
		    plugin_option_dynamic("autoclean-paidinvoices-age",
					  "int",
					  "How old do paid invoices have to be before deletion (0 = never)",
					  u64_option, &timer_cinfo.subsystem_age[PAIDINVOICES]),
		    plugin_option_dynamic("autoclean-expiredinvoices-age",
					  "int",
					  "How old do expired invoices have to be before deletion (0 = never)",
					  u64_option, &timer_cinfo.subsystem_age[EXPIREDINVOICES]),
		    NULL);
}
