#include "config.h"
#include <ccan/array_size/array_size.h>
#include <common/json_tok.h>
#include <plugins/libplugin.h>

static u64 cycle_seconds = 0, expired_by = 86400;
static struct plugin_timer *cleantimer;

static void do_clean(void *cb_arg);

static struct command_result *ignore(struct command *timer,
				     const char *buf,
				     const jsmntok_t *result,
				     void *arg)
{
	struct plugin *p = arg;
	cleantimer = plugin_timer(p, time_from_sec(cycle_seconds), do_clean, p);
	return timer_complete(p);
}

static void do_clean(void *cb_arg)
{
	struct plugin *p = cb_arg;
	/* FIXME: delexpiredinvoice should be in our plugin too! */
	struct out_req *req = jsonrpc_request_start(p, NULL, "delexpiredinvoice",
						    ignore, ignore, p);
	json_add_u64(req->js, "maxexpirytime",
		     time_now().ts.tv_sec - expired_by);

	send_outreq(p, req);
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

	cycle_seconds = *cycle;
	expired_by = *exby;

	if (cycle_seconds == 0) {
		response = jsonrpc_stream_success(cmd);
		json_add_bool(response, "enabled", false);
		return command_finished(cmd, response);
	}
	tal_free(cleantimer);
	cleantimer = plugin_timer(cmd->plugin, time_from_sec(cycle_seconds),
				  do_clean, cmd->plugin);

	response = jsonrpc_stream_success(cmd);
	json_add_bool(response, "enabled", true);
	json_add_u64(response, "cycle_seconds", cycle_seconds);
	json_add_u64(response, "expired_by", expired_by);
	return command_finished(cmd, response);
}

static const char *init(struct plugin *p,
			const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	if (cycle_seconds) {
		plugin_log(p, LOG_INFORM, "autocleaning every %"PRIu64" seconds", cycle_seconds);
		cleantimer = plugin_timer(p, time_from_sec(cycle_seconds),
					  do_clean, p);
	} else
		plugin_log(p, LOG_DBG, "autocleaning not active");

	return NULL;
}

static const struct plugin_command commands[] = { {
	"autocleaninvoice",
	"payment",
	"Set up autoclean of expired invoices. ",
	"Perform cleanup every {cycle_seconds} (default 3600), or disable autoclean if 0. "
	"Clean up expired invoices that have expired for {expired_by} seconds (default 86400). ",
	json_autocleaninvoice
	}
};

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_STATIC, true, NULL, commands, ARRAY_SIZE(commands),
	            NULL, 0, NULL, 0, NULL, 0,
		    plugin_option("autocleaninvoice-cycle",
				  "string",
				  "Perform cleanup of expired invoices every"
				  " given seconds, or do not autoclean if 0",
				  u64_option, &cycle_seconds),
		    plugin_option("autocleaninvoice-expired-by",
				  "string",
				  "If expired invoice autoclean enabled,"
				  " invoices that have expired for at least"
				  " this given seconds are cleaned",
				  u64_option, &expired_by),
		    NULL);
}
