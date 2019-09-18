#include <ccan/array_size/array_size.h>
#include <ccan/json_out/json_out.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/utils.h>
#include <inttypes.h>
#include <plugins/libplugin.h>

static u64 cycle_seconds = 0, expired_by = 86400;
static struct plugin_timer *cleantimer;
static struct plugin_conn *rpc;

static struct command_result *do_clean(void);

static struct command_result *ignore(struct command *timer,
				     const char *buf,
				     const jsmntok_t *result,
				     void *arg)
{
	cleantimer = plugin_timer(rpc, time_from_sec(cycle_seconds), do_clean);
	return timer_complete();
}

static struct command_result *do_clean(void)
{
	struct json_out *params = json_out_new(NULL);
	json_out_start(params, NULL, '{');
	json_out_add(params, "maxexpirytime", false, "%"PRIu64,
		     time_now().ts.tv_sec - expired_by);
	json_out_end(params, '}');
	json_out_finished(params);

	/* FIXME: delexpiredinvoice should be in our plugin too! */
	return send_outreq(NULL, "delexpiredinvoice", ignore, ignore, NULL,
			   take(params));
}

static struct command_result *json_autocleaninvoice(struct command *cmd,
						    const char *buffer,
						    const jsmntok_t *params)
{
	u64 *cycle;
	u64 *exby;

	if (!param(cmd, buffer, params,
		   p_opt_def("cycle_seconds", param_u64, &cycle, 3600),
		   p_opt_def("expired_by", param_u64, &exby, 86400),
		   NULL))
		return command_param_failed();

	cycle_seconds = *cycle;
	expired_by = *exby;

	if (cycle_seconds == 0) {
		tal_free(cleantimer);
		return command_success_str(cmd, "Autoclean timer disabled");
	}
	tal_free(cleantimer);
	cleantimer = plugin_timer(rpc, time_from_sec(cycle_seconds), do_clean);

	return command_success_str(cmd,
				   tal_fmt(cmd, "Autocleaning %"PRIu64
					   "-second old invoices every %"PRIu64
					   " seconds",
					   expired_by, cycle_seconds));
}

static void init(struct plugin_conn *prpc,
		  const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
	rpc = prpc;

	if (cycle_seconds) {
		plugin_log(LOG_INFORM, "autocleaning every %"PRIu64" seconds", cycle_seconds);
		cleantimer = plugin_timer(rpc, time_from_sec(cycle_seconds),
					  do_clean);
	} else
		plugin_log(LOG_DBG, "autocleaning not active");
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
	plugin_main(argv, init, PLUGIN_RESTARTABLE, commands, ARRAY_SIZE(commands),
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
