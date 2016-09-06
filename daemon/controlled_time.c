#include "controlled_time.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include "log.h"
#include "opt_time.h"
#include <ccan/tal/str/str.h>
#include <inttypes.h>
#include <stdio.h>

static struct timeabs mock_time;

struct timeabs controlled_time(void)
{
	if (mock_time.ts.tv_sec)
		return mock_time;
	return time_now();
}

void controlled_time_register_opts(void)
{
	opt_register_arg("--mocktime", opt_set_timeabs, opt_show_timeabs,
			 &mock_time, opt_hidden);
}

char *controlled_time_arg(const tal_t *ctx)
{
	char buf[sizeof("--mocktime=") + OPT_SHOW_LEN] = "--mocktime=";
	if (!mock_time.ts.tv_sec)
		return NULL;

	opt_show_timeabs(buf + strlen(buf), &mock_time);
	return tal_strdup(ctx, buf);
}

static void json_mocktime(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct json_result *response = new_json_result(cmd);
	jsmntok_t *mocktimetok;
	u64 prev_time, mocktime;
	char mocktimestr[STR_MAX_CHARS(int64_t)];

	if (!json_get_params(buffer, params,
			     "mocktime", &mocktimetok,
			     NULL)) {
		command_fail(cmd, "Need mocktime");
		return;
	}
	if (!json_tok_u64(buffer, mocktimetok, &mocktime)) {
		command_fail(cmd, "Need valid mocktime");
		return;
	}

	prev_time = controlled_time().ts.tv_sec;
	mock_time.ts.tv_sec = mocktime;

	json_object_start(response, NULL);
	sprintf(mocktimestr, "%"PRIi64,
		(s64)controlled_time().ts.tv_sec - prev_time);
	json_add_string(response, "offset", mocktimestr);
	json_object_end(response);

	log_unusual(cmd->dstate->base_log,
		    "mocktime set to %"PRIu64, (u64)mock_time.ts.tv_sec);
	command_success(cmd, response);
}

const struct json_command dev_mocktime_command = {
	"dev-mocktime",
	json_mocktime,
	"Set current time to {mocktime} seconds (0 to return to normal)",
	"Returns the offset on success"
};
