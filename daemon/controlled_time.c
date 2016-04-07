#include "controlled_time.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include "log.h"
#include <inttypes.h>
#include <stdio.h>

static struct timeabs mock_time;

struct timeabs controlled_time(void)
{
	if (mock_time.ts.tv_sec)
		return mock_time;
	return time_now();
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

const struct json_command mocktime_command = {
	"dev-mocktime",
	json_mocktime,
	"Set current time to {mocktime} seconds (0 to return to normal)",
	"Returns the offset on success"
};
