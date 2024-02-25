#include <plugins/renepay/finish.h>

static struct command_result *my_command_finish(struct payment *p,
						struct command *cmd)
{
	struct json_stream *result;
	if (p->status == PAYMENT_SUCCESS) {
		result = payment_result(p, cmd);
		return command_finished(cmd, result);
	}
	assert(p->status == PAYMENT_FAIL);
	assert(p->error_msg);
	return command_fail(cmd, p->error_code, "%s", p->error_msg);
}

struct command_result *payment_finish(struct payment *p)
{
	assert(p->status == PAYMENT_FAIL || p->status == PAYMENT_SUCCESS);
	assert(!payment_commands_empty(p));
	struct command *cmd = p->cmd_array[0];

	// notify all commands that the payment completed
	for (size_t i = 1; i < tal_count(p->cmd_array); ++i) {
		my_command_finish(p, p->cmd_array[i]);
	}
	tal_resize(&p->cmd_array, 0);
	return my_command_finish(p, cmd);
}
