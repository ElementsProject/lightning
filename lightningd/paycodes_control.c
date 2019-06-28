#include "json.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include "paycodes.h"
#include "paycodes_control.h"
#include <bitcoin/preimage.h>
#include <ccan/time/time.h>
#include <common/json_command.h>
#include <common/json_tok.h>
#include <common/jsonrpc_errors.h>
#include <common/param.h>

static void json_waitnewpaycode_resolve(enum paycodes_result result,
					struct command *cmd)
{
	struct json_stream *response;

	switch (result) {
	case paycodes_paid:
	case paycodes_timeout:
		response = json_stream_success(cmd);
		json_add_string(response, "status",
				result == paycodes_paid ? "paid" : "expired");
		was_pending(command_success(cmd, response));
		return;

	case paycodes_duplicate:
		was_pending(command_fail(cmd,
					 INVOICE_PREIMAGE_ALREADY_EXISTS,
					 "preimage already used"));
		return;
	}
}

static struct command_result *json_waitnewpaycode(struct command *cmd,
						  const char *buffer,
						  const jsmntok_t *obj UNNEEDED,
						  const jsmntok_t *params)
{
	struct preimage *preimage;
	struct amount_msat *min_msatoshi;
	struct amount_msat *max_msatoshi;
	u64 *expiry;

	if (!param(cmd, buffer, params,
		   p_req("preimage", param_preimage, &preimage),
		   p_opt("min_msatoshi", param_msat, &min_msatoshi),
		   p_opt("max_msatoshi", param_msat, &max_msatoshi),
		   p_opt_def("expiry", param_time, &expiry, 60 * 5),
		   NULL))
		return command_param_failed();

	/* If min is specified but not max, or if max is specified but
	 * not min, treat as exact value.  */
	if (min_msatoshi && !max_msatoshi)
		max_msatoshi = min_msatoshi;
	else if (max_msatoshi && !min_msatoshi)
		min_msatoshi = max_msatoshi;
	else if (!min_msatoshi && !max_msatoshi) {
		/* No range limit if both unspecified. */
		min_msatoshi = tal(cmd, struct amount_msat);
		max_msatoshi = tal(cmd, struct amount_msat);
		*min_msatoshi = AMOUNT_MSAT(0);
		*max_msatoshi = AMOUNT_MSAT(UINT64_MAX);
	}

	paycodes_add_and_wait(cmd->ld->paycodes,
			      preimage,
			      *min_msatoshi,
			      *max_msatoshi,
			      time_from_sec(*expiry),
			      &json_waitnewpaycode_resolve,
			      cmd);

	return command_still_pending(cmd);
}

static const struct json_command waitnewpaycode_command = {
	"waitnewpaycode",
	"payment",
	json_waitnewpaycode,
	"Wait for an incoming payment whose "
	"hash has the given unique {preimage}.  "
	"Incoming payment must be between "
	"{min_msatoshi} to {max_msatoshi}.  "
	"Time out if not paid after {expiry} seconds."
};
AUTODATA(json_command, &waitnewpaycode_command);
