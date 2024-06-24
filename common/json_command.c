#include "config.h"
#include <common/json_command.h>

struct command_result *
command_fail_badparam(struct command *cmd,
		      const char *paramname,
		      const char *buffer,
		      const jsmntok_t *tok,
		      const char *msg)
{
	if (command_dev_apis(cmd)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s: %s: invalid token '%.*s'",
				    paramname, msg,
				    json_tok_full_len(tok),
				    json_tok_full(buffer, tok));
	}

	/* Someone misconfigured LNBITS with "" around the rune, and so the
	 * user got a message about a bad rune parameter which *contained the
	 * rune itself*!.  LNBITS should probably swallow any JSONRPC2_* error
	 * itself, but it is quite possibly not the only case where this case
	 * where this can happen.  So we are a little circumspect in this
	 * case. */
	command_log(cmd, LOG_INFORM,
		    "Invalid parameter %s (%s): token '%.*s'",
		    paramname, msg,
		    json_tok_full_len(tok),
		    json_tok_full(buffer, tok));
	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "%s: %s: invalid token (see logs for details)",
			    paramname, msg);
}
