/* These functions must be supplied by any binary linking with common/param
 * so it can fail commands. */
#ifndef LIGHTNING_COMMON_JSON_COMMAND_H
#define LIGHTNING_COMMON_JSON_COMMAND_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <common/json_parse.h>
#include <common/jsonrpc_errors.h>

struct command;
struct command_result;

/* Caller supplied this: param assumes it can call it. */
struct command_result *command_fail(struct command *cmd, enum jsonrpc_errcode code,
				    const char *fmt, ...)
	PRINTF_FMT(3, 4) WARN_UNUSED_RESULT RETURNS_NONNULL;

/* Caller supplies this too: must provide this to reach into cmd */
struct json_filter **command_filter_ptr(struct command *cmd);

/* Convenient wrapper for "paramname: msg: invalid token '.*%s'" */
static inline struct command_result *
command_fail_badparam(struct command *cmd,
		      const char *paramname,
		      const char *buffer,
		      const jsmntok_t *tok,
		      const char *msg)
{
	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "%s: %s: invalid token '%.*s'",
			    paramname, msg,
			    json_tok_full_len(tok),
			    json_tok_full(buffer, tok));
}

/* Also caller supplied: is this invoked simply to get usage? */
bool command_usage_only(const struct command *cmd);

/* Caller supplies this too: they tried to use a deprecated parameter (or cmd). */
bool command_deprecated_in_ok(struct command *cmd,
			      const char *param,
			      const char *depr_start,
			      const char *depr_end);

/* Caller supplies this: should we output this deprecated thing */
bool command_deprecated_out_ok(struct command *cmd,
			       const char *fieldname,
			       const char *depr_start,
			       const char *depr_end);

/* Do we allow dev commands? */
bool command_dev_apis(const struct command *cmd);

/* If so, this is called. */
void command_set_usage(struct command *cmd, const char *usage);

/* Also caller supplied: is this invoked simply to check parameters? */
bool command_check_only(const struct command *cmd);

/* To return after param_check() succeeds but we're still
 * command_check_only(cmd). */
struct command_result *command_check_done(struct command *cmd)
	 WARN_UNUSED_RESULT;

#endif /* LIGHTNING_COMMON_JSON_COMMAND_H */
