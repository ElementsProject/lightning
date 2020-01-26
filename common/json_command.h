/* These functions must be supplied by any binary linking with common/param
 * so it can fail commands. */
#ifndef LIGHTNING_COMMON_JSON_COMMAND_H
#define LIGHTNING_COMMON_JSON_COMMAND_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <common/errcode.h>
#include <stdbool.h>

struct command;
struct command_result;

/* Caller supplied this: param assumes it can call it. */
struct command_result *command_fail(struct command *cmd, errcode_t code,
				    const char *fmt, ...)
	PRINTF_FMT(3, 4) WARN_UNUSED_RESULT;

/* Also caller supplied: is this invoked simply to get usage? */
bool command_usage_only(const struct command *cmd);

/* If so, this is called. */
void command_set_usage(struct command *cmd, const char *usage);

/* Also caller supplied: is this invoked simply to check parameters? */
bool command_check_only(const struct command *cmd);

#endif /* LIGHTNING_COMMON_JSON_COMMAND_H */
