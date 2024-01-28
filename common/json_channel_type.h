/* Dealing with channel_type in JSON */
#ifndef LIGHTNING_COMMON_JSON_CHANNEL_TYPE_H
#define LIGHTNING_COMMON_JSON_CHANNEL_TYPE_H
#include "config.h"
#include <common/json_parse_simple.h>

struct command;
struct channel_type;

/* Parse [1,2] as a channel_type */
struct command_result *param_channel_type(struct command *cmd,
					  const char *name,
					  const char *buffer,
					  const jsmntok_t *tok,
					  struct channel_type **ctype);

#endif /* LIGHTNING_COMMON_JSON_CHANNEL_TYPE_H */
