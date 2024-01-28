/* Dealing with channel_type in JSON */
#ifndef LIGHTNING_COMMON_JSON_CHANNEL_TYPE_H
#define LIGHTNING_COMMON_JSON_CHANNEL_TYPE_H
#include "config.h"
#include <common/json_parse_simple.h>

struct command;
struct channel_type;
struct json_stream;

/* Parse [1,2] as a channel_type */
struct command_result *param_channel_type(struct command *cmd,
					  const char *name,
					  const char *buffer,
					  const jsmntok_t *tok,
					  struct channel_type **ctype);

/* Adds [1, 5]-style JSON array. */
void json_add_channel_type_arr(struct json_stream *response,
			       const char *fieldname,
			       const struct channel_type *ctype);


/* Add channel_type object, with array and names */
void json_add_channel_type(struct json_stream *response,
			   const char *fieldname,
			   const struct channel_type *channel_type);
#endif /* LIGHTNING_COMMON_JSON_CHANNEL_TYPE_H */
