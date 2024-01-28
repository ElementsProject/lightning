#include "config.h"
#include <common/channel_type.h>
#include <common/json_channel_type.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_stream.h>

struct command_result *param_channel_type(struct command *cmd,
					  const char *name,
					  const char *buffer,
					  const jsmntok_t *tok,
					  struct channel_type **ctype)
{
	u8 *features = tal_arr(NULL, u8, 0);
	size_t i;
	const jsmntok_t *t;

	if (tok->type != JSMN_ARRAY) {
		return command_fail_badparam(cmd, name, buffer, tok,
					     "must be an array");
	}

	json_for_each_arr(i, t, tok) {
		u16 fbit;
		if (!json_to_u16(buffer, t, &fbit))
			return command_fail_badparam(cmd, name, buffer, t,
						     "must be a 16-bit integer");
		set_feature_bit(&features, fbit);
	}

	*ctype = channel_type_from(cmd, take(features));
	return NULL;
}

void json_add_channel_type_arr(struct json_stream *response,
			       const char *fieldname,
			       const struct channel_type *ctype)
{
	json_array_start(response, fieldname);
	for (size_t i = 0; i < tal_bytelen(ctype->features)*8; i++) {
		if (feature_is_set(ctype->features, i))
			json_add_u32(response, NULL, i);
	}
	json_array_end(response);
}
