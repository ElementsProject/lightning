#ifndef LIGHTNING_COMMON_BOLT11_JSON_H
#define LIGHTNING_COMMON_BOLT11_JSON_H
#include "config.h"

struct bolt11;
struct json_stream;

void json_add_bolt11(struct json_stream *response,
		     const struct bolt11 *b11);
#endif /* LIGHTNING_COMMON_BOLT11_JSON_H */
