#ifndef LIGHTNING_COMMON_JSON_BLINDED_PATH_H
#define LIGHTNING_COMMON_JSON_BLINDED_PATH_H
#include "config.h"
#include <common/json_parse_simple.h>

/* Extract reply path from this JSON */
struct blinded_path *json_to_blinded_path(const tal_t *ctx, const char *buffer,
					  const jsmntok_t *tok);

#endif /* LIGHTNING_COMMON_JSON_BLINDED_PATH_H */
