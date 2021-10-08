#ifndef LIGHTNING_COMMON_GRAPHQL_ARGS_H
#define LIGHTNING_COMMON_GRAPHQL_ARGS_H
#include "config.h"
#include <external/jsmn/jsmn.h>

struct graphql_field;

const char *get_alias(struct graphql_field *field);

void convert_args_to_paramtokens(struct graphql_field *field, const tal_t *ctx, jsmntok_t **params);

#endif /* LIGHTNING_COMMON_GRAPHQL_ARGS_H */

