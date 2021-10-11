#ifndef LIGHTNING_COMMON_GRAPHQL_ARGS_H
#define LIGHTNING_COMMON_GRAPHQL_ARGS_H
#include "config.h"
#include <external/jsmn/jsmn.h>

struct graphql_field;

const char *get_alias(struct graphql_field *field);

void convert_args_to_paramtokens(struct graphql_field *field, const tal_t *ctx, jsmntok_t **params);

#define NO_ARGS(cmd, field) \
	if ((field)->args) \
		return command_fail((cmd), GRAPHQL_ARG_ERROR, \
				    "no arguments accepted for '%s'", \
				    (field)->name->token_string) \

#define NO_SUBFIELDS(cmd, field) \
	if ((field)->sel_set) \
		return command_fail((cmd), GRAPHQL_FIELD_ERROR, \
				    "no subfields known for '%s'", \
				    (field)->name->token_string) \

#define NO_SUBFIELD_SELECTION(cmd, field) \
	if ((field)->sel_set) \
		return command_fail((cmd), GRAPHQL_FEATURE_NOT_SUPPORTED, \
				    "subfield selection not supported on field '%s'", \
				    (field)->name->token_string) \

#define NO_ALIAS_SUPPORT(cmd, field) \
	if (!streq((field)->name->token_string, get_alias(field))) \
		return command_fail((cmd), GRAPHQL_FEATURE_NOT_SUPPORTED, \
				    "alias not supported on field '%s'", \
				    (field)->name->token_string) \

#endif /* LIGHTNING_COMMON_GRAPHQL_ARGS_H */

