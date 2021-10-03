#ifndef LIGHTNING_COMMON_GRAPHQL_ARGS_H
#define LIGHTNING_COMMON_GRAPHQL_ARGS_H
#include "config.h"
#include <common/status_levels.h>

struct command;

#define a_opt_def(name, callback, var, def) \
		(name), 0, (callback), (var), (def) \

#define a_opt(name, callback, var) \
		(name), 0, (callback), (var), 0 \

#define a_req(name, callback, var) \
		(name), 1, (callback), (var), 0 \

struct json_stream;
struct graphql_field;
struct graphql_value;
struct node_id;

const char *get_alias(struct graphql_field *field);

bool get_args(struct command *cmd, const struct graphql_field *field, ...) LAST_ARG_NULL;

typedef void (*arg_cbx)(void *ctx, const char *str, void *var);

void str_to_node_id(void *ctx, const char *str, struct node_id **id);
void str_to_log_level(void *ctx, const char *str, enum log_level **ll);

#endif /* LIGHTNING_COMMON_GRAPHQL_ARGS_H */

