#ifndef LIGHTNING_COMMON_GRAPHQL_ARGS_H
#define LIGHTNING_COMMON_GRAPHQL_ARGS_H
#include "config.h"
#include <ccan/graphql/graphql.h>
#include <common/node_id.h>
#include <common/status_levels.h>

bool arg_node_id(const char *name, const struct graphql_field *field,
		 void *ctx, struct node_id **id);
bool arg_loglevel(const char *name, const struct graphql_field *field,
		  void *ctx, enum log_level **ll);

#endif /* LIGHTNING_COMMON_GRAPHQL_ARGS_H */

