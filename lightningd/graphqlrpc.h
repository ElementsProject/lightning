#ifndef LIGHTNING_LIGHTNINGD_GRAPHQLRPC_H
#define LIGHTNING_LIGHTNINGD_GRAPHQLRPC_H
#include "config.h"

struct json_stream;
struct command;
struct graphql_field;

typedef void (*toplevel_json_add_cb)(struct json_stream *js,
				     const struct graphql_field *field);

struct toplevel_field_data {
	toplevel_json_add_cb json_add_func;
};

#define create_cbd(field, tname, ctx, datatype) \
	((datatype *)create_cbd_((field), (tname), (ctx), tal((ctx), datatype)))
void *create_cbd_(struct graphql_field *field, const char *tname, void *ctx, void *obj);

#define get_cbd(field, tname, datatype) \
	((datatype *)get_cbd_((field), (tname)))
void *get_cbd_(const struct graphql_field *field, const char *tname);

#endif /* LIGHTNING_LIGHTNINGD_GRAPHQLRPC_H */
