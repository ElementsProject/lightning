#include <common/graphql_args.h>
#include <common/json_helpers.h>
#include <external/jsmn/jsmn.h>

bool arg_node_id(const char *name, struct graphql_field *field, void *ctx, struct node_id **id) {
	struct graphql_argument *arg;
	*id = NULL;
	if (!field->args || !field->args->first)
		return false;
	for (arg = field->args->first; arg; arg = arg->next) {
		if (arg->name && arg->name->token_type == 'a' &&
		    arg->name->token_string &&
		    streq(arg->name->token_string, name) &&
		    arg->val && arg->val->str_val && arg->val->str_val->val &&
		    arg->val->str_val->val->token_type == 's' &&
		    arg->val->str_val->val->token_string) {
			struct graphql_token *t = arg->val->str_val->val;

			/* A hackish way of being able to reuse json_to_node_id */
			jsmntok_t tmptok;
			tmptok.type = JSMN_STRING;
			tmptok.start = 0;
			tmptok.end = strlen(t->token_string);
			tmptok.size = 0;

			*id = tal(ctx, struct node_id);
			if (json_to_node_id(t->token_string, &tmptok, *id))
				return true;
			*id = tal_free(*id);
			return true;
		}
	}
	return false;
}

bool arg_loglevel(const char *name, struct graphql_field *field, void *ctx, enum log_level **ll) {
	struct graphql_argument *arg;
	*ll = NULL;
	if (!field->args || !field->args->first)
		return false;
	for (arg = field->args->first; arg; arg = arg->next) {
		if (arg->name && arg->name->token_type == 'a' &&
		    arg->name->token_string &&
		    streq(arg->name->token_string, name) &&
		    arg->val && arg->val->str_val && arg->val->str_val->val &&
		    arg->val->str_val->val->token_type == 's' &&
		    arg->val->str_val->val->token_string) {
			struct graphql_token *t = arg->val->str_val->val;

			*ll = tal(ctx, enum log_level);
			if (log_level_parse(t->token_string, strlen(t->token_string), *ll))
				return true;
			*ll = tal_free(*ll);
			return true;
		}
	}
	return false;
}

