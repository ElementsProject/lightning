#include <common/graphql_args.h>
#include <common/json_helpers.h>
#include <external/jsmn/jsmn.h>

/* Helper: Get a field argument by name, or NULL */
static struct graphql_argument *find_arg(struct graphql_field *field, const char *argname) {
	struct graphql_argument *arg;
	if (!field || !field->args)
		return NULL;
	for (arg = field->args->first; arg; arg = arg->next) {
		if (arg->name && arg->name->token_type == 'a' &&
		    arg->name->token_string &&
		    streq(arg->name->token_string, argname))
			return arg;
	}
	return NULL;
}

/* Helper: Get a string argument's value, or NULL */
static const char *get_string(struct graphql_argument *arg) {
	if (arg && arg->val && arg->val->str_val && arg->val->str_val->val &&
	    arg->val->str_val->val->token_type == 's' &&
	    arg->val->str_val->val->token_string)
		return arg->val->str_val->val->token_string;
	return NULL;
}

/* Get a node_id argument */
bool arg_node_id(const char *name, struct graphql_field *field, void *ctx, struct node_id **id) {
	const char *str;
	*id = NULL;
	if ((str = get_string(find_arg(field, name)))) {
		/* A hackish way of being able to reuse json_to_node_id */
		jsmntok_t tmptok;
		tmptok.type = JSMN_STRING;
		tmptok.start = 0;
		tmptok.end = strlen(str);
		tmptok.size = 0;

		*id = tal(ctx, struct node_id);
		if (json_to_node_id(str, &tmptok, *id))
			return true;

		*id = tal_free(*id);
		return true;
	}
	return false;
}

/* Get a log_level argument */
bool arg_loglevel(const char *name, struct graphql_field *field, void *ctx, enum log_level **ll) {
	const char *str;
	*ll = NULL;
	if ((str = get_string(find_arg(field, name)))) {

		*ll = tal(ctx, enum log_level);
		if (log_level_parse(str, strlen(str), *ll))
			return true;

		*ll = tal_free(*ll);
		return true;
	}
	return false;
}

