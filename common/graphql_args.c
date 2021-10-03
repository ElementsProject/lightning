#include <ccan/graphql/graphql.h>
#include <ccan/list/list.h>
#include <ccan/tal/str/str.h>
#include <common/graphql_args.h>
#include <common/json_helpers.h>
#include <common/json_stream.h>
#include <common/node_id.h>
#include <external/jsmn/jsmn.h>

const char *get_alias(struct graphql_field *field)
{
	const char *alias = field->name->token_string;
	if (field->alias && field->alias->name &&
	    field->alias->name->token_type == 'a' &&
	    field->alias->name->token_string)
		alias = field->alias->name->token_string;
	return alias;
}

/* Helper: Get a string argument's value, or NULL */
static const char *get_string(const struct graphql_argument *arg)
{
	if (arg && arg->val && arg->val->str_val && arg->val->str_val->val &&
	    arg->val->str_val->val->token_type == 's' &&
	    arg->val->str_val->val->token_string)
		return arg->val->str_val->val->token_string;
	return NULL;
}

void get_args(void *ctx, const struct graphql_field *field, ...)
{
	struct graphql_argument *arg;
	va_list ap;
	const char *name;

	va_start(ap, field);
	while ((name = va_arg(ap, const char *)) != NULL) {
		va_arg(ap, int); // is_required
		va_arg(ap, arg_cbx);
		void **var = va_arg(ap, void **);
		va_arg(ap, const char *);
		*var = NULL;
	}
	va_end(ap);

	if (field && field->args) // guard entire for loop
	for (arg = field->args->first; arg; arg = arg->next) {
		bool found;

		found = false;
		va_start(ap, field);
		while ((name = va_arg(ap, const char *)) != NULL) {
			va_arg(ap, int); // is_required
			arg_cbx cbx = va_arg(ap, arg_cbx);
			void **var = va_arg(ap, void **);
			va_arg(ap, const char *);
			if (streq(name, arg->name->token_string)) {
				found = true;
				if (*var) {
					//queue_warning(
					//	js, "ignoring duplicate argument '%s'",
					//	name);
				} else {
					cbx(ctx, get_string(arg), var);
					//if (!*var)
						//queue_warning(
						//	js, "invalid value for agrument '%s'",
						//	name);
				}
				break;
			}
		}
		va_end(ap);

		if (!found)
			//queue_warning(js, "unrecognized argument '%s'",
			//	      arg->name->token_string)
;
	}

	va_start(ap, field);
	while ((name = va_arg(ap, const char *)) != NULL) {
		bool is_required = va_arg(ap, int);
		arg_cbx cbx = va_arg(ap, arg_cbx);
		void **var = va_arg(ap, void **);
		const char *def = va_arg(ap, const char *);
		if (is_required && *var == NULL)
			//queue_warning(js, "missing required argument '%s'",
			//	      name)
;
		if (*var == NULL && def != NULL) {
			cbx(ctx, def, var);
		}
	}
	va_end(ap);
}

/* Helper: Get a field argument by name, or NULL */
/*static struct graphql_argument *find_arg(const struct graphql_field *field,
					 const char *argname)
{
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
*/

void str_to_node_id(void *ctx, const char *str, struct node_id **id)
{
        *id = NULL;
        if (!str)
                return;
        *id = tal(ctx, struct node_id);

	/* A hackish way of being able to reuse json_to_node_id */
	jsmntok_t tmptok;
	tmptok.type = JSMN_STRING;
	tmptok.start = 0;
	tmptok.end = strlen(str);
	tmptok.size = 0;

        if (json_to_node_id(str, &tmptok, *id))
                return;
        *id = tal_free(*id);
}

void str_to_log_level(void *ctx, const char *str, enum log_level **ll)
{
	*ll = NULL;
	if (!str)
		return;
	*ll = tal(ctx, enum log_level);
	if (log_level_parse(str, strlen(str), *ll))
		return;
	*ll = tal_free(*ll);
}

