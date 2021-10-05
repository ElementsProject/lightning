#include <ccan/graphql/graphql.h>
#include <ccan/list/list.h>
#include <ccan/tal/str/str.h>
#include <common/graphql_args.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/json_stream.h>
#include <common/node_id.h>

const char *get_alias(struct graphql_field *field)
{
	const char *alias = field->name->token_string;
	if (field->alias && field->alias->name &&
	    field->alias->name->token_type == 'a' &&
	    field->alias->name->token_string)
		alias = field->alias->name->token_string;
	return alias;
}

static int count_args(struct graphql_field *field)
{
	int n = 0;
	struct graphql_argument *a;

	if (!field->args)
		return 0;

	for (a = field->args->first; a; a = a->next)
		n++;
	return n;
}

static void convert_string_token(struct graphql_token *t, jsmntok_t *p)
{
	p->type = JSMN_STRING;
	p->start = t->source_offset;
	p->end = t->source_offset + t->source_len;
	p->size = 0;
}

static void convert_primitive_token(struct graphql_token *t, jsmntok_t *p)
{
	p->type = JSMN_PRIMITIVE;
	p->start = t->source_offset;
	p->end = t->source_offset + t->source_len;
	p->size = 0;
}

void convert_args_to_paramtokens(struct graphql_field *field, void *ctx, jsmntok_t **params)
{
	int n = count_args(field);
	struct graphql_argument *a;
	struct graphql_token *t;
	jsmntok_t *p;

	*params = tal_arr(ctx, jsmntok_t, 1 + n * 2);

	p = *params;
	p->type = JSMN_OBJECT;
	p->size = n;
	p++;

	if (!field->args)
		return;

	for (a = field->args->first; a; a = a->next) {
		t = a->name;
		convert_string_token(t, p);
		p++;
		if (a->val->str_val) {
			t = a->val->str_val->val;
			convert_string_token(t, p);
			p++;
		} else if (a->val->int_val) {
			t = a->val->int_val->val;
			convert_primitive_token(t, p);
			p++;
		} else if (a->val->float_val) {
			t = a->val->float_val->val;
			convert_primitive_token(t, p);
			p++;
		} else if (a->val->bool_val) {
			t = a->val->bool_val->val;
			convert_primitive_token(t, p);
			p++;
		} else if (a->val->null_val) {
			t = a->val->null_val->val;
			convert_primitive_token(t, p);
			p++;
		} else if (a->val->enum_val) {
			t = a->val->enum_val->val;
			convert_string_token(t, p);
			p++;
		} else {
			t = a->name;
			convert_string_token(t, p);
			p->end = p->start;
			p++;
		}
	}
}

