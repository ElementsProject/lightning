#include <ccan/graphql/graphql.h>
#include <ccan/list/list.h>
#include <ccan/tal/str/str.h>
#include <common/graphql_util.h>
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

void convert_args_to_paramtokens(const tal_t *ctx, struct graphql_field *field, jsmntok_t **params)
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

struct typelist {
	struct list_head types;
};

struct typenode {
	struct list_node node;
	const char *type_name;
	void *cb_data;
};

void *create_cbd_(struct graphql_field *field, const char *tname, void *ctx, void *obj)
{
	struct typelist *tl;
	struct typenode *tn;

	if (!field->data) {
		tl = field->data = tal(ctx, struct typelist);
		list_head_init(&tl->types);
	} else {
		tl = field->data;
	}

	tn = tal(ctx, struct typenode);
	list_add(&tl->types, &tn->node);
	tn->type_name = tal_strdup(ctx, tname);
	tn->cb_data = obj;

	return obj;
}

void *get_cbd_(const struct graphql_field *field, const char *tname)
{
	struct typelist *tl;
	struct typenode *tn = NULL, *n;

	if (!field->data)
		return NULL;
	tl = field->data;
	list_for_each(&tl->types, n, node) {
		if (streq(n->type_name, tname))
			tn = n;
	}
	if (!tn)
		return NULL;

	return tn->cb_data;
}

struct command_result *
object_prep(struct command *cmd, const char *buffer,
	    struct graphql_field *field, struct gqlcb_fieldspec *table,
	    struct gqlcb_data *d)
{
	struct graphql_selection *sel;
	struct command_result *err;

	if (field->sel_set) {
		for (sel = field->sel_set->first; sel; sel = sel->next) {
			err = field_prep(cmd, buffer, sel->field, table, d);
			if (err)
				return err;
			//if ((err = field_search(cmd, buffer, sel->field, table, d)))
			//	return err;
		}
	}

	return NULL;
}

struct command_result *
field_prep_typed(struct command *cmd, const char *buffer,
		 struct graphql_field *field, struct gqlcb_fieldspec table[],
		 void *parent, const char *tname, bool required)
{
	struct gqlcb_data *d;
	jsmntok_t *params;
	struct command_result *err;
	struct gqlcb_fieldspec *f = gqlcb_search(field, table);

	if (!f) {
		if (!required) {
			return NULL;
		} else {
			const char *b = tal_strdup(cmd, "");
			for (f = &table[0]; f->field_name; f++) {
				b = tal_strcat(cmd, take(b), ", ");
				b = tal_strcat(cmd, take(b), f->field_name);
			}
			return command_fail(cmd, GRAPHQL_FIELD_ERROR,
					    "unknown field '%s'; recognized fields are: %s",
					    field->name->token_string, b+2);
		}
	}

	if (tname)
		d = create_cbd(field, tname, cmd, struct gqlcb_data);
	else
		field->data = d = tal(cmd, struct gqlcb_data);
	d->name = get_alias(field);
	d->parent = parent;
	d->fieldspec = f;
	d->field = field;

	if (f->disable_alias) {
		NO_ALIAS_SUPPORT(cmd, field);
	}

	if (!f->arg_parser) {
		NO_ARGS(cmd, field);
	} else {
		if (!field->args) {
			field->args = tal(cmd, struct graphql_arguments);
			field->args->first = NULL;
			field->args->data = NULL;
		}
		convert_args_to_paramtokens(cmd, field, &params);
		if ((err = f->arg_parser(cmd, buffer, params, d)))
			return err;
	}

	if (f->disable_subfield_selection) {
		NO_SUBFIELD_SELECTION(cmd, field);
	} else if (!f->has_subfields) {
		NO_SUBFIELDS(cmd, field);
	} else {
		if (!field->sel_set) {
			field->sel_set = tal(cmd, struct graphql_selection_set);
			field->sel_set->first = NULL;
			field->sel_set->data = NULL;
		}
		if ((err = f->subfield_prepper(cmd, buffer, field, f->subtable, d)))
			return err;
	}

	return NULL;
}

struct gqlcb_fieldspec *gqlcb_search(struct graphql_field *field,
				     struct gqlcb_fieldspec list[])
{
	const char *name = field->name->token_string;
	struct gqlcb_fieldspec *f;

	// FIXME: replace with faster search
	for (f = &list[0]; f->field_name; f++) {
		if (streq(name, f->field_name)) {
			return f;
		}
	}

	return NULL;
}

/*
struct command_result *
field_search(struct command *cmd, const char *buffer,
	     struct graphql_field *field, struct gqlcb_fieldspec list[],
	     struct gqlcb_data *parent)
{
	const char *name = field->name->token_string;
	struct gqlcb_fieldspec *f;

	// FIXME: replace with binary search
	for (f = &list[0]; f->field_name; f++) {
		if (streq(name, f->field_name)) {
			return field_prep(cmd, buffer, field, f, parent);
		}
	}

	return command_fail(cmd, GRAPHQL_FIELD_ERROR,
			    "unknown field '%s'", name);
}
*/
