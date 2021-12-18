#include "config.h"
#include <ccan/asort/asort.h>
#include <ccan/tal/str/str.h>
#include <common/json_command.h>
#include <common/json_tok.h>
#include <common/param.h>

struct param {
	const char *name;
	bool is_set;
	bool required;
	param_cbx cbx;
	void *arg;
};

static bool param_add(struct param **params,
		      const char *name, bool required,
		      param_cbx cbx, void *arg)
{
#if DEVELOPER
	if (!(name && cbx && arg))
		return false;
#endif
	struct param last;

	last.is_set = false;
	last.name = name;
	last.required = required;
	last.cbx = cbx;
	last.arg = arg;

	tal_arr_expand(params, last);
	return true;
}

static struct command_result *make_callback(struct command *cmd,
					     struct param *def,
					     const char *buffer,
					     const jsmntok_t *tok)
{
	def->is_set = true;

	return def->cbx(cmd, def->name, buffer, tok, def->arg);
}

static struct command_result *post_check(struct command *cmd,
					 struct param *params)
{
	struct param *first = params;
	struct param *last = first + tal_count(params);

	/* Make sure required params were provided. */
	while (first != last && first->required) {
		if (!first->is_set) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "missing required parameter: %s",
					    first->name);
		}
		first++;
	}
	return NULL;
}

static struct command_result *parse_by_position(struct command *cmd,
						struct param *params,
						const char *buffer,
						const jsmntok_t tokens[],
						bool allow_extra)
{
	struct command_result *res;
	const jsmntok_t *tok;
	size_t i;

	json_for_each_arr(i, tok, tokens) {
		/* check for unexpected trailing params */
		if (i == tal_count(params)) {
			if (!allow_extra) {
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "too many parameters:"
						    " got %u, expected %zu",
						    tokens->size,
						    tal_count(params));
			}
			break;
		}

		if (!json_tok_is_null(buffer, tok)) {
			res = make_callback(cmd, params+i, buffer, tok);
			if (res)
				return res;
		}
	}

	return post_check(cmd, params);
}

static struct param *find_param(struct param *params, const char *start,
				size_t n)
{
	struct param *first = params;
	struct param *last = first + tal_count(params);

	while (first != last) {
		if (strncmp(first->name, start, n) == 0)
			if (strlen(first->name) == n)
				return first;
		first++;
	}
	return NULL;
}

static struct command_result *parse_by_name(struct command *cmd,
					    struct param *params,
					    const char *buffer,
					    const jsmntok_t tokens[],
					    bool allow_extra)
{
	size_t i;
	const jsmntok_t *t;

	json_for_each_obj(i, t, tokens) {
		struct param *p = find_param(params, buffer + t->start,
					     t->end - t->start);
		if (!p) {
			if (!allow_extra) {
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "unknown parameter: %.*s, this may be caused by a failure to autodetect key=value-style parameters. Please try using the -k flag and explicit key=value pairs of parameters.",
						    t->end - t->start,
						    buffer + t->start);
			}
		} else {
			struct command_result *res;

			if (p->is_set) {
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "duplicate json names: %s",
						    p->name);
			}

			res = make_callback(cmd, p, buffer, t + 1);
			if (res)
				return res;
		}
	}
	return post_check(cmd, params);
}

#if DEVELOPER
static int comp_by_name(const struct param *a, const struct param *b,
			void *unused)
{
	return strcmp(a->name, b->name);
}

static int comp_by_arg(const struct param *a, const struct param *b,
		       void *unused)
{
	/* size_t could be larger than int: don't turn a 4bn difference into 0 */
	if (a->arg > b->arg)
		return 1;
	else if (a->arg < b->arg)
		return -1;
	return 0;
}

/* This comparator is a bit different, but works well.
 * Return 0 if @a is optional and @b is required. Otherwise return 1.
 */
static int comp_req_order(const struct param *a, const struct param *b,
			  void *unused)
{
	if (!a->required && b->required)
		return 0;
	return 1;
}

/*
 * Make sure 2 sequential items in @params are not equal (based on
 * provided comparator).
 */
static bool check_distinct(struct param *params,
			   int (*compar) (const struct param *a,
					  const struct param *b, void *unused))
{
	struct param *first = params;
	struct param *last = first + tal_count(params);
	first++;
	while (first != last) {
		if (compar(first - 1, first, NULL) == 0)
			return false;
		first++;
	}
	return true;
}

static bool check_unique(struct param *copy,
			 int (*compar) (const struct param *a,
					const struct param *b, void *unused))
{
	asort(copy, tal_count(copy), compar, NULL);
	return check_distinct(copy, compar);
}

/*
 * Verify consistent internal state.
 */
static bool check_params(struct param *params)
{
	if (tal_count(params) < 2)
		return true;

	/* make sure there are no required params following optional */
	if (!check_distinct(params, comp_req_order))
		return false;

	/* duplicate so we can sort */
	struct param *copy = tal_dup_talarr(params, struct param, params);

	/* check for repeated names and args */
	if (!check_unique(copy, comp_by_name))
		return false;
	if (!check_unique(copy, comp_by_arg))
		return false;

	tal_free(copy);
	return true;
}
#endif

static char *param_usage(const tal_t *ctx,
			 const struct param *params)
{
	char *usage = tal_strdup(ctx, "");
	for (size_t i = 0; i < tal_count(params); i++) {
		if (i != 0)
			tal_append_fmt(&usage, " ");
		if (params[i].required)
			tal_append_fmt(&usage, "%s", params[i].name);
		else
			tal_append_fmt(&usage, "[%s]", params[i].name);
	}
	return usage;
}

static struct command_result *param_arr(struct command *cmd, const char *buffer,
					const jsmntok_t tokens[],
					struct param *params,
					bool allow_extra)
{
#if DEVELOPER
	if (!check_params(params)) {
		return command_fail(cmd, PARAM_DEV_ERROR,
				    "developer error: check_params");
	}
#endif
	if (tokens->type == JSMN_ARRAY)
		return parse_by_position(cmd, params, buffer, tokens, allow_extra);
	else if (tokens->type == JSMN_OBJECT)
		return parse_by_name(cmd, params, buffer, tokens, allow_extra);

	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "Expected array or object for params");
}

const char *param_subcommand(struct command *cmd, const char *buffer,
			     const jsmntok_t tokens[],
			     const char *name, ...)
{
	va_list ap;
	struct param *params = tal_arr(cmd, struct param, 0);
	const char *arg, **names = tal_arr(tmpctx, const char *, 1);
	const char *subcmd;

	param_add(&params, "subcommand", true, (void *)param_string, &subcmd);
	names[0] = name;
	va_start(ap, name);
	while ((arg = va_arg(ap, const char *)) != NULL)
		tal_arr_expand(&names, arg);
	va_end(ap);

	if (command_usage_only(cmd)) {
		char *usage = tal_strdup(cmd, "subcommand");
		for (size_t i = 0; i < tal_count(names); i++)
			tal_append_fmt(&usage, "%c%s",
				       i == 0 ? '=' : '|', names[i]);
		command_set_usage(cmd, usage);
		return NULL;
	}

	/* Check it's valid */
	if (param_arr(cmd, buffer, tokens, params, true) != NULL) {
		return NULL;
	}

	/* Check it's one of the known ones. */
	for (size_t i = 0; i < tal_count(names); i++)
		if (streq(subcmd, names[i]))
			return subcmd;

	/* We really do ignore this. */
	struct command_result *ignore;
	ignore = command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			      "Unknown subcommand '%s'", subcmd);
	assert(ignore);
	return NULL;
}

bool param(struct command *cmd, const char *buffer,
	   const jsmntok_t tokens[], ...)
{
	struct param *params = tal_arr(cmd, struct param, 0);
	const char *name;
	va_list ap;
	bool allow_extra = false;

	va_start(ap, tokens);
	while ((name = va_arg(ap, const char *)) != NULL) {
		bool required = va_arg(ap, int);
		param_cbx cbx = va_arg(ap, param_cbx);
		void *arg = va_arg(ap, void *);
		if (streq(name, "")) {
			allow_extra = true;
			continue;
		}
		if  (!param_add(&params, name, required, cbx, arg)) {
			/* We really do ignore this return! */
			struct command_result *ignore;
			ignore = command_fail(cmd, PARAM_DEV_ERROR,
					      "developer error: param_add %s", name);
			assert(ignore);
			va_end(ap);
			return false;
		}
	}
	va_end(ap);

	if (command_usage_only(cmd)) {
		command_set_usage(cmd, param_usage(cmd, params));
		return false;
	}

	/* Always return false if we're simply checking command parameters;
	 * normally this returns true if all parameters are valid. */
	return param_arr(cmd, buffer, tokens, params, allow_extra) == NULL
		&& !command_check_only(cmd);
}
