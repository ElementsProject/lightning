#include <ccan/asort/asort.h>
#include <ccan/tal/str/str.h>
#include <common/utils.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/lightningd.h>
#include <lightningd/param.h>

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
	struct param *last;

	tal_resize(params, tal_count(*params) + 1);
	last = &(*params)[tal_count(*params) - 1];

	last->is_set = false;
	last->name = name;
	last->required = required;
	last->cbx = cbx;
	last->arg = arg;
	return true;
}

static bool make_callback(struct command *cmd,
			  struct param *def,
			  const char *buffer, const jsmntok_t *tok)
{
	def->is_set = true;

	return def->cbx(cmd, def->name, buffer, tok, def->arg);
}

static bool post_check(struct command *cmd, struct param *params)
{
	struct param *first = params;
	struct param *last = first + tal_count(params);

	/* Make sure required params were provided. */
	while (first != last && first->required) {
		if (!first->is_set) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "missing required parameter: '%s'",
				     first->name);
			return false;
		}
		first++;
	}
	return true;
}

static bool parse_by_position(struct command *cmd,
			      struct param *params,
			      const char *buffer,
			      const jsmntok_t tokens[])
{
	const jsmntok_t *tok = tokens + 1;
	const jsmntok_t *end = json_next(tokens);
	struct param *first = params;
	struct param *last = first + tal_count(params);

	while (first != last && tok != end) {
		if (!json_tok_is_null(buffer, tok))
			if (!make_callback(cmd, first, buffer, tok))
				return NULL;
		tok = json_next(tok);
		first++;
	}

	/* check for unexpected trailing params */
	if (tok != end) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "too many parameters:"
			     " got %u, expected %zu",
			     tokens->size, tal_count(params));
		return false;
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

static bool parse_by_name(struct command *cmd,
			  struct param *params,
			  const char *buffer,
			  const jsmntok_t tokens[])
{
	const jsmntok_t *first = tokens + 1;
	const jsmntok_t *last = json_next(tokens);

	while (first != last) {
		struct param *p = find_param(params, buffer + first->start,
					     first->end - first->start);
		if (!p) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "unknown parameter: '%.*s'",
				     first->end - first->start,
				     buffer + first->start);
			return false;
		}

		if (p->is_set) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "duplicate json names: '%s'", p->name);
			return false;
		}

		if (!make_callback(cmd, p, buffer, first + 1))
			return false;
		first = json_next(first + 1);
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
	struct param *copy = tal_dup_arr(params, struct param,
					 params, tal_count(params), 0);

	/* check for repeated names and args */
	if (!check_unique(copy, comp_by_name))
		return false;
	if (!check_unique(copy, comp_by_arg))
		return false;

	tal_free(copy);
	return true;
}
#endif

static bool param_arr(struct command *cmd, const char *buffer,
		      const jsmntok_t tokens[],
		      struct param *params)
{
#if DEVELOPER
	if (!check_params(params)) {
		command_fail(cmd, PARAM_DEV_ERROR, "developer error");
		return false;
	}
#endif
	if (tokens->type == JSMN_ARRAY)
		return parse_by_position(cmd, params, buffer, tokens);
	else if (tokens->type == JSMN_OBJECT)
		return parse_by_name(cmd, params, buffer, tokens);

	command_fail(cmd, JSONRPC2_INVALID_PARAMS,
		     "Expected array or object for params");
	return false;
}

bool param(struct command *cmd, const char *buffer,
	   const jsmntok_t tokens[], ...)
{
	struct param *params = tal_arr(cmd, struct param, 0);
	const char *name;
	va_list ap;

	va_start(ap, tokens);
	while ((name = va_arg(ap, const char *)) != NULL) {
		bool required = va_arg(ap, int);
		param_cbx cbx = va_arg(ap, param_cbx);
		void *arg = va_arg(ap, void *);
		if  (!param_add(&params, name, required, cbx, arg)) {
			command_fail(cmd, PARAM_DEV_ERROR, "developer error");
			va_end(ap);
			return false;
		}
	}
	va_end(ap);

	return param_arr(cmd, buffer, tokens, params);
}
