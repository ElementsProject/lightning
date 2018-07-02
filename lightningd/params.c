#include <ccan/tal/str/str.h>
#include <common/utils.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/lightningd.h>
#include <lightningd/params.h>

struct param {
	const tal_t *ctx;
	char *name;
	bool is_set;
	param_cb cb;
	void *arg;
	size_t argsize;
};

struct param *param_add_(const tal_t *ctx,
			 char *name, param_cb cb, void *arg, size_t argsize)
{
#if DEVELOPER
	assert(name);
	assert(cb);
	assert(arg);
#endif
	struct param *last = tal(tmpctx, struct param);
	last->ctx = ctx;
	last->is_set = false;
	last->name = tal_strdup(last, name);
	last->cb = cb;
	last->arg = arg;
	last->argsize = argsize;
	/* Non-NULL means we are supposed to allocate iff found */
	if (last->ctx)
		*(void **)last->arg = NULL;
	return last;
}

struct param *param_opt_add_(const tal_t *ctx, char *name, const jsmntok_t **tok)
{
	struct param *last = tal(tmpctx, struct param);
	assert(ctx);
	last->ctx = ctx;
	last->is_set = false;
	last->name = tal_strdup(last, name);
	last->cb = (param_cb)json_tok_tok;
	last->arg = tok;
	last->argsize = sizeof(*tok);
	*tok = NULL;
	return last;
}

struct fail_format {
	void *cb;
	const char *format;
};

static struct fail_format fail_formats[] = {
	{json_tok_bool, "'%s' should be 'true' or 'false', not '%.*s'"},
	{json_tok_double, "'%s' should be a double, not '%.*s'"},
	{json_tok_u64, "'%s' should be an unsigned 64 bit integer, not '%.*s'"},
	{json_tok_number, "'%s' should be an integer, not '%.*s'"},
	{json_tok_wtx,
	 "'%s' should be 'all' or a positive integer greater than "
	 "545, not '%.*s'"},
	{NULL, "'%s' of '%.*s' is invalid'"}
};

static const char *find_fail_format(param_cb cb)
{
	struct fail_format *fmt = fail_formats;
	while (fmt->cb != NULL) {
		if (fmt->cb == cb)
			break;
		fmt++;
	}
	return fmt->format;
}

static bool make_callback(struct command *cmd,
			  struct param *def,
			  const char *buffer, const jsmntok_t * tok)
{
	void *arg;
	def->is_set = true;
	if (def->argsize && def->cb != (param_cb)json_tok_tok) {
		*(void **)def->arg
			= arg
			= tal_alloc_(def->ctx, def->argsize, false, false,
				     "param");
	} else
		arg = def->arg;
	if (!def->cb(buffer, tok, arg)) {
		struct json_result *data = new_json_result(cmd);
		const char *val = tal_fmt(cmd, "%.*s", tok->end - tok->start,
					  buffer + tok->start);
		json_object_start(data, NULL);
		json_add_string(data, def->name, val);
		json_object_end(data);
		command_fail_detailed(cmd, JSONRPC2_INVALID_PARAMS, data,
				      find_fail_format(def->cb), def->name,
				      tok->end - tok->start,
				      buffer + tok->start);
		return false;
	}
	return true;
}

static struct param **post_check(struct command *cmd, struct param **params)
{
	struct param **first = params;
	struct param **last = first + tal_count(params);

	/* Make sure required params were provided. */
	while (first != last && (*first)->argsize == 0) {
		if (!(*first)->is_set) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "missing required parameter: '%s'",
				     (*first)->name);
			return NULL;
		}
		first++;
	}
	return params;
}

static struct param **parse_by_position(struct command *cmd,
					struct param **params,
					const char *buffer,
					const jsmntok_t tokens[])
{
	const jsmntok_t *tok = tokens + 1;
	const jsmntok_t *end = json_next(tokens);
	struct param **first = params;
	struct param **last = first + tal_count(params);

	while (first != last && tok != end) {
		if (!json_tok_is_null(buffer, tok))
			if (!make_callback(cmd, *first, buffer, tok))
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
		return NULL;
	}

	return post_check(cmd, params);
}

static struct param *find_param(struct param **params, const char *start,
				size_t n)
{
	struct param **first = params;
	struct param **last = first + tal_count(params);

	while (first != last) {
		if (strncmp((*first)->name, start, n) == 0)
			if (strlen((*first)->name) == n)
				return *first;
		first++;
	}
	return NULL;
}

static struct param **parse_by_name(struct command *cmd,
				    struct param **params,
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
			return NULL;
		}

		if (p->is_set) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "duplicate json names: '%s'", p->name);
			return NULL;
		}

		if (!make_callback(cmd, p, buffer, first + 1))
			return NULL;
		first = json_next(first + 1);
	}
	return post_check(cmd, params);
}

#if DEVELOPER
static int comp_by_name(const void *a, const void *b)
{
	const char *x = (*(const struct param **) a)->name;
	const char *y = (*(const struct param **) b)->name;
	return strcmp(x, y);
}

static int comp_by_arg(const void *a, const void *b)
{
	size_t x = (size_t) ((*(const struct param **) a)->arg);
	size_t y = (size_t) ((*(const struct param **) b)->arg);
	return x - y;
}

/* This comparator is a bit different, but works well.
 * Return 0 if @a is optional and @b is required. Otherwise return 1.
 */
static int comp_req_order(const void *a, const void *b)
{
	bool x = (bool) ((*(const struct param **) a)->argsize == 0);
	bool y = (bool) ((*(const struct param **) b)->argsize == 0);
	if (!x && y)
		return 0;
	return 1;
}

/*
 * Make sure 2 sequential items in @params are not equal (based on
 * provided comparator).
 */
static void check_distinct(struct param **params,
			   int (*compar) (const void *, const void *))
{
	struct param **first = params;
	struct param **last = first + tal_count(params);
	first++;
	while (first != last) {
		assert(compar(first - 1, first) != 0);
		first++;
	}
}

static void check_unique(struct param **copy,
			 int (*compar) (const void *, const void *))
{
	qsort(copy, tal_count(copy), sizeof(struct param *), compar);
	check_distinct(copy, compar);
}

/*
 * Verify consistent internal state.
 */
static void check_params(struct param **params)
{
	if (tal_count(params) < 2)
		return;

	/* make sure there are no required params following optional */
	check_distinct(params, comp_req_order);

	/* duplicate so we can sort */
	struct param **copy = tal_dup_arr(params, struct param *,
					  params, tal_count(params), 0);

	/* check for repeated names and args */
	check_unique(copy, comp_by_name);
	check_unique(copy, comp_by_arg);

	tal_free(copy);
}
#endif

static struct param **param_parse_arr(struct command *cmd,
				      const char *buffer,
				      const jsmntok_t tokens[],
				      struct param **params)
{
#if DEVELOPER
	check_params(params);
#endif
	if (tokens->type == JSMN_ARRAY)
		return parse_by_position(cmd, params, buffer, tokens);
	else if (tokens->type == JSMN_OBJECT)
		return parse_by_name(cmd, params, buffer, tokens);

	command_fail(cmd, JSONRPC2_INVALID_PARAMS,
		     "Expected array or object for params");
	return NULL;
}

struct param **param_parse(struct command *cmd, const char *buffer,
			   const jsmntok_t tokens[], ...)
{
	struct param *def;
	struct param **params = tal_arr(cmd, struct param *, 0);
	va_list ap;
	va_start(ap, tokens);
	while ((def = va_arg(ap, struct param *)) != NULL) {
		tal_steal(params, def);
		tal_resize(&params, tal_count(params) + 1);
		params[tal_count(params) - 1] = def;
	}
	va_end(ap);

	return param_parse_arr(cmd, buffer, tokens, params);
}
