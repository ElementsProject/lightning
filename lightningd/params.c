#include <ccan/tal/str/str.h>
#include <common/utils.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/lightningd.h>
#include <lightningd/params.h>

struct param_def {
	char *name;
	bool compulsory;
	bool is_set;
	param_cb cb;
	void *arg;
};

struct param_table {
	struct command *cmd;
	struct param_def *defs;
};

struct param_table *new_param_table(struct command *cmd)
{
	struct param_table *pt = tal(cmd, struct param_table);
	pt->cmd = cmd;
	pt->defs = tal_arr(pt, struct param_def, 0);
	return pt;
};

#if DEVELOPER
static void check_def(const struct param_def *def)
{
	assert(def->name != NULL);
	assert(def->cb != NULL);
	assert(def->arg != NULL);
}

/*
 * Make sure the last parameter is unique
 */
static void check_repeat(struct param_def *first, struct param_def *last)
{
	while (first != last) {
		assert(strcmp(first->name, last->name) != 0);
		assert(first->arg != last->arg);
		first++;
	}
}
#endif

void * param_is_set(struct param_table *pt, void *arg)
{
	struct param_def *first = pt->defs;
	struct param_def *last = first + tal_count(pt->defs);
	while (first != last) {
		if (first->arg == arg)
			return (first->is_set) ? arg : NULL;
		first++;
	}
	abort();
}

void param_add_(struct param_table *pt, char *name, param_cb cb, void *arg)
{
	tal_resize(&pt->defs, tal_count(pt->defs) + 1);
	struct param_def *last = &pt->defs[tal_count(pt->defs) - 1];

#if DEVELOPER
	assert(name);
#endif
	last->name = tal_strdup(pt, name);
	last->cb = cb;
	last->arg = arg;
#if DEVELOPER
	check_def(last);
	check_repeat(pt->defs, last);
#endif
	if (last->name[0] == '?') {
		last->compulsory = false;
		last->name++;
	} else {
		last->compulsory = true;
	}
#if DEVELOPER
	/* check for compulsory after optional */
	if (last != pt->defs) {
		assert(!(last->compulsory && !(last-1)->compulsory));
	}
#endif
}

struct fail_format {
	void * cb;
	const char * format;
};

static struct fail_format fail_formats[] = {
	{ json_tok_bool, "'%s' should be 'true' or 'false', not '%.*s'"},
	{ json_tok_double, "'%s' should be a double, not '%.*s'"},
	{ json_tok_u64, "'%s' should be an unsigned 64 bit integer, not '%.*s'"},
	{ json_tok_newaddr, "'%s' should be 'bech32' or 'p2sh-segwit', not '%.*s'"},
	{ json_tok_number, "'%s' should be an integer, not '%.*s'"},
	{ json_tok_wtx, "'%s' should be 'all' or a positive integer greater than "
		"545, not '%.*s'"},
	{ NULL, "'%s' of '%.*s' is invalid'"}
};

static const char *find_fail_format(param_cb cb)
{
	struct fail_format *first = fail_formats;
	while (first->cb != NULL) {
		if (first->cb == cb)
			break;
		first++;
	}
	return first->format;
}

static bool make_callback(const struct param_table *pt,
			  struct param_def *def,
			  const char *buffer, const jsmntok_t * tok)
{

	def->is_set = false;
	if (tok == NULL) {
		if (def->compulsory) {
			command_fail(pt->cmd, JSONRPC2_INVALID_PARAMS,
				     "missing required parameter: '%s'", def->name);
			return false;
		}
		/*
		 * If the handler is json_tok_tok then we set the arg, a jsmntok_t,
		 * to NULL.  This way, we remain compatible with json_get_params.
		 */
		if (def->cb == (param_cb) json_tok_tok) {
			jsmntok_t **tok = def->arg;
			*tok = NULL;
		}
	} else {
		def->is_set = true;
		if (!def->cb(buffer, tok, def->arg)) {
			struct json_result *data = new_json_result(pt);
			const char *val = tal_fmt(pt, "%.*s",tok->end - tok->start,
						  buffer + tok->start);
			json_object_start(data, NULL);
			json_add_string(data, def->name, val);
			json_object_end(data);
			command_fail_detailed(pt->cmd, JSONRPC2_INVALID_PARAMS, data,
				     find_fail_format(def->cb), def->name,
				     tok->end - tok->start, buffer + tok->start);
			return false;
		}
	}
	return true;
}
/*
 * Return NULL if @tok is NULL, a null json token, or equal to @end.
 * Otherwise return @tok.
 */
static const jsmntok_t *convert_null(const char *buffer,
				     const jsmntok_t *tok,
				     const jsmntok_t *end)
{
	if (tok == end)
		return NULL;
	if (tok && json_tok_is_null(buffer, tok))
		return NULL;
	return tok;
}

static bool parse_by_position(const struct param_table *pt,
			      const char *buffer, const jsmntok_t params[])
{
	const jsmntok_t *p = params + 1;
	const jsmntok_t *end = json_next(params);
	struct param_def *first = &pt->defs[0];
	struct param_def *last = first + tal_count(pt->defs);
	while (first != last) {
		if (!make_callback(pt, first, buffer, convert_null(buffer, p, end)))
			return false;
		if (p != end)
			p = json_next(p);
		first++;
	}

	/* make sure there are no unexpected trailing params */
	if (p != end) {
		command_fail(pt->cmd, JSONRPC2_INVALID_PARAMS,
			     "too many parameters:"
			     " got %u, expected %zu",
			     params->size, tal_count(pt->defs));
		return false;
	}

	return true;
}

static bool parse_by_name(const struct param_table *pt,
			  const char *buffer, const jsmntok_t params[])
{
	struct param_def *first = &pt->defs[0];
	struct param_def *last = first + tal_count(pt->defs);
	size_t num_names = 0;
	const char **names = tal_arr(pt, const char *, num_names + 1);

	while (first != last) {
		const jsmntok_t *p;
		names[num_names] = first->name;
		p = json_get_member(buffer, params, first->name);
		if (!make_callback(pt, first, buffer, convert_null(buffer, p, NULL)))
			return false;

		num_names++;
		tal_resize(&names, num_names + 1);
		first++;
	}

	/* Now make sure there aren't any params which aren't valid */
	/* Find each parameter among the valid names */
	for (const jsmntok_t * t = params + 1, *end = json_next(params);
	     t < end; t = json_next(t + 1)) {
		bool found = false;
		for (size_t i = 0; i < num_names; i++) {
			if (json_tok_streq(buffer, t, names[i]))
				found = true;
		}
		if (!found) {
			command_fail(pt->cmd,
				     JSONRPC2_INVALID_PARAMS,
				     "unknown parameter: '%.*s'",
				     t->end - t->start, buffer + t->start);
			return false;
		}
	}

	tal_free(names);
	return true;
}

bool param_parse(const struct param_table *pt,
		 const char *buffer, const jsmntok_t params[])
{
	if (params->type == JSMN_ARRAY)
		return parse_by_position(pt, buffer, params);
	if (params->type == JSMN_OBJECT)
		return parse_by_name(pt, buffer, params);
	command_fail(pt->cmd, JSONRPC2_INVALID_PARAMS,
		     "Expected array or object for params");
	return false;
}
