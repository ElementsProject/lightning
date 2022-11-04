#include "config.h"
#include <assert.h>
#include <ccan/strmap/strmap.h>
#include <ccan/tal/str/str.h>
#include <common/json_command.h>
#include <common/json_filter.h>
#include <common/utils.h>

/* If they set a filter, we keep it in a tree. */
struct json_filter {
	/* We accumulate errors: if they treat an array as an object */
	bool misused;

	/* Pointer to parent, or NULL at top. */
	struct json_filter *parent;

	/* Tracks how far we are into filter, e.g.
	 * if they specify "peers.foo" and we're
	 * in "peer.foo.bar" depth will be 1. */
	size_t depth;
	/* If we're in "peer.bar", we're negative */
	bool positive;

	/* If this is an array */
	struct json_filter *filter_array;

	/* Otherwise, object: one per keyword */
	STRMAP(struct json_filter *) filter_map;
};

/* Returns true if we should print this member: this is a shortcut for:
 *
 *   json_filter_down(filter, member);
 *   ret = json_filter_ok(filter, NULL);
 *   json_filter_up(filter);
 *
 */
bool json_filter_ok(const struct json_filter *filter, const char *member)
{
	if (!filter)
		return true;
	if (filter->depth > 0 || !member)
		return filter->positive;
	return strmap_get(&filter->filter_map, member) != NULL;
}

/* Returns true if we should print this new obj/array */
bool json_filter_down(struct json_filter **filter, const char *member)
{
	struct json_filter *child;

	if (!*filter)
		return true;
	if ((*filter)->depth > 0) {
		(*filter)->depth++;
		return (*filter)->positive;
	}

	/* If we're a leaf node: all true. */
	if (!(*filter)->filter_array && strmap_empty(&(*filter)->filter_map)) {
		assert((*filter)->positive);
		(*filter)->depth = 1;
		return true;
	}

	/* Array? */
	if (!member) {
		if (!(*filter)->filter_array) {
			(*filter)->misused = true;
			goto fail;
		}
		child = (*filter)->filter_array;
	} else {
		if ((*filter)->filter_array) {
			(*filter)->misused = true;
			goto fail;
		}
		child = strmap_get(&(*filter)->filter_map, member);
	}

	if (child) {
		/* Should have been cleaned up last time. */
		assert(child->depth == 0);
		/* We only have positive filters natively. */
		assert(child->positive == true);
		*filter = child;
		return true;
	}

	/* OK, this path wasn't specified. */
fail:
	(*filter)->positive = false;
	(*filter)->depth = 1;
	return false;
}

/* Returns true if we were printing (i.e. close object/arr) */
bool json_filter_up(struct json_filter **filter)
{
	if (!*filter)
		return true;

	if ((*filter)->depth == 0) {
		assert((*filter)->parent);
		assert((*filter)->parent->depth == 0);
		/* Reset for next time */
		(*filter)->positive = true;
		*filter = (*filter)->parent;
		return true;
	}

	(*filter)->depth--;
	return (*filter)->positive;
}

static void destroy_json_filter(struct json_filter *filter)
{
	strmap_clear(&filter->filter_map);
}

struct json_filter *json_filter_new(const tal_t *ctx)
{
	struct json_filter *filter = tal(ctx, struct json_filter);
	filter->misused = false;
	filter->parent = NULL;
	filter->depth = 0;
	filter->positive = true;
	filter->filter_array = NULL;
	strmap_init(&filter->filter_map);
	tal_add_destructor(filter, destroy_json_filter);
	return filter;
}

struct json_filter *json_filter_subobj(struct json_filter *filter,
				       const char *fieldname,
				       size_t fieldnamelen)
{
	struct json_filter *subfilter = json_filter_new(filter);
	subfilter->parent = filter;
	strmap_add(&filter->filter_map,
		   tal_strndup(filter, fieldname, fieldnamelen),
		   subfilter);
	return subfilter;
}

struct json_filter *json_filter_subarr(struct json_filter *filter)
{
	struct json_filter *subfilter = json_filter_new(filter);
	subfilter->parent = filter;
	filter->filter_array = subfilter;
	return subfilter;
}

bool json_filter_finished(const struct json_filter *filter)
{
	return !filter->parent && filter->depth == 0;
}

static bool strmap_filter_misused(const char *member,
				  struct json_filter *filter,
				  const char **ret)
{
	*ret = json_filter_misused(tmpctx, filter);
	if (*ret == NULL)
		return true;

	/* If there was a problem, prepend member and stop iterating */
	*ret = tal_fmt(tmpctx, ".%s%s", member, *ret);
	return false;
}

const char *json_filter_misused(const tal_t *ctx, const struct json_filter *f)
{
	const char *ret;

	if (f->misused) {
		if (f->filter_array)
			return tal_fmt(ctx, " is an object");
		else
			return tal_fmt(ctx, " is an array");
	}

	if (f->filter_array) {
		ret = json_filter_misused(tmpctx, f->filter_array);
		if (ret)
			return tal_fmt(ctx, "[]%s", ret);
		return NULL;
	} else {
		ret = NULL;
		strmap_iterate(&f->filter_map, strmap_filter_misused, &ret);
		return tal_steal(ctx, ret);
	}
}

/* Recursively populate filter.  NULL on success.
 *
 * Example for listtransactions to include output type, amount_msat,
 *   {"transactions": [{"outputs": [{"amount_msat": true, "type": true}]}]}
 */
static struct command_result *
build_filter(struct command *cmd,
	     const char *name,
	     const char *buffer,
	     const jsmntok_t *tok,
	     struct json_filter *filter)
{
	struct command_result *ret;
	size_t i;
	const jsmntok_t *t;
	struct json_filter *subf;

	if (tok->type == JSMN_ARRAY) {
		if (tok->size != 1)
			return command_fail_badparam(cmd, name, buffer, tok,
						     "Arrays can only have one element");
		subf = json_filter_subarr(filter);
		return build_filter(cmd, name, buffer, tok + 1, subf);
	}

	json_for_each_obj(i, t, tok) {
		bool is_true;
		const jsmntok_t *val = t + 1;

		if (t->type != JSMN_STRING)
			return command_fail_badparam(cmd, name, buffer, t,
						     "expected string key");
		subf = json_filter_subobj(filter, buffer + t->start, t->end - t->start);
		if (val->type == JSMN_OBJECT || val->type == JSMN_ARRAY) {
			ret = build_filter(cmd, name, buffer, val, subf);
			if (ret)
				return ret;
		} else if (!json_to_bool(buffer, val, &is_true) || !is_true)
			return command_fail_badparam(cmd, name, buffer, val, "value must be true");
	}
	return NULL;
}

struct command_result *parse_filter(struct command *cmd,
				    const char *name,
				    const char *buffer,
				    const jsmntok_t *tok)
{
	struct json_filter **filter = command_filter_ptr(cmd);

	if (tok->type != JSMN_OBJECT)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Expected object");

	*filter = json_filter_new(cmd);
	return build_filter(cmd, name, buffer, tok, *filter);
}
