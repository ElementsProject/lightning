/* JSON core and helpers */
#include "config.h"
#include <assert.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/json_parse_simple.h>
#include <common/utils.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <wire/onion_wire.h>

const char *json_tok_full(const char *buffer, const jsmntok_t *t)
{
	if (t->type == JSMN_STRING)
		return buffer + t->start - 1;
	return buffer + t->start;
}

/* Include " if it's a string. */
int json_tok_full_len(const jsmntok_t *t)
{
	if (t->type == JSMN_STRING)
		return t->end - t->start + 2;
	return t->end - t->start;
}

bool json_tok_strneq(const char *buffer, const jsmntok_t *tok,
		     const char *str, size_t len)
{
	if (tok->type != JSMN_STRING)
		return false;
	return memeq(buffer + tok->start, tok->end - tok->start, str, len);
}

bool json_tok_streq(const char *buffer, const jsmntok_t *tok, const char *str)
{
	return json_tok_strneq(buffer, tok, str, strlen(str));
}

bool json_tok_startswith(const char *buffer, const jsmntok_t *tok,
			 const char *prefix)
{
	if (tok->type != JSMN_STRING)
		return false;
	if (tok->end - tok->start < strlen(prefix))
		return false;
	return memcmp(buffer + tok->start,
		      prefix, strlen(prefix)) == 0;
}

bool json_tok_endswith(const char *buffer, const jsmntok_t *tok,
		       const char *suffix)
{
	if (tok->type != JSMN_STRING)
		return false;
	if (tok->end - tok->start < strlen(suffix))
		return false;
	return memcmp(buffer + tok->end - strlen(suffix),
		      suffix, strlen(suffix)) == 0;
}

char *json_strdup(const tal_t *ctx, const char *buffer, const jsmntok_t *tok)
{
	return tal_strndup(ctx, buffer + tok->start, tok->end - tok->start);
}


bool json_to_u64(const char *buffer, const jsmntok_t *tok, u64 *num)
{
	char *end;
	unsigned long long l;

	l = strtoull(buffer + tok->start, &end, 0);
	if (end != buffer + tok->end)
		return false;

	BUILD_ASSERT(sizeof(l) >= sizeof(*num));
	*num = l;

	/* Check for overflow */
	if (l == ULLONG_MAX && errno == ERANGE)
		return false;

	if (*num != l)
		return false;

	return true;
}

bool json_str_to_u64(const char *buffer, const jsmntok_t *tok, u64 *num)
{
	jsmntok_t temp;
	if (tok->type != JSMN_STRING)
		return false;

	temp = *tok;
	temp.start += 1;
	temp.end -= 1;

	return json_to_u64(buffer, &temp, num);
}

bool json_to_u32(const char *buffer, const jsmntok_t *tok, u32 *num)
{
	uint64_t u64;

	if (!json_to_u64(buffer, tok, &u64))
		return false;
	*num = u64;

	/* Just in case it doesn't fit. */
	if (*num != u64)
		return false;
	return true;
}

bool json_to_bool(const char *buffer, const jsmntok_t *tok, bool *b)
{
	if (tok->type != JSMN_PRIMITIVE)
		return false;
	if (memeqstr(buffer + tok->start, tok->end - tok->start, "true")) {
		*b = true;
		return true;
	}
	if (memeqstr(buffer + tok->start, tok->end - tok->start, "false")) {
		*b = false;
		return true;
	}
	return false;
}


bool json_tok_is_num(const char *buffer, const jsmntok_t *tok)
{
	if (tok->type != JSMN_PRIMITIVE)
		return false;

	for (int i = tok->start; i < tok->end; i++)
		if (!cisdigit(buffer[i]))
			return false;
	return true;
}

bool json_tok_is_null(const char *buffer, const jsmntok_t *tok)
{
	if (tok->type != JSMN_PRIMITIVE)
		return false;
	return buffer[tok->start] == 'n';
}

const jsmntok_t *json_next(const jsmntok_t *tok)
{
	const jsmntok_t *t;
	size_t i;

	for (t = tok + 1, i = 0; i < tok->size; i++)
		t = json_next(t);

	return t;
}

const jsmntok_t *json_get_membern(const char *buffer,
				  const jsmntok_t tok[],
				  const char *label, size_t len)
{
	const jsmntok_t *t;
	size_t i;

	if (tok->type != JSMN_OBJECT)
		return NULL;

	json_for_each_obj(i, t, tok)
		if (json_tok_strneq(buffer, t, label, len))
			return t + 1;

	return NULL;
}

const jsmntok_t *json_get_member(const char *buffer, const jsmntok_t tok[],
				 const char *label)
{
	return json_get_membern(buffer, tok, label, strlen(label));
}

const jsmntok_t *json_get_arr(const jsmntok_t tok[], size_t index)
{
	const jsmntok_t *t;
	size_t i;

	if (tok->type != JSMN_ARRAY)
		return NULL;

	json_for_each_arr(i, t, tok) {
		if (index == 0)
			return t;
		index--;
	}

	return NULL;
}

const char *json_get_id(const tal_t *ctx,
			const char *buffer, const jsmntok_t *obj)
{
	const jsmntok_t *idtok = json_get_member(buffer, obj, "id");
	if (!idtok)
		return NULL;
	return json_strdup(ctx, buffer, idtok);
}

/*-----------------------------------------------------------------------------
JSMN Result Validation Starts
-----------------------------------------------------------------------------*/
/*~ LIBJSMN is a fast, small JSON parsing library.
 *
 * "Fast, small" means it does not, in fact, do a
 * lot of checking for invalid JSON.
 *
 * For example, by itself it would accept the strings
 * `{"1" "2" "3" "4"}` and `["key": 1 2 3 4]` as valid.
 * Obviously those are not in any way valid JSON.
 *
 * This part of the code performs some filtering so
 * that at least some of the invalid JSON that
 * LIBJSMN accepts, will be rejected by
 * json_parse_input.  It also checks that strings are valid UTF-8.
 */

/*~ These functions are used in JSMN validation.
 *
 * The calling convention is that the "current" token
 * is passed in as the first argument, and after the
 * validator, is returned from the function.
 *
 *      p = validate_jsmn_datum(p, end, valid);
 *
 * The reason has to do with typical C ABIs.
 * Usually, the first few arguments are passed in via
 * register, and the return value is also returned
 * via register.
 * This calling convention generally ensures that
 * the current token pointer `p` is always in a
 * register and is never forced into memory by the
 * compiler.
 *
 * These functions are pre-declared here as they
 * are interrecursive.
 * Note that despite the recursion, `p` is only ever
 * advanced, and there is only ever one `p` value,
 * thus the overall algorithm is strict O(n)
 * (*not* amortized) in time.
 * The recursion does mean the algorithm is O(d)
 * in memory (specifically stack frames), where d
 * is the nestedness of objects in the input.
 * This may become an issue later if we are in a
 * stack-limited environment, such as if we actually
 * went and used threads.
 */
/* Validate a *single* datum.  */
static const jsmntok_t *
validate_jsmn_datum(const char *buf,
		    const jsmntok_t *p,
		    const jsmntok_t *end,
		    bool *valid);
/*~ Validate a key-value pair.
 *
 * In JSMN, objects are not dictionaries.
 * Instead, they are a sequence of datums.
 *
 * In fact, objects and arrays in JSMN are "the same",
 * they only differ in delimiter characters.
 *
 * Of course, in "real" JSON, an object is a dictionary
 * of key-value pairs.
 *
 * So what JSMN does is that the syntax "key": "value"
 * is considered a *single* datum, a string "key"
 * that contains a value "value".
 *
 * Indeed, JSMN accepts `["key": "value"]` as well as
 * `{"item1", "item2"}`.
 * The entire point of the validate_jsmn_result function
 * is to reject such improper arrays and objects.
 */
static const jsmntok_t *
validate_jsmn_keyvalue(const char *buf,
		       const jsmntok_t *p,
		       const jsmntok_t *end,
		       bool *valid);

static const jsmntok_t *
validate_jsmn_datum(const char *buf,
		    const jsmntok_t *p,
		    const jsmntok_t *end,
		    bool *valid)
{
	int i;
	int sz;

	if (p >= end) {
		*valid = false;
		return p;
	}

	switch (p->type) {
	case JSMN_STRING:
		if (!utf8_check(buf + p->start, p->end - p->start))
			*valid = false;
		/* Fall thru */
	case JSMN_UNDEFINED:
	case JSMN_PRIMITIVE:
		/* These types should not have sub-datums.  */
		if (p->size != 0)
			*valid = false;
		else
			++p;
		break;

	case JSMN_ARRAY:
		/* Save the array size; we will advance p.  */
		sz = p->size;
		++p;
		for (i = 0; i < sz; ++i) {
			/* Arrays should only contain standard JSON datums.  */
			p = validate_jsmn_datum(buf, p, end, valid);
			if (!*valid)
				break;
		}
		break;

	case JSMN_OBJECT:
		/* Save the object size; we will advance p.  */
		sz = p->size;
		++p;
		for (i = 0; i < sz; ++i) {
			/* Objects should only contain key-value pairs.  */
			p = validate_jsmn_keyvalue(buf, p, end, valid);
			if (!*valid)
				break;
		}
		break;

	default:
		*valid = false;
		break;
	}

	return p;
}
/* Key-value pairs *must* be strings with size 1.  */
static inline const jsmntok_t *
validate_jsmn_keyvalue(const char *buf,
		       const jsmntok_t *p,
		       const jsmntok_t *end,
		       bool *valid)
{
	if (p >= end) {
		*valid = false;
		return p;
	}

	/* Check key.
	 *
	 * JSMN parses the syntax `"key": "value"` as a
	 * JSMN_STRING of size 1, containing the value
	 * datum as a sub-datum.
	 *
	 * Thus, keys in JSON objects are really strings
	 * that "contain" the value, thus we check if
	 * the size is 1.
	 *
	 * JSMN supports a non-standard syntax such as
	 * `"key": 1 2 3 4`, which it considers as a
	 * string object that contains a sequence of
	 * sub-datums 1 2 3 4.
	 * The check below that p->size == 1 also
	 * incidentally rejects that non-standard
	 * JSON.
	 */
	if (p->type != JSMN_STRING || p->size != 1
	    || !utf8_check(buf + p->start, p->end - p->start)) {
		*valid = false;
		return p;
	}

	++p;
	return validate_jsmn_datum(buf, p, end, valid);
}

/** validate_jsmn_parse_output
 *
 * @brief Validates the result of jsmn_parse.
 *
 * @desc LIBJMSN is a small fast library, not a
 * comprehensive library.
 *
 * This simply means that LIBJSMN will accept a
 * *lot* of very strange text that is technically
 * not JSON.
 *
 * For example, LIBJSMN would accept the strings
 * `{"1" "2" "3" "4"}` and `["key": 1 2 3 4]` as valid.
 *
 * This can lead to strange sequences of jsmntok_t
 * objects.
 * Unfortunately, most of our code assumes that
 * the data fed into our JSON-RPC interface is
 * valid JSON, and in particular is not invalid
 * JSON that tickles LIBJSMN into emitting
 * strange sequences of `jsmntok_t`.
 *
 * This function detects such possible problems
 * and returns false if such an issue is found.
 * If so, it is probably unsafe to pass the
 * `jsmntok_t` generated by LIBJSMN to any other
 * parts of our code.
 *
 * @param p - The first jsmntok_t token to process.
 * This function does not assume that semantically
 * only one JSON datum is processed; it does expect
 * a sequence of complete JSON datums (which is
 * what LIBJSMN *should* output).
 * @param end - One past the end of jsmntok_t.
 * Basically, this function is assured to read tokens
 * starting at p up to end - 1.
 * If p >= end, this will not validate anything and
 * trivially return true.
 *
 * @return true if there appears to be no problem
 * with the jsmntok_t sequence outputted by
 * `jsmn_parse`, false otherwise.
 */
static bool
validate_jsmn_parse_output(const char *buf,
			   const jsmntok_t *p, const jsmntok_t *end)
{
	bool valid = true;

	while (p < end && valid)
		p = validate_jsmn_datum(buf, p, end, &valid);

	return valid;
}

/*-----------------------------------------------------------------------------
JSMN Result Validation Ends
-----------------------------------------------------------------------------*/

void toks_reset(jsmntok_t *toks)
{
	assert(tal_count(toks) >= 1);
	toks[0].type = JSMN_UNDEFINED;
}

jsmntok_t *toks_alloc(const tal_t *ctx)
{
	jsmntok_t *toks = tal_arr(ctx, jsmntok_t, 10);
	toks_reset(toks);
	return toks;
}

bool json_parse_input(jsmn_parser *parser,
		      jsmntok_t **toks,
		      const char *input, int len,
		      bool *complete)
{
	int ret;

again:
	ret = jsmn_parse(parser, input, len, *toks, tal_count(*toks) - 1);

	switch (ret) {
	case JSMN_ERROR_INVAL:
		return false;
	case JSMN_ERROR_NOMEM:
		tal_resize(toks, tal_count(*toks) * 2);
		goto again;
	}

	/* Check whether we read at least one full root element, i.e., root
	 * element has its end set. */
	if ((*toks)[0].type == JSMN_UNDEFINED || (*toks)[0].end == -1) {
		*complete = false;
		return true;
	}

	/* If we read a partial element at the end of the stream we'll get a
	 * ret=JSMN_ERROR_PART, but due to the previous check we know we read at
	 * least one full element, so count tokens that are part of this root
	 * element. */
	ret = json_next(*toks) - *toks;

	if (!validate_jsmn_parse_output(input, *toks, *toks + ret))
		return false;

	/* Cut to length and return. */
	tal_resize(toks, ret + 1);
	/* Make sure last one is always referenceable. */
	(*toks)[ret].type = -1;
	(*toks)[ret].start = (*toks)[ret].end = (*toks)[ret].size = 0;

	*complete = true;
	return true;
}

jsmntok_t *json_parse_simple(const tal_t *ctx, const char *input, int len)
{
	bool complete;
	jsmn_parser parser;
	jsmntok_t *toks = toks_alloc(ctx);

	jsmn_init(&parser);

	if (!json_parse_input(&parser, &toks, input, len, &complete)
	    || !complete)
		return tal_free(toks);
	return toks;
}

const char *jsmntype_to_string(jsmntype_t t)
{
	switch (t) {
		case JSMN_UNDEFINED :
			return "UNDEFINED";
		case JSMN_OBJECT :
			return "OBJECT";
		case JSMN_ARRAY :
			return "ARRAY";
		case JSMN_STRING :
			return "STRING";
		case JSMN_PRIMITIVE :
			return "PRIMITIVE";
	}
	return "INVALID";
}

jsmntok_t *json_tok_copy(const tal_t *ctx, const jsmntok_t *tok)
{
	return tal_dup_arr(ctx, jsmntok_t, tok, json_next(tok) - tok, 0);
}

void json_tok_remove(jsmntok_t **tokens,
		     jsmntok_t *obj_or_array, const jsmntok_t *tok, size_t num)
{
	const jsmntok_t *src = tok;
	const jsmntok_t *end = json_next(*tokens);
	jsmntok_t *dest = *tokens + (tok - *tokens);
	int remove_count;

	assert(*tokens);
	assert(obj_or_array->type == JSMN_ARRAY
	       || obj_or_array->type == JSMN_OBJECT);
	/* obj_or_array must be inside tokens, and tok must be inside
	 * obj_or_array */
	assert(obj_or_array >= *tokens
	       && obj_or_array < *tokens + tal_count(*tokens));
	assert(tok >= obj_or_array
	       && tok < *tokens + tal_count(*tokens));

	for (int i = 0; i < num; i++)
		src = json_next(src);

	/* Don't give us a num which goes over end of obj_or_array. */
	assert(src <= json_next(obj_or_array));

	remove_count = src - tok;

	memmove(dest, src, sizeof(jsmntok_t) * (end - src));

	/* Subtract first: this ptr may move after tal_resize! */
	obj_or_array->size -= num;
	tal_resize(tokens, tal_count(*tokens) - remove_count);
}
