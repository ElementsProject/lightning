/* JSON core and helpers */
#include "config.h"
#include <assert.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/json.h>
#include <common/json_stream.h>
#include <common/overflows.h>
#include <common/utils.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>

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

bool json_to_u64(const char *buffer, const jsmntok_t *tok,
		  uint64_t *num)
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

bool json_to_s64(const char *buffer, const jsmntok_t *tok, s64 *num)
{
	char *end;
	long long l;

	l = strtoll(buffer + tok->start, &end, 0);
	if (end != buffer + tok->end)
		return false;

	BUILD_ASSERT(sizeof(l) >= sizeof(*num));
	*num = l;

	/* Check for overflow/underflow */
	if ((l == LONG_MAX || l == LONG_MIN) && errno == ERANGE)
		return false;

	/* Check if the number did not fit in `s64` (in case `long long`
	is a bigger type). */
	if (*num != l)
		return false;

	return true;
}

bool json_to_millionths(const char *buffer, const jsmntok_t *tok,
			u64 *millionths)
{
	int decimal_places = -1;
	bool has_digits = 0;

	*millionths = 0;
	for (int i = tok->start; i < tok->end; i++) {
		if (isdigit(buffer[i])) {
			has_digits = true;
			/* Ignore too much precision */
			if (decimal_places >= 0 && ++decimal_places > 6)
				continue;
			if (mul_overflows_u64(*millionths, 10))
				return false;
			*millionths *= 10;
			if (add_overflows_u64(*millionths, buffer[i] - '0'))
				return false;
			*millionths += buffer[i] - '0';
		} else if (buffer[i] == '.') {
			if (decimal_places != -1)
				return false;
			decimal_places = 0;
		} else
			return false;
	}

	if (!has_digits)
		return false;

	if (decimal_places == -1)
		decimal_places = 0;

	while (decimal_places < 6) {
		if (mul_overflows_u64(*millionths, 10))
			return false;
		*millionths *= 10;
		decimal_places++;
	}
	return true;
}

bool json_to_number(const char *buffer, const jsmntok_t *tok,
		    unsigned int *num)
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

bool json_to_u16(const char *buffer, const jsmntok_t *tok,
		 short unsigned int *num)
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

bool json_to_u32(const char *buffer, const jsmntok_t *tok,
		 uint32_t *num)
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

bool json_to_int(const char *buffer, const jsmntok_t *tok, int *num)
{
	s64 tmp;

	if (!json_to_s64(buffer, tok, &tmp))
		return false;
	*num = tmp;

	/* Just in case it doesn't fit. */
	if (*num != tmp)
		return false;

	return true;
}

bool json_to_errcode(const char *buffer, const jsmntok_t *tok, errcode_t *errcode)
{
	s64 tmp;

	if (!json_to_s64(buffer, tok, &tmp))
		return false;
	*errcode = tmp;

	/* Just in case it doesn't fit. */
	if (*errcode != tmp)
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

bool json_to_sha256(const char *buffer, const jsmntok_t *tok, struct sha256 *dest)
{
	if (tok->type != JSMN_STRING)
		return false;

	return hex_decode(buffer + tok->start, tok->end - tok->start, dest,
			  sizeof(struct sha256));
}

u8 *json_tok_bin_from_hex(const tal_t *ctx, const char *buffer, const jsmntok_t *tok)
{
	u8 *result;
	size_t hexlen, rawlen;
	hexlen = tok->end - tok->start;
	rawlen = hex_data_size(hexlen);

	result = tal_arr(ctx, u8, rawlen);
	if (!hex_decode(buffer + tok->start, hexlen, result, rawlen))
		return tal_free(result);

	return result;
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

static const jsmntok_t *json_get_membern(const char *buffer,
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

/* talfmt take a ctx pointer and return NULL or a valid pointer.
 * fmt takes the argument, and returns a bool.
 *
 * This function returns NULL on success, or errmsg on failure.
*/
static const char *handle_percent(const char *buffer,
				  const jsmntok_t *tok,
				  va_list *ap)
{
	void *ctx;
	const char *fmtname;

	/* This is set to (dummy) json_scan if it's a non-tal fmt */
	ctx = va_arg(*ap, void *);
	fmtname = va_arg(*ap, const char *);
	if (ctx != json_scan) {
		void *(*talfmt)(void *, const char *, const jsmntok_t *);
		void **p;
		p = va_arg(*ap, void **);
		talfmt = va_arg(*ap, void *(*)(void *, const char *, const jsmntok_t *));
		*p = talfmt(ctx, buffer, tok);
		if (*p != NULL)
			return NULL;
	} else {
		bool (*fmt)(const char *, const jsmntok_t *, void *);
		void *p;

		p = va_arg(*ap, void *);
		fmt = va_arg(*ap, bool (*)(const char *, const jsmntok_t *, void *));
		if (fmt(buffer, tok, p))
			return NULL;
	}

	return tal_fmt(tmpctx, "%s could not parse %.*s",
		       fmtname,
		       json_tok_full_len(tok),
		       json_tok_full(buffer, tok));
}

/* GUIDE := OBJ | ARRAY | '%'
 * OBJ := '{' FIELDLIST '}'
 * FIELDLIST := FIELD [',' FIELD]*
 * FIELD := LITERAL ':' FIELDVAL
 * FIELDVAL := OBJ | ARRAY | LITERAL | '%'
 * ARRAY := '[' ARRLIST ']'
 * ARRLIST := ARRELEM [',' ARRELEM]*
 * ARRELEM := NUMBER ':' FIELDVAL
 */

static void parse_literal(const char **guide,
			  const char **literal,
			  size_t *len)
{
	*literal = *guide;
	*len = strspn(*guide,
		      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		      "abcdefghijklmnopqrstuvwxyz"
		      "0123456789"
		      "_-");
	*guide += *len;
}

static void parse_number(const char **guide, u32 *number)
{
	char *endp;
	long int l;

	l = strtol(*guide, &endp, 10);
	assert(endp != *guide);
	assert(errno != ERANGE);

	/* Test for overflow */
	*number = l;
	assert(*number == l);

	*guide = endp;
}

static char guide_consume_one(const char **guide)
{
	char c = **guide;
	(*guide)++;
	return c;
}

static void guide_must_be(const char **guide, char c)
{
	char actual = guide_consume_one(guide);
	assert(actual == c);
}

/* Recursion: return NULL on success, errmsg on fail */
static const char *parse_obj(const char *buffer,
			     const jsmntok_t *tok,
			     const char **guide,
			     va_list *ap);

static const char *parse_arr(const char *buffer,
			     const jsmntok_t *tok,
			     const char **guide,
			     va_list *ap);

static const char *parse_guide(const char *buffer,
			       const jsmntok_t *tok,
			       const char **guide,
			       va_list *ap)
{
	const char *errmsg;

	if (**guide == '{') {
		errmsg = parse_obj(buffer, tok, guide, ap);
		if (errmsg)
			return errmsg;
	} else if (**guide == '[') {
		errmsg = parse_arr(buffer, tok, guide, ap);
		if (errmsg)
			return errmsg;
	} else {
		guide_must_be(guide, '%');
		errmsg = handle_percent(buffer, tok, ap);
		if (errmsg)
			return errmsg;
	}
	return NULL;
}

static const char *parse_fieldval(const char *buffer,
				  const jsmntok_t *tok,
				  const char **guide,
				  va_list *ap)
{
	const char *errmsg;

	if (**guide == '{') {
		errmsg = parse_obj(buffer, tok, guide, ap);
		if (errmsg)
			return errmsg;
	} else if (**guide == '[') {
		errmsg = parse_arr(buffer, tok, guide, ap);
		if (errmsg)
			return errmsg;
	} else if (**guide == '%') {
		guide_consume_one(guide);
		errmsg = handle_percent(buffer, tok, ap);
		if (errmsg)
			return errmsg;
	} else {
		const char *literal;
		size_t len;

		/* Literal must match exactly (modulo quotes for strings) */
		parse_literal(guide, &literal, &len);
		if (!memeq(buffer + tok->start, tok->end - tok->start,
			   literal, len)) {
			return tal_fmt(tmpctx,
				       "%.*s does not match expected %.*s",
				       json_tok_full_len(tok),
				       json_tok_full(buffer, tok),
				       (int)len, literal);
		}
	}
	return NULL;
}

static const char *parse_field(const char *buffer,
			       const jsmntok_t *tok,
			       const char **guide,
			       va_list *ap)
{
	const jsmntok_t *member;
	size_t len;
	const char *memname;

	parse_literal(guide, &memname, &len);
	guide_must_be(guide, ':');

	member = json_get_membern(buffer, tok, memname, len);
	if (!member) {
		return tal_fmt(tmpctx, "object does not have member %.*s",
			       (int)len, memname);
	}

	return parse_fieldval(buffer, member, guide, ap);
}

static const char *parse_fieldlist(const char *buffer,
				   const jsmntok_t *tok,
				   const char **guide,
				   va_list *ap)
{
	for (;;) {
		const char *errmsg;

		errmsg = parse_field(buffer, tok, guide, ap);
		if (errmsg)
			return errmsg;
		if (**guide != ',')
			break;
		guide_consume_one(guide);
	}
	return NULL;
}

static const char *parse_obj(const char *buffer,
			     const jsmntok_t *tok,
			     const char **guide,
			     va_list *ap)
{
	const char *errmsg;

	guide_must_be(guide, '{');

	if (tok->type != JSMN_OBJECT) {
		return tal_fmt(tmpctx, "token is not an object: %.*s",
			       json_tok_full_len(tok),
			       json_tok_full(buffer, tok));
	}

	errmsg = parse_fieldlist(buffer, tok, guide, ap);
	if (errmsg)
		return errmsg;

	guide_must_be(guide, '}');
	return NULL;
}

static const char *parse_arrelem(const char *buffer,
				 const jsmntok_t *tok,
				 const char **guide,
				 va_list *ap)
{
	const jsmntok_t *member;
	u32 idx;

	parse_number(guide, &idx);
	guide_must_be(guide, ':');

	member = json_get_arr(tok, idx);
	if (!member) {
		return tal_fmt(tmpctx, "token has no index %u: %.*s",
			       idx,
			       json_tok_full_len(tok),
			       json_tok_full(buffer, tok));
	}

	return parse_fieldval(buffer, member, guide, ap);
}

static const char *parse_arrlist(const char *buffer,
				 const jsmntok_t *tok,
				 const char **guide,
				 va_list *ap)
{
	const char *errmsg;

	for (;;) {
		errmsg = parse_arrelem(buffer, tok, guide, ap);
		if (errmsg)
			return errmsg;
		if (**guide != ',')
			break;
		guide_consume_one(guide);
	}
	return NULL;
}

static const char *parse_arr(const char *buffer,
			     const jsmntok_t *tok,
			     const char **guide,
			     va_list *ap)
{
	const char *errmsg;

	guide_must_be(guide, '[');

	if (tok->type != JSMN_ARRAY) {
		return tal_fmt(tmpctx, "token is not an array: %.*s",
			       json_tok_full_len(tok),
			       json_tok_full(buffer, tok));
	}

	errmsg = parse_arrlist(buffer, tok, guide, ap);
	if (errmsg)
		return errmsg;

	guide_must_be(guide, ']');
	return NULL;
}

const char *json_scanv(const tal_t *ctx,
		       const char *buffer,
		       const jsmntok_t *tok,
		       const char *guide,
		       va_list ap)
{
	va_list cpy;
	const char *orig_guide = guide, *errmsg;

	/* We need this, since &ap doesn't work on some platforms... */
	va_copy(cpy, ap);
	errmsg = parse_guide(buffer, tok, &guide, &cpy);
	va_end(cpy);

	if (errmsg) {
		return tal_fmt(ctx, "Parsing '%.*s': %s",
			       (int)(guide - orig_guide), orig_guide,
			       errmsg);
	}
	assert(guide[0] == '\0');
	return NULL;
}

const char *json_scan(const tal_t *ctx,
		      const char *buffer,
		      const jsmntok_t *tok,
		      const char *guide,
		      ...)
{
	va_list ap;
	const char *ret;

	va_start(ap, guide);
	ret = json_scanv(ctx, buffer, tok, guide, ap);
	va_end(ap);
	return ret;
}

void json_add_num(struct json_stream *result, const char *fieldname, unsigned int value)
{
	json_add_member(result, fieldname, false, "%u", value);
}

void json_add_u64(struct json_stream *result, const char *fieldname,
		  uint64_t value)
{
	json_add_member(result, fieldname, false, "%"PRIu64, value);
}

void json_add_s64(struct json_stream *result, const char *fieldname,
		  int64_t value)
{
	json_add_member(result, fieldname, false, "%"PRIi64, value);
}

void json_add_u32(struct json_stream *result, const char *fieldname,
		  uint32_t value)
{
	json_add_member(result, fieldname, false, "%u", value);
}

void json_add_s32(struct json_stream *result, const char *fieldname,
		  int32_t value)
{
	json_add_member(result, fieldname, false, "%d", value);
}

void json_add_literal(struct json_stream *result, const char *fieldname,
		      const char *literal, int len)
{
	/* Literal may contain quotes, so bypass normal checks */
	char *dest = json_member_direct(result, fieldname, len);
	if (dest)
		memcpy(dest, literal, len);
}

void json_add_stringn(struct json_stream *result, const char *fieldname,
		      const char *value TAKES, size_t value_len)
{
	json_add_member(result, fieldname, true, "%.*s", (int)value_len, value);
	if (taken(value))
		tal_free(value);
}

void json_add_string(struct json_stream *result, const char *fieldname, const char *value TAKES)
{
	json_add_stringn(result, fieldname, value, strlen(value));
}

void json_add_bool(struct json_stream *result, const char *fieldname, bool value)
{
	json_add_member(result, fieldname, false, value ? "true" : "false");
}

void json_add_null(struct json_stream *stream, const char *fieldname)
{
	json_add_member(stream, fieldname, false, "null");
}

void json_add_hex(struct json_stream *js, const char *fieldname,
		  const void *data, size_t len)
{
	/* Size without NUL term */
	size_t hexlen = hex_str_size(len) - 1;
	char *dest;

	dest = json_member_direct(js, fieldname, 1 + hexlen + 1);
	if (dest) {
		dest[0] = '"';
		if (!hex_encode(data, len, dest + 1, hexlen + 1))
			abort();
		dest[1+hexlen] = '"';
	}
}

void json_add_hex_talarr(struct json_stream *result,
			 const char *fieldname,
			 const tal_t *data)
{
	json_add_hex(result, fieldname, data, tal_bytelen(data));
}

void json_add_escaped_string(struct json_stream *result, const char *fieldname,
			     const struct json_escape *esc TAKES)
{
	/* Already escaped, don't re-escape! */
	char *dest = json_member_direct(result,	fieldname,
					1 + strlen(esc->s) + 1);

	if (dest) {
		dest[0] = '"';
		memcpy(dest + 1, esc->s, strlen(esc->s));
		dest[1+strlen(esc->s)] = '"';
	}
	if (taken(esc))
		tal_free(esc);
}

void json_add_timeabs(struct json_stream *result, const char *fieldname,
		      struct timeabs t)
{
	json_add_member(result, fieldname, false, "%" PRIu64 ".%03" PRIu64,
			(u64)t.ts.tv_sec, (u64)t.ts.tv_nsec / 1000000);
}

void json_add_time(struct json_stream *result, const char *fieldname,
			  struct timespec ts)
{
	char timebuf[100];

	snprintf(timebuf, sizeof(timebuf), "%lu.%09u",
		(unsigned long)ts.tv_sec,
		(unsigned)ts.tv_nsec);
	json_add_string(result, fieldname, timebuf);
}

void json_add_timeiso(struct json_stream *result,
		      const char *fieldname,
		      struct timeabs *time)
{
	char iso8601_msec_fmt[sizeof("YYYY-mm-ddTHH:MM:SS.%03dZ")];
	char iso8601_s[sizeof("YYYY-mm-ddTHH:MM:SS.nnnZ")];

	strftime(iso8601_msec_fmt, sizeof(iso8601_msec_fmt),
		 "%FT%T.%%03dZ", gmtime(&time->ts.tv_sec));
	snprintf(iso8601_s, sizeof(iso8601_s),
		 iso8601_msec_fmt, (int) time->ts.tv_nsec / 1000000);

	json_add_string(result, fieldname, iso8601_s);
}


void json_add_tok(struct json_stream *result, const char *fieldname,
                  const jsmntok_t *tok, const char *buffer)
{
	char *space;
	assert(tok->type != JSMN_UNDEFINED);

	space = json_member_direct(result, fieldname, json_tok_full_len(tok));
	memcpy(space, json_tok_full(buffer, tok), json_tok_full_len(tok));
}

void json_add_errcode(struct json_stream *result, const char *fieldname,
		      errcode_t code)
{
	json_add_member(result, fieldname, false, "%"PRIerrcode, code);
}

void json_add_invstring(struct json_stream *result, const char *invstring)
{
	if (strstarts(invstring, "lni"))
		json_add_string(result, "bolt12", invstring);
	else
		json_add_string(result, "bolt11", invstring);
}
