/* JSON core and helpers */
#include "json.h"
#include "json_escaped.h"
#include <assert.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

struct json_result {
	/* tal_arr of types we're enclosed in. */
	jsmntype_t *wrapping;

	/* tal_count() of this is strlen() + 1 */
	char *s;
};

const char *json_tok_contents(const char *buffer, const jsmntok_t *t)
{
	if (t->type == JSMN_STRING)
		return buffer + t->start - 1;
	return buffer + t->start;
}

/* Include " if it's a string. */
int json_tok_len(const jsmntok_t *t)
{
	if (t->type == JSMN_STRING)
		return t->end - t->start + 2;
	return t->end - t->start;
}

bool json_tok_streq(const char *buffer, const jsmntok_t *tok, const char *str)
{
	if (tok->type != JSMN_STRING)
		return false;
	if (tok->end - tok->start != strlen(str))
		return false;
	return strncmp(buffer + tok->start, str, tok->end - tok->start) == 0;
}

bool json_tok_u64(const char *buffer, const jsmntok_t *tok,
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

bool json_tok_double(const char *buffer, const jsmntok_t *tok, double *num)
{
	char *end;

	*num = strtod(buffer + tok->start, &end);
	if (end != buffer + tok->end)
		return false;
	return true;
}

bool json_tok_percent(const char *buffer, const jsmntok_t *tok, double *num)
{
	if (!json_tok_double(buffer, tok, num))
		return false;

	/* Ensure it is in the range [0.0, 100.0] */
	if (!(0.0 <= *num))
		return false;

	if (!(*num <= 100.0))
		return false;

	return true;
}

bool json_tok_number(const char *buffer, const jsmntok_t *tok,
		     unsigned int *num)
{
	uint64_t u64;

	if (!json_tok_u64(buffer, tok, &u64))
		return false;
	*num = u64;

	/* Just in case it doesn't fit. */
	if (*num != u64)
		return false;
	return true;
}

bool json_tok_bitcoin_amount(const char *buffer, const jsmntok_t *tok,
			     uint64_t *satoshi)
{
	char *end;
	unsigned long btc, sat;

	btc = strtoul(buffer + tok->start, &end, 10);
	if (btc == ULONG_MAX && errno == ERANGE)
		return false;
	if (end != buffer + tok->end) {
		/* Expect always 8 decimal places. */
		if (*end != '.' || buffer + tok->end - end != 9)
			return false;
		sat = strtoul(end+1, &end, 10);
		if (sat == ULONG_MAX && errno == ERANGE)
			return false;
		if (end != buffer + tok->end)
			return false;
	} else
		sat = 0;

	*satoshi = btc * (uint64_t)100000000 + sat;
	if (*satoshi != btc * (uint64_t)100000000 + sat)
		return false;

	return true;
}

bool json_tok_is_null(const char *buffer, const jsmntok_t *tok)
{
	if (tok->type != JSMN_PRIMITIVE)
		return false;
	return buffer[tok->start] == 'n';
}

bool json_tok_bool(const char *buffer, const jsmntok_t *tok, bool *b)
{
	if (tok->type != JSMN_PRIMITIVE)
		return false;
	if (tok->end - tok->start == strlen("true")
	    && memcmp(buffer + tok->start, "true", strlen("true")) == 0) {
		*b = true;
		return true;
	}
	if (tok->end - tok->start == strlen("false")
	    && memcmp(buffer + tok->start, "false", strlen("false")) == 0) {
		*b = false;
		return true;
	}
	return false;
}

bool json_tok_sha256(const char *buffer, const jsmntok_t * tok,
		     struct sha256 *hash)
{
	return hex_decode(buffer + tok->start,
			  tok->end - tok->start,
			  hash, sizeof(*hash));
}

bool json_tok_tok(const char *buffer, const jsmntok_t * tok,
		  const jsmntok_t **out)
{
	*out = tok;
	return true;
}

const jsmntok_t *json_next(const jsmntok_t *tok)
{
	const jsmntok_t *t;
	size_t i;

	for (t = tok + 1, i = 0; i < tok->size; i++)
		t = json_next(t);

	return t;
}

const jsmntok_t *json_get_member(const char *buffer, const jsmntok_t tok[],
				 const char *label)
{
	const jsmntok_t *t, *end;

	if (tok->type != JSMN_OBJECT)
		return NULL;

	end = json_next(tok);
	for (t = tok + 1; t < end; t = json_next(t+1))
		if (json_tok_streq(buffer, t, label))
			return t + 1;

	return NULL;
}

const jsmntok_t *json_get_arr(const jsmntok_t tok[], size_t index)
{
	const jsmntok_t *t, *end;

	if (tok->type != JSMN_ARRAY)
		return NULL;

	end = json_next(tok);
	for (t = tok + 1; t < end; t = json_next(t)) {
		if (index == 0)
			return t;
		index--;
	}

	return NULL;
}

jsmntok_t *json_parse_input(const char *input, int len, bool *valid)
{
	jsmn_parser parser;
	jsmntok_t *toks;
	int ret;

	toks = tal_arr(input, jsmntok_t, 10);

again:
	jsmn_init(&parser);
	ret = jsmn_parse(&parser, input, len, toks, tal_count(toks) - 1);

	switch (ret) {
	case JSMN_ERROR_INVAL:
		*valid = false;
		return tal_free(toks);
	case JSMN_ERROR_PART:
		*valid = true;
		return tal_free(toks);
	case JSMN_ERROR_NOMEM:
		tal_resize(&toks, tal_count(toks) * 2);
		goto again;
	}

	/* Cut to length and return. */
	*valid = true;
	tal_resize(&toks, ret + 1);
	/* Make sure last one is always referenceable. */
	toks[ret].type = -1;
	toks[ret].start = toks[ret].end = toks[ret].size = 0;

	return toks;
}

static void result_append(struct json_result *res, const char *str)
{
	size_t len = tal_count(res->s) - 1;

	tal_resize(&res->s, len + strlen(str) + 1);
	strcpy(res->s + len, str);
}

static void PRINTF_FMT(2,3)
result_append_fmt(struct json_result *res, const char *fmt, ...)
{
	size_t len = tal_count(res->s) - 1, fmtlen;
	va_list ap;

	va_start(ap, fmt);
	fmtlen = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	tal_resize(&res->s, len + fmtlen + 1);
	va_start(ap, fmt);
	vsprintf(res->s + len, fmt, ap);
	va_end(ap);
}

static bool result_ends_with(struct json_result *res, const char *str)
{
	size_t len = tal_count(res->s) - 1;

	if (strlen(str) > len)
		return false;
	return streq(res->s + len - strlen(str), str);
}

static void check_fieldname(const struct json_result *result,
			    const char *fieldname)
{
	size_t n = tal_count(result->wrapping);
	if (n == 0)
		/* Can't have a fieldname if not in anything! */
		assert(!fieldname);
	else if (result->wrapping[n-1] == JSMN_ARRAY)
		/* No fieldnames in arrays. */
		assert(!fieldname);
	else
		/* Must have fieldnames in objects. */
		assert(fieldname);
}

static void result_add_indent(struct json_result *result);

	static void json_start_member(struct json_result *result, const char *fieldname)
{
	/* Prepend comma if required. */
	if (result->s[0]
	    && !result_ends_with(result, "{")
	    && !result_ends_with(result, "["))
		result_append(result, ", \n");
	else
		result_append(result, "\n");

	result_add_indent(result);

	check_fieldname(result, fieldname);
	if (fieldname)
		result_append_fmt(result, "\"%s\": ", fieldname);
}

static void result_add_indent(struct json_result *result)
{
	size_t i, indent = tal_count(result->wrapping);

	if (!indent)
		return;

	for (i = 0; i < indent; i++)
		result_append(result, "  ");
}

static void result_add_wrap(struct json_result *result, jsmntype_t type)
{
	size_t indent = tal_count(result->wrapping);

	tal_resize(&result->wrapping, indent+1);
	result->wrapping[indent] = type;
}

static void result_pop_wrap(struct json_result *result, jsmntype_t type)
{
	size_t indent = tal_count(result->wrapping);

	assert(indent);
	assert(result->wrapping[indent-1] == type);
	tal_resize(&result->wrapping, indent-1);
}

void json_array_start(struct json_result *result, const char *fieldname)
{
	json_start_member(result, fieldname);
	result_append(result, "[");
	result_add_wrap(result, JSMN_ARRAY);
}

void json_array_end(struct json_result *result)
{
	result_append(result, "\n");
	result_pop_wrap(result, JSMN_ARRAY);
	result_add_indent(result);
	result_append(result, "]");
}

void json_object_start(struct json_result *result, const char *fieldname)
{
	json_start_member(result, fieldname);
	result_append(result, "{");
	result_add_wrap(result, JSMN_OBJECT);
}

void json_object_end(struct json_result *result)
{
	result_append(result, "\n");
	result_pop_wrap(result, JSMN_OBJECT);
	result_add_indent(result);
	result_append(result, "}");
}

void json_add_num(struct json_result *result, const char *fieldname, unsigned int value)
{
	json_start_member(result, fieldname);
	result_append_fmt(result, "%u", value);
}

void json_add_double(struct json_result *result, const char *fieldname, double value)
{
	json_start_member(result, fieldname);
	result_append_fmt(result, "%f", value);
}

void json_add_u64(struct json_result *result, const char *fieldname,
		  uint64_t value)
{
	json_start_member(result, fieldname);
	result_append_fmt(result, "%"PRIu64, value);
}

void json_add_literal(struct json_result *result, const char *fieldname,
		      const char *literal, int len)
{
	json_start_member(result, fieldname);
	result_append_fmt(result, "%.*s", len, literal);
}

void json_add_string(struct json_result *result, const char *fieldname, const char *value)
{
	struct json_escaped *esc = json_partial_escape(NULL, value);

	json_start_member(result, fieldname);
	result_append_fmt(result, "\"%s\"", esc->s);
	tal_free(esc);
}

void json_add_bool(struct json_result *result, const char *fieldname, bool value)
{
	json_start_member(result, fieldname);
	result_append(result, value ? "true" : "false");
}

void json_add_hex(struct json_result *result, const char *fieldname,
		  const void *data, size_t len)
{
	char *hex = tal_arr(NULL, char, hex_str_size(len));

	hex_encode(data, len, hex, hex_str_size(len));
	json_add_string(result, fieldname, hex);
	tal_free(hex);
}

void json_add_hex_talarr(struct json_result *result,
			 const char *fieldname,
			 const tal_t *data)
{
	json_add_hex(result, fieldname, data, tal_bytelen(data));
}

void json_add_object(struct json_result *result, ...)
{
	va_list ap;
	const char *field;

	va_start(ap, result);
	json_object_start(result, NULL);
	while ((field = va_arg(ap, const char *)) != NULL) {
		jsmntype_t type = va_arg(ap, jsmntype_t);
		const char *value = va_arg(ap, const char *);
		if (type == JSMN_STRING)
			json_add_string(result, field, value);
		else
			json_add_literal(result, field, value, strlen(value));
	}
	json_object_end(result);
	va_end(ap);
}

void json_add_escaped_string(struct json_result *result, const char *fieldname,
			     const struct json_escaped *esc TAKES)
{
	json_start_member(result, fieldname);
	result_append_fmt(result, "\"%s\"", esc->s);
	if (taken(esc))
		tal_free(esc);
}

struct json_result *new_json_result(const tal_t *ctx)
{
	struct json_result *r = tal(ctx, struct json_result);

	/* Using tal_arr means that it has a valid count. */
	r->s = tal_arrz(r, char, 1);
	r->wrapping = tal_arr(r, jsmntype_t, 0);
	return r;
}

const char *json_result_string(const struct json_result *result)
{
	assert(tal_count(result->wrapping) == 0);
	assert(tal_count(result->s) == strlen(result->s) + 1);
	return result->s;
}
