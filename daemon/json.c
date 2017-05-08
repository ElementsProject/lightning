/* JSON core and helpers */
#include "json.h"
#include <arpa/inet.h>
#include <assert.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/tal.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

struct json_result {
	unsigned int indent;
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

	btc = strtoul(buffer + tok->start, &end, 0);
	if (btc == ULONG_MAX && errno == ERANGE)
		return false;
	if (end != buffer + tok->end) {
		/* Expect always 8 decimal places. */
		if (*end != '.' || buffer + tok->start - end != 9)
			return false;
		sat = strtoul(end+1, &end, 0);
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

	assert(tok->type == JSMN_OBJECT);

	end = json_next(tok);
	for (t = tok + 1; t < end; t = json_next(t+1))
		if (json_tok_streq(buffer, t, label))
			return t + 1;

	return NULL;
}

const jsmntok_t *json_get_arr(const jsmntok_t tok[], size_t index)
{
	const jsmntok_t *t, *end;

	assert(tok->type == JSMN_ARRAY);

	end = json_next(tok);
	for (t = tok + 1; t < end; t = json_next(t)) {
		if (index == 0)
			return t;
		index--;
	}

	return NULL;
}

/* Guide is a string with . for members, [] around indexes. */
const jsmntok_t *json_delve(const char *buffer,
			    const jsmntok_t *tok,
			    const char *guide)
{
	while (*guide) {
		const char *key;
		size_t len = strcspn(guide+1, ".[]");

		key = tal_strndup(NULL, guide+1, len);
		switch (guide[0]) {
		case '.':
			if (tok->type != JSMN_OBJECT)
				return tal_free(key);
			tok = json_get_member(buffer, tok, key);
			if (!tok)
				return tal_free(key);
			break;
		case '[':
			if (tok->type != JSMN_ARRAY)
				return tal_free(key);
			tok = json_get_arr(tok, atol(key));
			if (!tok)
				return tal_free(key);
			/* Must be terminated */
			assert(guide[1+strlen(key)] == ']');
			len++;
			break;
		default:
			abort();
		}
		tal_free(key);
		guide += len + 1;
	}

	return tok;
}

/* FIXME: Return false if unknown params specified, too! */
bool json_get_params(const char *buffer, const jsmntok_t param[], ...)
{
	va_list ap;
	const char *name;
	 /* Uninitialized warnings on p and end */
	const jsmntok_t **tokptr, *p = NULL, *end = NULL;

	if (param->type == JSMN_ARRAY) {
		if (param->size == 0)
			p = NULL;
		else
			p = param + 1;
		end = json_next(param);
	} else
		assert(param->type == JSMN_OBJECT);

	va_start(ap, param);
	while ((name = va_arg(ap, const char *)) != NULL) {
		tokptr = va_arg(ap, const jsmntok_t **);
		bool compulsory = true;
		if (name[0] == '?') {
			name++;
			compulsory = false;
		}
		if (param->type == JSMN_ARRAY) {
			*tokptr = p;
			if (p) {
				p = json_next(p);
				if (p == end)
					p = NULL;
			}
		} else {
			*tokptr = json_get_member(buffer, param, name);
		}
		/* Convert 'null' to NULL */
		if (*tokptr
		    && (*tokptr)->type == JSMN_PRIMITIVE
		    && buffer[(*tokptr)->start] == 'n') {
			*tokptr = NULL;
		}
		if (compulsory && !*tokptr)
			return false;
	}

	va_end(ap);
	return true;
}

jsmntok_t *json_parse_input(const char *input, int len, bool *valid)
{
	jsmn_parser parser;
	jsmntok_t *toks;
	jsmnerr_t ret;

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
	/* Make sure last one is always referencable. */
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

static void json_start_member(struct json_result *result, const char *fieldname)
{
	/* Prepend comma if required. */
	if (result->s[0]
	    && !result_ends_with(result, "{ ")
	    && !result_ends_with(result, "[ "))
		result_append(result, ", ");
	if (fieldname)
		result_append_fmt(result, "\"%s\" : ", fieldname);
}

void json_array_start(struct json_result *result, const char *fieldname)
{
	json_start_member(result, fieldname);
	if (result->indent) {
		unsigned int i;
		result_append(result, "\n");
		for (i = 0; i < result->indent; i++)
			result_append(result, "\t");
	}
	result_append(result, "[ ");
	result->indent++;
}

void json_array_end(struct json_result *result)
{
	assert(result->indent);
	result->indent--;
	result_append(result, " ]");
}

void json_object_start(struct json_result *result, const char *fieldname)
{
	json_start_member(result, fieldname);
	if (result->indent) {
		unsigned int i;
		result_append(result, "\n");
		for (i = 0; i < result->indent; i++)
			result_append(result, "\t");
	}
	result_append(result, "{ ");
	result->indent++;
}

void json_object_end(struct json_result *result)
{
	assert(result->indent);
	result->indent--;
	result_append(result, " }");
}

void json_add_num(struct json_result *result, const char *fieldname, unsigned int value)
{
	json_start_member(result, fieldname);
	result_append_fmt(result, "%u", value);
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
	json_start_member(result, fieldname);
	result_append_fmt(result, "\"%s\"", value);
}

void json_add_bool(struct json_result *result, const char *fieldname, bool value)
{
	json_start_member(result, fieldname);
	result_append(result, value ? "true" : "false");
}

void json_add_null(struct json_result *result, const char *fieldname)
{
	json_start_member(result, fieldname);
	result_append(result, "null");
}

void json_add_hex(struct json_result *result, const char *fieldname,
		  const void *data, size_t len)
{
	char hex[hex_str_size(len)];

	hex_encode(data, len, hex, sizeof(hex));
	json_add_string(result, fieldname, hex);
}

void json_add_pubkey(struct json_result *response,
		     const char *fieldname,
		     const struct pubkey *key)
{
	u8 der[PUBKEY_DER_LEN];

	pubkey_to_der(der, key);
	json_add_hex(response, fieldname, der, sizeof(der));
}

void json_add_short_channel_id(struct json_result *response,
			       const char *fieldname,
			       const struct short_channel_id *id)
{
	char *str = tal_fmt(response, "%d:%d:%d", id->blocknum, id->txnum, id->outnum);
	json_add_string(response, fieldname, str);
}

void json_add_address(struct json_result *response, const char *fieldname,
		      const struct ipaddr *addr)
{
	json_object_start(response, fieldname);
	char *addrstr = tal_arr(response, char, INET6_ADDRSTRLEN);
	if (addr->type == ADDR_TYPE_IPV4) {
		inet_ntop(AF_INET, addr->addr, addrstr, INET_ADDRSTRLEN);
		json_add_string(response, "type", "ipv4");
		json_add_string(response, "address", addrstr);
		json_add_num(response, "port", addr->port);
	} else if (addr->type == ADDR_TYPE_IPV6) {
		inet_ntop(AF_INET6, addr->addr, addrstr, INET6_ADDRSTRLEN);
		json_add_string(response, "type", "ipv6");
		json_add_string(response, "address", addrstr);
		json_add_num(response, "port", addr->port);
	}
	json_object_end(response);
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

struct json_result *new_json_result(const tal_t *ctx)
{
	struct json_result *r = tal(ctx, struct json_result);

	/* Using tal_arr means that it has a valid count. */
	r->s = tal_arrz(r, char, 1);
	r->indent = 0;
	return r;
}

const char *json_result_string(const struct json_result *result)
{
	assert(!result->indent);
	assert(tal_count(result->s) == strlen(result->s) + 1);
	return result->s;
}
