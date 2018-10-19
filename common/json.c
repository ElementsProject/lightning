/* JSON core and helpers */
#include "json.h"
#include <assert.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

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

bool json_to_double(const char *buffer, const jsmntok_t *tok, double *num)
{
	char *end;

	*num = strtod(buffer + tok->start, &end);
	if (end != buffer + tok->end)
		return false;
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
	toks[0].type = JSMN_UNDEFINED;

	jsmn_init(&parser);
again:
	ret = jsmn_parse(&parser, input, len, toks, tal_count(toks) - 1);

	switch (ret) {
	case JSMN_ERROR_INVAL:
		*valid = false;
		return tal_free(toks);
	case JSMN_ERROR_NOMEM:
		tal_resize(&toks, tal_count(toks) * 2);
		goto again;
	}

	/* Check whether we read at least one full root element, i.e., root
	 * element has its end set. */
	if (toks[0].type == JSMN_UNDEFINED || toks[0].end == -1) {
		*valid = true;
		return tal_free(toks);
	}

	/* If we read a partial element at the end of the stream we'll get a
	 * ret=JSMN_ERROR_PART, but due to the previous check we know we read at
	 * least one full element, so count tokens that are part of this root
	 * element. */
	ret = json_next(toks) - toks;

	/* Cut to length and return. */
	*valid = true;
	tal_resize(&toks, ret + 1);
	/* Make sure last one is always referenceable. */
	toks[ret].type = -1;
	toks[ret].start = toks[ret].end = toks[ret].size = 0;

	return toks;
}
