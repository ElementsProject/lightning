#include <common/json_escaped.h>
#include <stdio.h>

struct json_escaped *json_escaped_string_(const tal_t *ctx,
					  const void *bytes, size_t len)
{
	struct json_escaped *esc;

	esc = tal_alloc_arr_(ctx, 1, len + 1, false, true,
			     TAL_LABEL(struct json_escaped, ""));
	memcpy(esc->s, bytes, len);
	esc->s[len] = '\0';
	return esc;
}

struct json_escaped *json_tok_escaped_string(const tal_t *ctx,
					     const char *buffer,
					     const jsmntok_t *tok)
{
	if (tok->type != JSMN_STRING)
		return NULL;
	/* jsmn always gives us ~ well-formed strings. */
	return json_escaped_string_(ctx, buffer + tok->start,
				    tok->end - tok->start);
}

bool json_escaped_streq(const struct json_escaped *esc, const char *str)
{
	return streq(esc->s, str);
}

bool json_escaped_eq(const struct json_escaped *a,
		     const struct json_escaped *b)
{
	return streq(a->s, b->s);
}

struct json_escaped *json_escape(const tal_t *ctx, const char *str TAKES)
{
	struct json_escaped *esc;
	size_t i, n;

	/* Worst case: all \uXXXX */
	esc = (struct json_escaped *)tal_arr(ctx, char, strlen(str) * 6 + 1);

	for (i = n = 0; str[i]; i++, n++) {
		char escape = 0;
		switch (str[i]) {
		case '\n':
			escape = 'n';
			break;
		case '\b':
			escape = 'b';
			break;
		case '\f':
			escape = 'f';
			break;
		case '\t':
			escape = 't';
			break;
		case '\r':
			escape = 'r';
			break;
		case '\\':
		case '"':
			escape = str[i];
			break;
		default:
			if ((unsigned)str[i] < ' ' || str[i] == 127) {
				sprintf(esc->s + n, "\\u%04X", str[i]);
				n += 5;
				continue;
			}
		}
		if (escape) {
			esc->s[n++] = '\\';
			esc->s[n] = escape;
		} else
			esc->s[n] = str[i];
	}

	esc->s[n] = '\0';
	if (taken(str))
		tal_free(str);
	return esc;
}
