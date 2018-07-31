#include <common/json_escaped.h>
#include <stdio.h>

struct json_escaped *json_escaped_string_(const tal_t *ctx,
					  const void *bytes, size_t len)
{
	struct json_escaped *esc;

	esc = (void *)tal_arr_label(ctx, char, len + 1,
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

bool json_escaped_eq(const struct json_escaped *a,
		     const struct json_escaped *b)
{
	return streq(a->s, b->s);
}

static struct json_escaped *escape(const tal_t *ctx,
				   const char *str TAKES,
				   bool partial)
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
			if (partial) {
				/* Don't double-escape standard escapes. */
				if (str[i+1] == 'n'
				    || str[i+1] == 'b'
				    || str[i+1] == 'f'
				    || str[i+1] == 't'
				    || str[i+1] == 'r'
				    || str[i+1] == '/'
				    || str[i+1] == '\\'
				    || str[i+1] == '"') {
					escape = str[i+1];
					i++;
					break;
				}
				if (str[i+1] == 'u'
				    && cisxdigit(str[i+2])
				    && cisxdigit(str[i+3])
				    && cisxdigit(str[i+4])
				    && cisxdigit(str[i+5])) {
					    memcpy(esc->s + n, str + i, 6);
					    n += 5;
					    i += 5;
					    continue;
				}
			} /* fall thru */
		case '"':
			escape = str[i];
			break;
		default:
			if ((unsigned)str[i] < ' ' || str[i] == 127) {
				snprintf(esc->s + n, 7, "\\u%04X", str[i]);
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

struct json_escaped *json_partial_escape(const tal_t *ctx, const char *str TAKES)
{
	return escape(ctx, str, true);
}

struct json_escaped *json_escape(const tal_t *ctx, const char *str TAKES)
{
	return escape(ctx, str, false);
}

/* By policy, we don't handle \u.  Use UTF-8. */
const char *json_escaped_unescape(const tal_t *ctx,
				  const struct json_escaped *esc)
{
	char *unesc = tal_arr(ctx, char, strlen(esc->s) + 1);
	size_t i, n;

	for (i = n = 0; esc->s[i]; i++, n++) {
		if (esc->s[i] != '\\') {
			unesc[n] = esc->s[i];
			continue;
		}

		i++;
		switch (esc->s[i]) {
		case 'n':
			unesc[n] = '\n';
			break;
		case 'b':
			unesc[n] = '\b';
			break;
		case 'f':
			unesc[n] = '\f';
			break;
		case 't':
			unesc[n] = '\t';
			break;
		case 'r':
			unesc[n] = '\r';
			break;
		case '/':
		case '\\':
		case '"':
			unesc[n] = esc->s[i];
			break;
		default:
			return tal_free(unesc);
		}
	}

	unesc[n] = '\0';
	return unesc;
}
