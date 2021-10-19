/* MIT (BSD) license - see LICENSE file for details */
#include <ccan/json_escape/json_escape.h>
#include <stdio.h>

struct json_escape *json_escape_string_(const tal_t *ctx,
					const void *bytes, size_t len)
{
	struct json_escape *esc;

	esc = (void *)tal_arr_label(ctx, char, len + 1,
				    TAL_LABEL(struct json_escape, ""));
	memcpy(esc->s, bytes, len);
	esc->s[len] = '\0';
	return esc;
}

bool json_escape_eq(const struct json_escape *a, const struct json_escape *b)
{
	return streq(a->s, b->s);
}

bool json_escape_needed(const char *str, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		if ((unsigned)str[i] < ' '
		    || str[i] == 127
		    || str[i] == '"'
		    || str[i] == '\\')
			return true;
	}
	return false;
}

static struct json_escape *escape(const tal_t *ctx,
				  const char *str TAKES,
				  size_t len,
				  bool partial)
{
	struct json_escape *esc;
	size_t i, n;

	/* Fast path: can steal, and nothing to escape. */
	if (is_taken(str)
	    && tal_count(str) > len
	    && !json_escape_needed(str, len)) {
		taken(str);
		esc = (struct json_escape *)tal_steal(ctx, str);
		esc->s[len] = '\0';
		return esc;
	}

	/* Worst case: all \uXXXX */
	esc = (struct json_escape *)tal_arr(ctx, char, len * 6 + 1);

	for (i = n = 0; i < len; i++, n++) {
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

struct json_escape *json_partial_escape(const tal_t *ctx, const char *str TAKES)
{
	return escape(ctx, str, strlen(str), true);
}

struct json_escape *json_escape(const tal_t *ctx, const char *str TAKES)
{
	return escape(ctx, str, strlen(str), false);
}

struct json_escape *json_escape_len(const tal_t *ctx, const char *str TAKES,
				    size_t len)
{
	return escape(ctx, str, len, false);
}

/* By policy, we don't handle \u.  Use UTF-8. */
const char *json_escape_unescape(const tal_t *ctx, const struct json_escape *esc)
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
