#ifndef LIGHTNING_COMMON_JSON_ESCAPED_H
#define LIGHTNING_COMMON_JSON_ESCAPED_H
#include "config.h"
#include <common/json.h>

/* Type differentiation for a correctly-escaped JSON string */
struct json_escaped {
	/* NUL terminated string. */
	char s[1];
};

/* @str be a valid UTF-8 string */
struct json_escaped *json_escape(const tal_t *ctx, const char *str TAKES);

/* @str is a valid UTF-8 string which may already contain escapes. */
struct json_escaped *json_partial_escape(const tal_t *ctx,
					 const char *str TAKES);

/* Extract a JSON-escaped string. */
struct json_escaped *json_tok_escaped_string(const tal_t *ctx,
					     const char *buffer,
					     const jsmntok_t *tok);

/* Are two escaped json strings identical? */
bool json_escaped_eq(const struct json_escaped *a,
		     const struct json_escaped *b);

/* Internal routine for creating json_escaped from bytes. */
struct json_escaped *json_escaped_string_(const tal_t *ctx,
					  const void *bytes, size_t len);

/* Be very careful here!  Can fail!  Doesn't handle \u: use UTF-8 please. */
const char *json_escaped_unescape(const tal_t *ctx,
				  const struct json_escaped *esc);
#endif /* LIGHTNING_COMMON_JSON_ESCAPED_H */
