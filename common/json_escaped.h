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

/* Extract a JSON-escaped string. */
struct json_escaped *json_tok_escaped_string(const tal_t *ctx,
					     const char *buffer,
					     const jsmntok_t *tok);

/* Is @esc equal to @str */
bool json_escaped_streq(const struct json_escaped *esc, const char *str);


/* Are two escaped json strings identical? */
bool json_escaped_eq(const struct json_escaped *a,
		     const struct json_escaped *b);

void json_add_escaped_string(struct json_result *result,
			     const char *fieldname,
			     const struct json_escaped *esc TAKES);

/* Internal routine for creating json_escaped from bytes. */
struct json_escaped *json_escaped_string_(const tal_t *ctx,
					  const void *bytes, size_t len);

#endif /* LIGHTNING_COMMON_JSON_ESCAPED_H */
