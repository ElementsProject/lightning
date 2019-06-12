/* MIT (BSD) license - see LICENSE file for details */
#ifndef CCAN_JSON_ESCAPE_H
#define CCAN_JSON_ESCAPE_H
#include "config.h"
#include <ccan/tal/tal.h>

/* Type differentiation for a correctly-escaped JSON string */
struct json_escape {
	/* NUL terminated string. */
	char s[1];
};

/**
 * json_escape - escape a valid UTF-8 string.
 * @ctx: tal context to allocate from.
 * @str: the string to escape.
 *
 * Allocates and returns a valid JSON string (without surrounding quotes).
 */
struct json_escape *json_escape(const tal_t *ctx, const char *str TAKES);

/* Version with @len */
struct json_escape *json_escape_len(const tal_t *ctx,
				    const char *str TAKES, size_t len);

/* @str is a valid UTF-8 string which may already contain escapes. */
struct json_escape *json_partial_escape(const tal_t *ctx,
					 const char *str TAKES);

/* Do we need to escape this str? */
bool json_escape_needed(const char *str, size_t len);

/* Are two escape json strings identical? */
bool json_escape_eq(const struct json_escape *a,
		     const struct json_escape *b);

/* Internal routine for creating json_escape from bytes. */
struct json_escape *json_escape_string_(const tal_t *ctx,
					const void *bytes, size_t len);

/* Be very careful here!  Can fail!  Doesn't handle \u: use UTF-8 please. */
const char *json_escape_unescape(const tal_t *ctx,
				 const struct json_escape *esc);
#endif /* CCAN_JSON_ESCAPE_H */
