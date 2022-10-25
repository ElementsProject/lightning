/* Very simple core JSON parse helpers: used by lightning-cli too */
#ifndef LIGHTNING_COMMON_JSON_PARSE_SIMPLE_H
#define LIGHTNING_COMMON_JSON_PARSE_SIMPLE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

#define JSMN_STRICT 1
# include <external/jsmn/jsmn.h>

/* Include " if it's a string. */
const char *json_tok_full(const char *buffer, const jsmntok_t *t);

/* Include " if it's a string. */
int json_tok_full_len(const jsmntok_t *t);

/* Is this a string equal to str? */
bool json_tok_streq(const char *buffer, const jsmntok_t *tok, const char *str);

/* Is this a string equal to str of length len? */
bool json_tok_strneq(const char *buffer, const jsmntok_t *tok,
		     const char *str, size_t len);

/* Does this string token start with prefix? */
bool json_tok_startswith(const char *buffer, const jsmntok_t *tok,
			 const char *prefix);

/* Does this string token end with suffix? */
bool json_tok_endswith(const char *buffer, const jsmntok_t *tok,
		       const char *suffix);

/* Allocate a tal string copy */
char *json_strdup(const tal_t *ctx, const char *buffer, const jsmntok_t *tok);

/* Extract number from this (may be a string, or a number literal) */
bool json_to_u64(const char *buffer, const jsmntok_t *tok, u64 *num);

/* Extract number from string. The number must be the entirety of the
 * string between the '"' */
bool json_str_to_u64(const char *buffer, const jsmntok_t *tok, u64 *num);

/* Extract number from this (may be a string, or a number literal) */
bool json_to_u32(const char *buffer, const jsmntok_t *tok, u32 *num);

/* Extract boolean from this */
bool json_to_bool(const char *buffer, const jsmntok_t *tok, bool *b);

/* Is this a number? [0..9]+ */
bool json_tok_is_num(const char *buffer, const jsmntok_t *tok);

/* Is this the null primitive? */
bool json_tok_is_null(const char *buffer, const jsmntok_t *tok);

/* Returns next token with same parent (WARNING: slow!). */
const jsmntok_t *json_next(const jsmntok_t *tok);

/* Get top-level member with explicit label len */
const jsmntok_t *json_get_membern(const char *buffer,
				  const jsmntok_t tok[],
				  const char *label, size_t len);

/* Get top-level member. */
const jsmntok_t *json_get_member(const char *buffer, const jsmntok_t tok[],
				 const char *label);

/* Get index'th array member. */
const jsmntok_t *json_get_arr(const jsmntok_t tok[], size_t index);

/* Helper to get "id" field from object. */
const char *json_get_id(const tal_t *ctx,
			const char *buffer, const jsmntok_t *obj);

/* Allocate a starter array of tokens for json_parse_input */
jsmntok_t *toks_alloc(const tal_t *ctx);

/* Reset a token array to reuse it. */
void toks_reset(jsmntok_t *toks);

/**
 * json_parse_input: parse and validate JSON.
 * @parser: parser initialized with jsmn_init.
 * @toks: tallocated array from toks_alloc()
 * @input, @len: input string.
 * @complete: set to true if the valid JSON is complete, or NULL if must be.
 *
 * This returns false if the JSON is invalid, true otherwise.
 * If it returns true, *@complete indicates that (*@toks)[0] points to a
 * valid, complete JSON element.  If @complete is NULL, then incomplete
 * JSON returns false (i.e. is considered invalid).
 *
 * *@toks is resized to the complete set of tokens, with a dummy
 * terminator (type == -1) at the end.
 *
 * If it returns true, and *@complete is false, you can append more
 * data to @input and call it again (with the same perser) and the parser
 * will continue where it left off.
*/
bool json_parse_input(jsmn_parser *parser,
		      jsmntok_t **toks,
		      const char *input, int len,
		      bool *complete);

/* Simplified version of above which parses only a complete, valid
 * JSON string */
jsmntok_t *json_parse_simple(const tal_t *ctx, const char *input, int len);

/* Convert a jsmntype_t enum to a human readable string. */
const char *jsmntype_to_string(jsmntype_t t);

/* Return a copy of a json value as an array. */
jsmntok_t *json_tok_copy(const tal_t *ctx, const jsmntok_t *tok);

/*
 * Remove @num json values from a json array or object @obj. @tok points
 * to the first value to remove.  The array @tokens will be resized.
 */
void json_tok_remove(jsmntok_t **tokens,
		     jsmntok_t *obj_or_array, const jsmntok_t *tok, size_t num);


/* Iterator macro for array: i is counter, t is token ptr, arr is JSMN_ARRAY */
#define json_for_each_arr(i, t, arr) \
	for (i = 0, t = (arr) + 1; i < (arr)->size; t = json_next(t), i++)

/* Iterator macro for object: i is counter, t is token ptr (t+1 is
 * contents of obj member), obj is JSMN_OBJECT */
#define json_for_each_obj(i, t, obj) \
	for (i = 0, t = (obj) + 1; i < (obj)->size; t = json_next(t+1), i++)

#endif /* LIGHTNING_COMMON_JSON_PARSE_SIMPLE_H */
