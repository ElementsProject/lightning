#ifndef LIGHTNING_COMMON_JSON_H
#define LIGHTNING_COMMON_JSON_H
#include "config.h"
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/tal/tal.h>
#include <common/errcode.h>

#define JSMN_STRICT 1
# include <external/jsmn/jsmn.h>

struct json_escape;
struct json_stream;
struct timeabs;
struct timespec;

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

/* Decode a hex-encoded binary */
u8 *json_tok_bin_from_hex(const tal_t *ctx, const char *buffer, const jsmntok_t *tok);

/* Extract number from this (may be a string, or a number literal) */
bool json_to_number(const char *buffer, const jsmntok_t *tok,
		    unsigned int *num);

/* Extract number from this (may be a string, or a number literal) */
bool json_to_u64(const char *buffer, const jsmntok_t *tok,
		 uint64_t *num);

/* Extract signed 64 bit integer from this (may be a string, or a number literal) */
bool json_to_s64(const char *buffer, const jsmntok_t *tok, s64 *num);

/* Extract number from this (may be a string, or a number literal) */
bool json_to_u32(const char *buffer, const jsmntok_t *tok,
		 uint32_t *num);

/* Extract number from this (may be a string, or a number literal) */
bool json_to_u16(const char *buffer, const jsmntok_t *tok,
                 uint16_t *num);

bool json_to_sha256(const char *buffer, const jsmntok_t *tok, struct sha256 *dest);
/*
 * Extract a non-negative (either 0 or positive) floating-point number from this
 * (must be a number literal), multiply it by 1 million and return it as an
 * integer. Any fraction smaller than 0.000001 is ignored.
 */
bool json_to_millionths(const char *buffer, const jsmntok_t *tok,
			u64 *millionths);

/* Extract signed integer from this (may be a string, or a number literal) */
bool json_to_int(const char *buffer, const jsmntok_t *tok, int *num);

/* Extract an error code from this (may be a string, or a number literal) */
bool json_to_errcode(const char *buffer, const jsmntok_t *tok, errcode_t *errcode);

/* Extract boolean from this */
bool json_to_bool(const char *buffer, const jsmntok_t *tok, bool *b);

/* Is this a number? [0..9]+ */
bool json_tok_is_num(const char *buffer, const jsmntok_t *tok);

/* Is this the null primitive? */
bool json_tok_is_null(const char *buffer, const jsmntok_t *tok);

/* Returns next token with same parent (WARNING: slow!). */
const jsmntok_t *json_next(const jsmntok_t *tok);

/* Get top-level member. */
const jsmntok_t *json_get_member(const char *buffer, const jsmntok_t tok[],
				 const char *label);

/* Get index'th array member. */
const jsmntok_t *json_get_arr(const jsmntok_t tok[], size_t index);

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

/* Guide is % for a token: each must be followed by JSON_SCAN().
 * Returns NULL on error (asserts() on bad guide). */
const char *json_scan(const tal_t *ctx,
		      const char *buffer,
		      const jsmntok_t *tok,
		      const char *guide,
		      ...);

/* eg. JSON_SCAN(json_to_bool, &boolvar) */
#define JSON_SCAN(fmt, var)						\
	json_scan,							\
	stringify(fmt),							\
	((var) + 0*sizeof(fmt((const char *)NULL,			\
			      (const jsmntok_t *)NULL, var) == true)),	\
	(fmt)

/* eg. JSON_SCAN_TAL(tmpctx, json_strdup, &charvar) */
#define JSON_SCAN_TAL(ctx, fmt, var)					\
	(ctx),								\
	stringify(fmt),							\
	((var) + 0*sizeof((*var) = fmt((ctx),				\
				       (const char *)NULL,		\
				       (const jsmntok_t *)NULL))),	\
	(fmt)

/* Already-have-varargs version */
const char *json_scanv(const tal_t *ctx,
		       const char *buffer,
		       const jsmntok_t *tok,
		       const char *guide,
		       va_list ap);

/* Iterator macro for array: i is counter, t is token ptr, arr is JSMN_ARRAY */
#define json_for_each_arr(i, t, arr) \
	for (i = 0, t = (arr) + 1; i < (arr)->size; t = json_next(t), i++)

/* Iterator macro for object: i is counter, t is token ptr (t+1 is
 * contents of obj member), obj is JSMN_OBJECT */
#define json_for_each_obj(i, t, obj) \
	for (i = 0, t = (obj) + 1; i < (obj)->size; t = json_next(t+1), i++)


/* '"fieldname" : "value"' or '"value"' if fieldname is NULL.  Turns
 * any non-printable chars into JSON escapes, but leaves existing escapes alone.
 */
void json_add_string(struct json_stream *result, const char *fieldname, const char *value);

/* '"fieldname" : "value[:value_len]"' or '"value[:value_len]"' if
 * fieldname is NULL.  Turns any non-printable chars into JSON
 * escapes, but leaves existing escapes alone.
 */
void json_add_stringn(struct json_stream *result, const char *fieldname,
		      const char *value TAKES, size_t value_len);

/* '"fieldname" : "value"' or '"value"' if fieldname is NULL.  String must
 * already be JSON escaped as necessary. */
void json_add_escaped_string(struct json_stream *result,
			     const char *fieldname,
			     const struct json_escape *esc TAKES);

/* '"fieldname" : literal' or 'literal' if fieldname is NULL*/
void json_add_literal(struct json_stream *result, const char *fieldname,
		      const char *literal, int len);
/* '"fieldname" : value' or 'value' if fieldname is NULL */
void json_add_num(struct json_stream *result, const char *fieldname,
		  unsigned int value);
/* '"fieldname" : value' or 'value' if fieldname is NULL */
void json_add_u64(struct json_stream *result, const char *fieldname,
		  uint64_t value);
/* '"fieldname" : value' or 'value' if fieldname is NULL */
void json_add_s64(struct json_stream *result, const char *fieldname,
		  int64_t value);
/* '"fieldname" : value' or 'value' if fieldname is NULL */
void json_add_u32(struct json_stream *result, const char *fieldname,
		  uint32_t value);
/* '"fieldname" : value' or 'value' if fieldname is NULL */
void json_add_s32(struct json_stream *result, const char *fieldname,
		  int32_t value);
/* '"fieldname" : true|false' or 'true|false' if fieldname is NULL */
void json_add_bool(struct json_stream *result, const char *fieldname,
		   bool value);

/* '"fieldname" : null' or 'null' if fieldname is NULL */
void json_add_null(struct json_stream *stream, const char *fieldname);

/* '"fieldname" : "0189abcdef..."' or "0189abcdef..." if fieldname is NULL */
void json_add_hex(struct json_stream *result, const char *fieldname,
		  const void *data, size_t len);
/* '"fieldname" : "0189abcdef..."' or "0189abcdef..." if fieldname is NULL */
void json_add_hex_talarr(struct json_stream *result,
			 const char *fieldname,
			 const tal_t *data);

void json_add_timeabs(struct json_stream *result, const char *fieldname,
		      struct timeabs t);

/* used in log.c and notification.c*/
void json_add_time(struct json_stream *result, const char *fieldname,
			  struct timespec ts);

/* Add ISO_8601 timestamp string, i.e. "2019-09-07T15:50+01:00" */
void json_add_timeiso(struct json_stream *result,
		      const char *fieldname,
		      struct timeabs *time);

/* Add any json token */
void json_add_tok(struct json_stream *result, const char *fieldname,
                  const jsmntok_t *tok, const char *buffer);

/* Add an error code */
void json_add_errcode(struct json_stream *result, const char *fieldname,
		      errcode_t code);

/* Add "bolt11" or "bolt12" field, depending on invstring. */
void json_add_invstring(struct json_stream *result, const char *invstring);

#endif /* LIGHTNING_COMMON_JSON_H */
