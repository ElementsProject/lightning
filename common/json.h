#ifndef LIGHTNING_COMMON_JSON_H
#define LIGHTNING_COMMON_JSON_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <ccan/take/take.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define JSMN_STRICT 1
# include <external/jsmn/jsmn.h>

struct json_escaped;
struct json_result;
struct short_channel_id;

/* Include " if it's a string. */
const char *json_tok_contents(const char *buffer, const jsmntok_t *t);

/* Include " if it's a string. */
int json_tok_len(const jsmntok_t *t);

/* Is this a string equal to str? */
bool json_tok_streq(const char *buffer, const jsmntok_t *tok, const char *str);

/* Extract number from this (may be a string, or a number literal) */
bool json_tok_number(const char *buffer, const jsmntok_t *tok,
		     unsigned int *num);

/* Extract number from this (may be a string, or a number literal) */
bool json_tok_u64(const char *buffer, const jsmntok_t *tok,
		  uint64_t *num);

/* Extract double from this (must be a number literal) */
bool json_tok_double(const char *buffer, const jsmntok_t *tok, double *num);

/* Extract satoshis from this (may be a string, or a decimal number literal) */
bool json_tok_bitcoin_amount(const char *buffer, const jsmntok_t *tok,
			     uint64_t *satoshi);

/* Extract double in range [0.0, 100.0] */
bool json_tok_percent(const char *buffer, const jsmntok_t *tok, double *num);

/* Extract boolean this (must be a true or false) */
bool json_tok_bool(const char *buffer, const jsmntok_t *tok, bool *b);

/* Extract sha256 hash */
bool json_tok_sha256(const char *buffer, const jsmntok_t * tok,
		     struct sha256 *hash);

/*
 * Set the address of @out to @tok.  Used as a param_table callback by handlers that
 * want to unmarshal @tok themselves.
 */
bool json_tok_tok(const char *buffer, const jsmntok_t * tok,
		  const jsmntok_t **out);

/* Is this the null primitive? */
bool json_tok_is_null(const char *buffer, const jsmntok_t *tok);

/* Returns next token with same parent. */
const jsmntok_t *json_next(const jsmntok_t *tok);

/* Get top-level member. */
const jsmntok_t *json_get_member(const char *buffer, const jsmntok_t tok[],
				 const char *label);

/* Get index'th array member. */
const jsmntok_t *json_get_arr(const jsmntok_t tok[], size_t index);

/* If input is complete and valid, return tokens. */
jsmntok_t *json_parse_input(const char *input, int len, bool *valid);

/* Creating JSON strings */

/* '"fieldname" : [ ' or '[ ' if fieldname is NULL */
void json_array_start(struct json_result *ptr, const char *fieldname);
/* '"fieldname" : { ' or '{ ' if fieldname is NULL */
void json_object_start(struct json_result *ptr, const char *fieldname);
/* ' ], ' */
void json_array_end(struct json_result *ptr);
/* ' }, ' */
void json_object_end(struct json_result *ptr);

struct json_result *new_json_result(const tal_t *ctx);

/* '"fieldname" : "value"' or '"value"' if fieldname is NULL.  Turns
 * any non-printable chars into JSON escapes, but leaves existing escapes alone.
 */
void json_add_string(struct json_result *result, const char *fieldname, const char *value);

/* '"fieldname" : "value"' or '"value"' if fieldname is NULL.  String must
 * already be JSON escaped as necessary. */
void json_add_escaped_string(struct json_result *result,
			     const char *fieldname,
			     const struct json_escaped *esc TAKES);

/* '"fieldname" : literal' or 'literal' if fieldname is NULL*/
void json_add_literal(struct json_result *result, const char *fieldname,
		      const char *literal, int len);
/* '"fieldname" : value' or 'value' if fieldname is NULL */
void json_add_double(struct json_result *result, const char *fieldname,
		     double value);
/* '"fieldname" : value' or 'value' if fieldname is NULL */
void json_add_num(struct json_result *result, const char *fieldname,
		  unsigned int value);
/* '"fieldname" : value' or 'value' if fieldname is NULL */
void json_add_u64(struct json_result *result, const char *fieldname,
		  uint64_t value);
/* '"fieldname" : true|false' or 'true|false' if fieldname is NULL */
void json_add_bool(struct json_result *result, const char *fieldname,
		   bool value);
/* '"fieldname" : "0189abcdef..."' or "0189abcdef..." if fieldname is NULL */
void json_add_hex(struct json_result *result, const char *fieldname,
		  const void *data, size_t len);
/* '"fieldname" : "0189abcdef..."' or "0189abcdef..." if fieldname is NULL */
void json_add_hex_talarr(struct json_result *result,
			 const char *fieldname,
			 const tal_t *data);
void json_add_object(struct json_result *result, ...);

const char *json_result_string(const struct json_result *result);
#endif /* LIGHTNING_COMMON_JSON_H */
