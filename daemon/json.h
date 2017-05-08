#ifndef LIGHTNING_DAEMON_JSON_H
#define LIGHTNING_DAEMON_JSON_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <ccan/tal/tal.h>
#include <daemon/routing.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define JSMN_STRICT 1
# include "jsmn/jsmn.h"

struct json_result;

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

/* Extract boolean this (must be a true or false) */
bool json_tok_bool(const char *buffer, const jsmntok_t *tok, bool *b);

/* Is this the null primitive? */
bool json_tok_is_null(const char *buffer, const jsmntok_t *tok);

/* Returns next token with same parent. */
const jsmntok_t *json_next(const jsmntok_t *tok);

/* Get the parameters (by position or name).  Followed by triples of
 * of const char *name, const jsmntok_t **ret_ptr, then NULL.
 *
 * If name starts with '?' it is optional (and will be set to NULL
 * if it's a literal 'null' or not present).
 * Otherwise false is returned.
 */
bool json_get_params(const char *buffer, const jsmntok_t param[], ...);

/* Get top-level member. */
const jsmntok_t *json_get_member(const char *buffer, const jsmntok_t tok[],
				 const char *label);

/* Get index'th array member. */
const jsmntok_t *json_get_arr(const jsmntok_t tok[], size_t index);

/* Guide is a string with . for members, [] around indexes. */
const jsmntok_t *json_delve(const char *buffer,
			    const jsmntok_t *tok,
			    const char *guide);

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

/* '"fieldname" : "value"' or '"value"' if fieldname is NULL*/
void json_add_string(struct json_result *result, const char *fieldname, const char *value);
/* '"fieldname" : literal' or 'literal' if fieldname is NULL*/
void json_add_literal(struct json_result *result, const char *fieldname,
		      const char *literal, int len);
/* '"fieldname" : value' or 'value' if fieldname is NULL */
void json_add_num(struct json_result *result, const char *fieldname,
		  unsigned int value);
/* '"fieldname" : value' or 'value' if fieldname is NULL */
void json_add_u64(struct json_result *result, const char *fieldname,
		  uint64_t value);
/* '"fieldname" : true|false' or 'true|false' if fieldname is NULL */
void json_add_bool(struct json_result *result, const char *fieldname,
		   bool value);
/* '"fieldname" : null' or 'null' if fieldname is NULL */
void json_add_null(struct json_result *result, const char *fieldname);
/* '"fieldname" : "0189abcdef..."' or "0189abcdef..." if fieldname is NULL */
void json_add_hex(struct json_result *result, const char *fieldname,
		  const void *data, size_t len);
/* '"fieldname" : "0289abcdef..."' or "0289abcdef..." if fieldname is NULL */
void json_add_pubkey(struct json_result *response,
		     const char *fieldname,
		     const struct pubkey *key);

/* '"fieldname" : "1234/5/6"' */
void json_add_short_channel_id(struct json_result *response,
			       const char *fieldname,
			       const struct short_channel_id *id);

/* JSON serialize a network address for a node */
void json_add_address(struct json_result *response, const char *fieldname,
		      const struct ipaddr *addr);

void json_add_object(struct json_result *result, ...);

const char *json_result_string(const struct json_result *result);
#endif /* LIGHTNING_DAEMON_JSON_H */
