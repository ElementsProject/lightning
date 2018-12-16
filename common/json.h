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
struct short_channel_id;

/* Include " if it's a string. */
const char *json_tok_full(const char *buffer, const jsmntok_t *t);

/* Include " if it's a string. */
int json_tok_full_len(const jsmntok_t *t);

/* Is this a string equal to str? */
bool json_tok_streq(const char *buffer, const jsmntok_t *tok, const char *str);

/* Allocate a tal string copy */
char *json_strdup(const tal_t *ctx, const char *buffer, const jsmntok_t *tok);

/* Extract number from this (may be a string, or a number literal) */
bool json_to_number(const char *buffer, const jsmntok_t *tok,
		    unsigned int *num);

/* Extract number from this (may be a string, or a number literal) */
bool json_to_u64(const char *buffer, const jsmntok_t *tok,
		 uint64_t *num);

/* Extract double from this (must be a number literal) */
bool json_to_double(const char *buffer, const jsmntok_t *tok, double *num);

/* Extract signed integer from this (may be a string, or a number literal) */
bool json_to_int(const char *buffer, const jsmntok_t *tok, int *num);

/* Extract boolean from this */
bool json_to_bool(const char *buffer, const jsmntok_t *tok, bool *b);

/* Extract satoshis from this (may be a string, or a decimal number literal) */
bool json_to_bitcoin_amount(const char *buffer, const jsmntok_t *tok,
			    uint64_t *satoshi);

/* Is this a number? [0..9]+ */
bool json_tok_is_num(const char *buffer, const jsmntok_t *tok);

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
jsmntok_t *json_parse_input(const tal_t *ctx,
			    const char *input, int len, bool *valid);

/* Convert a jsmntype_t enum to a human readable string. */
const char *jsmntype_to_string(jsmntype_t t);

/* Print a json value for debugging purposes. */
void json_tok_print(const char *buffer, const jsmntok_t *params);

/* Return a copy of a json value as an array. */
jsmntok_t *json_tok_copy(const tal_t *ctx, const jsmntok_t *tok);

/*
 * Remove @num json values from a json array or object. @tok points
 * to the first value to remove.  The array will be resized.
 */
void json_tok_remove(jsmntok_t **tokens, jsmntok_t *tok, size_t num);

/* Guide is a string with . for members, [] around indexes. */
const jsmntok_t *json_delve(const char *buffer,
			    const jsmntok_t *tok,
			    const char *guide);

#endif /* LIGHTNING_COMMON_JSON_H */
