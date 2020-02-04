#ifndef LIGHTNING_COMMON_JSON_H
#define LIGHTNING_COMMON_JSON_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/errcode.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define JSMN_STRICT 1
# include <external/jsmn/jsmn.h>

struct amount_sat;
struct amount_msat;
struct bitcoin_tx;
struct bitcoin_txid;
struct channel_id;
struct json_escape;
struct json_stream;
struct pubkey;
struct node_id;
struct sha256;
struct preimage;
struct secret;
struct short_channel_id;
struct timeabs;
struct timespec;
struct wallet_payment;
struct wallet_tx;
struct wireaddr;
struct wireaddr_internal;


/* Include " if it's a string. */
const char *json_tok_full(const char *buffer, const jsmntok_t *t);

/* Include " if it's a string. */
int json_tok_full_len(const jsmntok_t *t);

/* Is this a string equal to str? */
bool json_tok_streq(const char *buffer, const jsmntok_t *tok, const char *str);

/* Allocate a tal string copy */
char *json_strdup(const tal_t *ctx, const char *buffer, const jsmntok_t *tok);

/* Decode a hex-encoded binary */
u8 *json_tok_bin_from_hex(const tal_t *ctx, const char *buffer, const jsmntok_t *tok);

/* Decode a hex-encoded payment preimage */
bool json_to_preimage(const char *buffer, const jsmntok_t *tok, struct preimage *preimage);

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

/* Extract double from this (must be a number literal) */
bool json_to_double(const char *buffer, const jsmntok_t *tok, double *num);

/* Extract signed integer from this (may be a string, or a number literal) */
bool json_to_int(const char *buffer, const jsmntok_t *tok, int *num);

/* Extract an error code from this (may be a string, or a number literal) */
bool json_to_errcode(const char *buffer, const jsmntok_t *tok, errcode_t *errcode);

/* Extract boolean from this */
bool json_to_bool(const char *buffer, const jsmntok_t *tok, bool *b);

/* Extract a secret from this. */
bool json_to_secret(const char *buffer, const jsmntok_t *tok, struct secret *dest);

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
 * Remove @num json values from a json array or object @obj. @tok points
 * to the first value to remove.  The array @tokens will be resized.
 */
void json_tok_remove(jsmntok_t **tokens,
		     jsmntok_t *obj_or_array, const jsmntok_t *tok, size_t num);

/* Guide is a string with . for members, [] around indexes. */
const jsmntok_t *json_delve(const char *buffer,
			    const jsmntok_t *tok,
			    const char *guide);

/* Iterator macro for array: i is counter, t is token ptr, arr is JSMN_ARRAY */
#define json_for_each_arr(i, t, arr) \
	for (i = 0, t = (arr) + 1; i < (arr)->size; t = json_next(t), i++)

/* Iterator macro for object: i is counter, t is token ptr (t+1 is
 * contents of obj member), obj is JSMN_OBJECT */
#define json_for_each_obj(i, t, obj) \
	for (i = 0, t = (obj) + 1; i < (obj)->size; t = json_next(t+1), i++)


/* Helpers for outputting JSON results */

/* '"fieldname" : "0289abcdef..."' or "0289abcdef..." if fieldname is NULL */
void json_add_pubkey(struct json_stream *response,
		     const char *fieldname,
		     const struct pubkey *key);

/* '"fieldname" : "89abcdef..."' or "89abcdef..." if fieldname is NULL */
void json_add_secret(struct json_stream *response,
		     const char *fieldname,
		     const struct secret *secret);

/* '"fieldname" : "0289abcdef..."' or "0289abcdef..." if fieldname is NULL */
void json_add_node_id(struct json_stream *response,
				const char *fieldname,
				const struct node_id *id);

/* '"fieldname" : <hexrev>' or "<hexrev>" if fieldname is NULL */
void json_add_txid(struct json_stream *result, const char *fieldname,
		   const struct bitcoin_txid *txid);

/* '"fieldname" : "1234:5:6"' */
void json_add_short_channel_id(struct json_stream *response,
			       const char *fieldname,
			       const struct short_channel_id *id);

/* JSON serialize a network address for a node */
void json_add_address(struct json_stream *response, const char *fieldname,
		      const struct wireaddr *addr);

/* JSON serialize a network address for a node. */
void json_add_address_internal(struct json_stream *response,
			       const char *fieldname,
			       const struct wireaddr_internal *addr);

/* '"fieldname" : "value"' or '"value"' if fieldname is NULL.  Turns
 * any non-printable chars into JSON escapes, but leaves existing escapes alone.
 */
void json_add_string(struct json_stream *result, const char *fieldname, const char *value);

/* '"fieldname" : "value"' or '"value"' if fieldname is NULL.  String must
 * already be JSON escaped as necessary. */
void json_add_escaped_string(struct json_stream *result,
			     const char *fieldname,
			     const struct json_escape *esc TAKES);

/* '"fieldname" : literal' or 'literal' if fieldname is NULL*/
void json_add_literal(struct json_stream *result, const char *fieldname,
		      const char *literal, int len);
/* '"fieldname" : value' or 'value' if fieldname is NULL */
void json_add_double(struct json_stream *result, const char *fieldname,
		     double value);
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
/* '"fieldname" : "010000000001..."' or "010000000001..." if fieldname is NULL */
void json_add_tx(struct json_stream *result,
		 const char *fieldname,
		 const struct bitcoin_tx *tx);

/* Adds both a 'raw' number field and an 'amount_msat' field */
void json_add_amount_msat_compat(struct json_stream *result,
				 struct amount_msat msat,
				 const char *rawfieldname,
				 const char *msatfieldname)
	NO_NULL_ARGS;

/* Adds both a 'raw' number field and an 'amount_msat' field */
void json_add_amount_sat_compat(struct json_stream *result,
				struct amount_sat sat,
				const char *rawfieldname,
				const char *msatfieldname)
	NO_NULL_ARGS;

/* Adds an 'msat' field */
void json_add_amount_msat_only(struct json_stream *result,
			  const char *msatfieldname,
			  struct amount_msat msat)
	NO_NULL_ARGS;

/* Adds an 'msat' field */
void json_add_amount_sat_only(struct json_stream *result,
			 const char *msatfieldname,
			 struct amount_sat sat)
	NO_NULL_ARGS;

void json_add_timeabs(struct json_stream *result, const char *fieldname,
		      struct timeabs t);

/* used in log.c and notification.c*/
void json_add_time(struct json_stream *result, const char *fieldname,
			  struct timespec ts);

void json_add_sha256(struct json_stream *result, const char *fieldname,
		     const struct sha256 *hash);

void json_add_preimage(struct json_stream *result, const char *fieldname,
		     const struct preimage *preimage);

/* Add any json token */
void json_add_tok(struct json_stream *result, const char *fieldname,
                  const jsmntok_t *tok, const char *buffer);


#endif /* LIGHTNING_COMMON_JSON_H */
