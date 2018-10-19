/* lightningd/json.h
 * Helpers for outputting JSON results that are specific only for
 * lightningd.
 */
#ifndef LIGHTNING_LIGHTNINGD_JSON_H
#define LIGHTNING_LIGHTNINGD_JSON_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define JSMN_STRICT 1
# include <external/jsmn/jsmn.h>

struct bitcoin_txid;
struct channel_id;
struct command;
struct json_escaped;
struct json_stream;
struct pubkey;
struct route_hop;
struct sha256;
struct short_channel_id;
struct wallet_payment;
struct wireaddr;
struct wireaddr_internal;

/* Output a route array. */
void json_add_route(struct json_stream *r, char const *n,
		    const struct route_hop *hops, size_t hops_len);

/* Output the fields of a wallet payment.
 * Should be used within an object context. */
void json_add_payment_fields(struct json_stream *response,
			     const struct wallet_payment *t);

/* '"fieldname" : "0289abcdef..."' or "0289abcdef..." if fieldname is NULL */
void json_add_pubkey(struct json_stream *response,
		     const char *fieldname,
		     const struct pubkey *key);

/* '"fieldname" : <hexrev>' or "<hexrev>" if fieldname is NULL */
void json_add_txid(struct json_stream *result, const char *fieldname,
		   const struct bitcoin_txid *txid);

/* Extract json array token */
bool json_tok_array(struct command *cmd, const char *name,
		    const char *buffer, const jsmntok_t *tok,
		    const jsmntok_t **arr);

/* Extract boolean this (must be a true or false) */
bool json_tok_bool(struct command *cmd, const char *name,
		   const char *buffer, const jsmntok_t *tok,
		   bool **b);

/* Extract double from this (must be a number literal) */
bool json_tok_double(struct command *cmd, const char *name,
		     const char *buffer, const jsmntok_t *tok,
		     double **num);

/* Extract an escaped string (and unescape it) */
bool json_tok_escaped_string(struct command *cmd, const char *name,
			     const char * buffer, const jsmntok_t *tok,
			     const char **str);

/* Extract a string */
bool json_tok_string(struct command *cmd, const char *name,
		     const char * buffer, const jsmntok_t *tok,
		     const char **str);

/* Extract a label. It is either an escaped string or a number. */
bool json_tok_label(struct command *cmd, const char *name,
		    const char * buffer, const jsmntok_t *tok,
		    struct json_escaped **label);

/* Extract number from this (may be a string, or a number literal) */
bool json_tok_number(struct command *cmd, const char *name,
		     const char *buffer, const jsmntok_t *tok,
		     unsigned int **num);

/* Extract sha256 hash */
bool json_tok_sha256(struct command *cmd, const char *name,
		     const char *buffer, const jsmntok_t *tok,
		     struct sha256 **hash);

/* Extract positive integer, or NULL if tok is 'any'. */
bool json_tok_msat(struct command *cmd, const char *name,
		   const char *buffer, const jsmntok_t * tok,
		   u64 **msatoshi_val);

/* Extract double in range [0.0, 100.0] */
bool json_tok_percent(struct command *cmd, const char *name,
		      const char *buffer, const jsmntok_t *tok,
		      double **num);

/* Extract a pubkey from this */
bool json_to_pubkey(const char *buffer, const jsmntok_t *tok,
		    struct pubkey *pubkey);

bool json_tok_pubkey(struct command *cmd, const char *name,
		     const char *buffer, const jsmntok_t *tok,
		     struct pubkey **pubkey);

/* Extract a short_channel_id from this */
bool json_to_short_channel_id(const char *buffer, const jsmntok_t *tok,
			      struct short_channel_id *scid);

bool json_tok_short_channel_id(struct command *cmd, const char *name,
			       const char *buffer, const jsmntok_t *tok,
			       struct short_channel_id **scid);

/* Extract number from this (may be a string, or a number literal) */
bool json_tok_u64(struct command *cmd, const char *name,
		  const char *buffer, const jsmntok_t *tok,
		  uint64_t **num);

enum feerate_style {
	FEERATE_PER_KSIPA,
	FEERATE_PER_KBYTE
};

/* Extract a feerate style. */
bool json_tok_feerate_style(struct command *cmd, const char *name,
			    const char *buffer, const jsmntok_t *tok,
			    enum feerate_style **style);

const char *json_feerate_style_name(enum feerate_style style);

/* Extract a feerate with optional style suffix. */
bool json_tok_feerate(struct command *cmd, const char *name,
		      const char *buffer, const jsmntok_t *tok,
		      u32 **feerate);

/* '"fieldname" : "1234:5:6"' */
void json_add_short_channel_id(struct json_stream *response,
			       const char *fieldname,
			       const struct short_channel_id *id);

bool json_tok_channel_id(const char *buffer, const jsmntok_t *tok,
			 struct channel_id *cid);

/* JSON serialize a network address for a node */
void json_add_address(struct json_stream *response, const char *fieldname,
		      const struct wireaddr *addr);

/* JSON serialize a network address for a node. */
void json_add_address_internal(struct json_stream *response,
			       const char *fieldname,
			       const struct wireaddr_internal *addr);

/*
 * Set the address of @out to @tok.  Used as a callback by handlers that
 * want to unmarshal @tok themselves.
 */
bool json_tok_tok(struct command *cmd, const char *name,
		  const char *buffer, const jsmntok_t * tok,
		  const jsmntok_t **out);


/* Creating JSON output */

/* '"fieldname" : [ ' or '[ ' if fieldname is NULL */
void json_array_start(struct json_stream *ptr, const char *fieldname);
/* '"fieldname" : { ' or '{ ' if fieldname is NULL */
void json_object_start(struct json_stream *ptr, const char *fieldname);
/* ' ], ' */
void json_array_end(struct json_stream *ptr);
/* ' }, ' */
void json_object_end(struct json_stream *ptr);

/**
 * json_stream_success - start streaming a successful json result.
 * @cmd: the command we're running.
 *
 * The returned value should go to command_success() when done.
 * json_add_* will be placed into the 'result' field of the JSON reply.
 */
struct json_stream *json_stream_success(struct command *cmd);

/**
 * json_stream_fail - start streaming a failed json result.
 * @cmd: the command we're running.
 * @code: the error code from lightningd/jsonrpc_errors.h
 * @errmsg: the error string.
 *
 * The returned value should go to command_failed() when done;
 * json_add_* will be placed into the 'data' field of the 'error' JSON reply.
 */
struct json_stream *json_stream_fail(struct command *cmd,
				     int code,
				     const char *errmsg);

/**
 * json_stream_fail_nodata - start streaming a failed json result.
 * @cmd: the command we're running.
 * @code: the error code from lightningd/jsonrpc_errors.h
 * @errmsg: the error string.
 *
 * This is used by command_fail(), which doesn't add any JSON data.
 */
struct json_stream *json_stream_fail_nodata(struct command *cmd,
					    int code,
					    const char *errmsg);

/* '"fieldname" : "value"' or '"value"' if fieldname is NULL.  Turns
 * any non-printable chars into JSON escapes, but leaves existing escapes alone.
 */
void json_add_string(struct json_stream *result, const char *fieldname, const char *value);

/* '"fieldname" : "value"' or '"value"' if fieldname is NULL.  String must
 * already be JSON escaped as necessary. */
void json_add_escaped_string(struct json_stream *result,
			     const char *fieldname,
			     const struct json_escaped *esc TAKES);

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
/* '"fieldname" : true|false' or 'true|false' if fieldname is NULL */
void json_add_bool(struct json_stream *result, const char *fieldname,
		   bool value);
/* '"fieldname" : "0189abcdef..."' or "0189abcdef..." if fieldname is NULL */
void json_add_hex(struct json_stream *result, const char *fieldname,
		  const void *data, size_t len);
/* '"fieldname" : "0189abcdef..."' or "0189abcdef..." if fieldname is NULL */
void json_add_hex_talarr(struct json_stream *result,
			 const char *fieldname,
			 const tal_t *data);
void json_add_object(struct json_stream *result, ...);

#endif /* LIGHTNING_LIGHTNINGD_JSON_H */
