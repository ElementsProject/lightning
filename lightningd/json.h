/* lightningd/json.h
 * Helpers for outputting JSON results that are specific only for
 * lightningd.
 */
#ifndef LIGHTNING_LIGHTNINGD_JSON_H
#define LIGHTNING_LIGHTNINGD_JSON_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define JSMN_STRICT 1
# include <external/jsmn/jsmn.h>

struct bitcoin_txid;
struct channel_id;
struct command;
struct json_escaped;
struct json_result;
struct pubkey;
struct route_hop;
struct sha256;
struct short_channel_id;
struct wallet_payment;
struct wireaddr;
struct wireaddr_internal;

/* Output a route array. */
void json_add_route(struct json_result *r, char const *n,
		    const struct route_hop *hops, size_t hops_len);

/* Output the fields of a wallet payment.
 * Should be used within an object context. */
void json_add_payment_fields(struct json_result *response,
			     const struct wallet_payment *t);

/* '"fieldname" : "0289abcdef..."' or "0289abcdef..." if fieldname is NULL */
void json_add_pubkey(struct json_result *response,
		     const char *fieldname,
		     const struct pubkey *key);

/* '"fieldname" : <hexrev>' or "<hexrev>" if fieldname is NULL */
void json_add_txid(struct json_result *result, const char *fieldname,
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
void json_add_short_channel_id(struct json_result *response,
			       const char *fieldname,
			       const struct short_channel_id *id);

bool json_tok_channel_id(const char *buffer, const jsmntok_t *tok,
			 struct channel_id *cid);

/* JSON serialize a network address for a node */
void json_add_address(struct json_result *response, const char *fieldname,
		      const struct wireaddr *addr);

/* JSON serialize a network address for a node. */
void json_add_address_internal(struct json_result *response,
			       const char *fieldname,
			       const struct wireaddr_internal *addr);

/*
 * Set the address of @out to @tok.  Used as a callback by handlers that
 * want to unmarshal @tok themselves.
 */
bool json_tok_tok(struct command *cmd, const char *name,
		  const char *buffer, const jsmntok_t * tok,
		  const jsmntok_t **out);

#endif /* LIGHTNING_LIGHTNINGD_JSON_H */
