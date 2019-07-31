/* lightningd/json.h
 * Helpers for outputting JSON results that are specific only for
 * lightningd.
 */
#ifndef LIGHTNING_LIGHTNINGD_JSON_H
#define LIGHTNING_LIGHTNINGD_JSON_H
#include "config.h"
#include <bitcoin/privkey.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/time/time.h>
#include <common/amount.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define JSMN_STRICT 1
# include <external/jsmn/jsmn.h>

struct bitcoin_tx;
struct bitcoin_txid;
struct chainparams;
struct channel_id;
struct command;
struct json_escape;
struct json_stream;
struct pubkey;
struct node_id;
struct route_hop;
struct sha256;
struct short_channel_id;
struct wallet_payment;
struct wallet_tx;
struct wireaddr;
struct wireaddr_internal;

/* Output a route array. */
void json_add_route(struct json_stream *r, char const *n,
		    const struct route_hop *hops, size_t hops_len);

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

struct command_result *param_pubkey(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    struct pubkey **pubkey);

struct command_result *param_txid(struct command *cmd, const char *name,
				  const char *buffer, const jsmntok_t *tok,
				  struct bitcoin_txid **txid);
/* Makes sure *id is valid. */
struct command_result *param_node_id(struct command *cmd,
					       const char *name,
					       const char *buffer,
					       const jsmntok_t *tok,
					       struct node_id **id);

struct command_result *param_short_channel_id(struct command *cmd,
					      const char *name,
					      const char *buffer,
					      const jsmntok_t *tok,
					      struct short_channel_id **scid);

enum feerate_style {
	FEERATE_PER_KSIPA,
	FEERATE_PER_KBYTE
};

/* Extract a feerate style. */
struct command_result *param_feerate_style(struct command *cmd,
					   const char *name,
					   const char *buffer,
					   const jsmntok_t *tok,
					   enum feerate_style **style);

const char *json_feerate_style_name(enum feerate_style style);

/* Extract a feerate with optional style suffix. */
struct command_result *param_feerate(struct command *cmd, const char *name,
				     const char *buffer, const jsmntok_t *tok,
				     u32 **feerate);

/* Extract a route. */
struct command_result *param_route(struct command *cmd, const char *name,
				   const char *buffer, const jsmntok_t *tok,
				   struct route_hop **route);

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

enum address_parse_result {
	/* Not recognized as an onchain address */
	ADDRESS_PARSE_UNRECOGNIZED,
	/* Recognized as an onchain address, but targets wrong network */
	ADDRESS_PARSE_WRONG_NETWORK,
	/* Recognized and succeeds */
	ADDRESS_PARSE_SUCCESS,
};
/* Return result of address parsing and fills in *scriptpubkey
 * allocated off ctx if ADDRESS_PARSE_SUCCESS
 */
enum address_parse_result json_tok_address_scriptpubkey(const tal_t *ctx,
			     const struct chainparams *chainparams,
			     const char *buffer,
			     const jsmntok_t *tok, const u8 **scriptpubkey);

void json_add_timeabs(struct json_stream *result, const char *fieldname,
		      struct timeabs t);

/* used in log.c and notification.c*/
void json_add_time(struct json_stream *result, const char *fieldname,
			  struct timespec ts);

#endif /* LIGHTNING_LIGHTNINGD_JSON_H */
