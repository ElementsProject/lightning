/* More specialized (bitcoin, lightning-specific) JSON helpers. */
#ifndef LIGHTNING_COMMON_JSON_HELPERS_H
#define LIGHTNING_COMMON_JSON_HELPERS_H
#include "config.h"
#include <bitcoin/tx.h>
#include <common/json.h>
#include <wire/wire.h>

struct amount_msat;
struct amount_sat;
struct bip340sig;
struct channel_id;
struct lease_rates;
struct node_id;
struct preimage;
struct pubkey;
struct point32;
struct secret;
struct short_channel_id;
struct short_channel_id_dir;
struct wireaddr;
struct wireaddr_internal;
struct wally_psbt;

/* Decode a hex-encoded payment preimage */
bool json_to_preimage(const char *buffer, const jsmntok_t *tok, struct preimage *preimage);

/* Extract a secret from this. */
bool json_to_secret(const char *buffer, const jsmntok_t *tok, struct secret *dest);

/* Extract a psbt from this. */
struct wally_psbt *json_to_psbt(const tal_t *ctx, const char *buffer,
				const jsmntok_t *tok);

/* Extract a pubkey from this */
bool json_to_pubkey(const char *buffer, const jsmntok_t *tok,
		    struct pubkey *pubkey);

/* Extract node_id from this: makes sure *id is valid! */
bool json_to_node_id(const char *buffer, const jsmntok_t *tok,
			       struct node_id *id);

/* Extract satoshis from this (may be a string, or a decimal number literal) */
bool json_to_bitcoin_amount(const char *buffer, const jsmntok_t *tok,
			    uint64_t *satoshi);

/* Extract a short_channel_id from this */
bool json_to_short_channel_id(const char *buffer, const jsmntok_t *tok,
			      struct short_channel_id *scid);

/* Extract a satoshis amount from this */
bool json_to_sat(const char *buffer, const jsmntok_t *tok,
		 struct amount_sat *sat);

/* Extract a satoshis amount from this */
/* If the string is "all", set amonut as AMOUNT_SAT(-1ULL). */
bool json_to_sat_or_all(const char *buffer, const jsmntok_t *tok,
			struct amount_sat *sat);

/* Extract a millisatoshis amount from this */
bool json_to_msat(const char *buffer, const jsmntok_t *tok,
		  struct amount_msat *msat);

/* Extract a bitcoin txid from this */
bool json_to_txid(const char *buffer, const jsmntok_t *tok,
		  struct bitcoin_txid *txid);

/* Extract a bitcoin outpoint from this */
bool json_to_outpoint(const char *buffer, const jsmntok_t *tok,
		      struct bitcoin_outpoint *op);

/* Extract a channel id from this */
bool json_to_channel_id(const char *buffer, const jsmntok_t *tok,
			struct channel_id *cid);

/* Split a json token into 2 tokens given a splitting character */
bool split_tok(const char *buffer, const jsmntok_t *tok,
				char split,
				jsmntok_t *a,
				jsmntok_t *b);

/* Extract reply path from this JSON */
struct tlv_onionmsg_payload_reply_path *
json_to_reply_path(const tal_t *ctx, const char *buffer, const jsmntok_t *tok);

/* Obsolete version! */
struct tlv_obs2_onionmsg_payload_reply_path *
json_to_obs2_reply_path(const tal_t *ctx, const char *buffer, const jsmntok_t *tok);

/* Helpers for outputting JSON results */

/* '"fieldname" : "0289abcdef..."' or "0289abcdef..." if fieldname is NULL */
void json_add_pubkey(struct json_stream *response,
		     const char *fieldname,
		     const struct pubkey *key);

/* '"fieldname" : "89abcdef..."' or "89abcdef..." if fieldname is NULL */
void json_add_point32(struct json_stream *response,
		       const char *fieldname,
		       const struct point32 *key);

/* '"fieldname" : "89abcdef..."' or "89abcdef..." if fieldname is NULL */
void json_add_bip340sig(struct json_stream *response,
			const char *fieldname,
			const struct bip340sig *sig);

/* '"fieldname" : "89abcdef..."' or "89abcdef..." if fieldname is NULL */
void json_add_secret(struct json_stream *response,
		     const char *fieldname,
		     const struct secret *secret);

/* '"fieldname" : "0289abcdef..."' or "0289abcdef..." if fieldname is NULL */
void json_add_node_id(struct json_stream *response,
				const char *fieldname,
				const struct node_id *id);

/* '"fieldname" : "0289abcdef..."' or "0289abcdef..." if fieldname is NULL */
void json_add_channel_id(struct json_stream *response,
			 const char *fieldname,
			 const struct channel_id *cid);

/* '"fieldname" : <hexrev>' or "<hexrev>" if fieldname is NULL */
void json_add_txid(struct json_stream *result, const char *fieldname,
		   const struct bitcoin_txid *txid);

/* '"fieldname" : "txid:n" */
void json_add_outpoint(struct json_stream *result, const char *fieldname,
		       const struct bitcoin_outpoint *out);

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

void json_add_sha256(struct json_stream *result, const char *fieldname,
		     const struct sha256 *hash);

void json_add_preimage(struct json_stream *result, const char *fieldname,
		     const struct preimage *preimage);

/* '"fieldname" : "010000000001..."' or "010000000001..." if fieldname is NULL */
void json_add_tx(struct json_stream *result,
		 const char *fieldname,
		 const struct bitcoin_tx *tx);

/* '"fieldname" : "cHNidP8BAJoCAAAAAljo..." or "cHNidP8BAJoCAAAAAljo..." if fieldname is NULL */
void json_add_psbt(struct json_stream *stream,
		   const char *fieldname,
		   const struct wally_psbt *psbt);

/* Add fields from the lease_rates to a json stream.
 * Note that field names are set */
void json_add_lease_rates(struct json_stream *result,
			  const struct lease_rates *rates);
#endif /* LIGHTNING_COMMON_JSON_HELPERS_H */
