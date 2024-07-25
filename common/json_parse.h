#ifndef LIGHTNING_COMMON_JSON_PARSE_H
#define LIGHTNING_COMMON_JSON_PARSE_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <ccan/crypto/sha256/sha256.h>
#include <common/coin_mvt.h>
#include <common/errcode.h>
/* Simple helpers are here: this file contains heavier ones */
#include <common/json_parse_simple.h>
#include <common/jsonrpc_errors.h>

struct json_escape;
struct json_stream;
struct timeabs;
struct timespec;
struct preimage;
struct secret;
struct pubkey;
struct node_id;
struct short_channel_id;
struct amount_sat;
struct amount_msat;
struct bitcoin_txid;
struct bitcoin_outpoint;
struct channel_id;

/* Decode a hex-encoded binary */
u8 *json_tok_bin_from_hex(const tal_t *ctx, const char *buffer, const jsmntok_t *tok);

/* Extract number from this (may be a string, or a number literal) */
bool json_to_number(const char *buffer, const jsmntok_t *tok,
		    unsigned int *num);

/* Extract signed 64 bit integer from this (may be a string, or a number literal) */
bool json_to_s64(const char *buffer, const jsmntok_t *tok, s64 *num);

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
bool json_to_jsonrpc_errcode(const char *buffer, const jsmntok_t *tok,
			     enum jsonrpc_errcode *errcode);

/* Split a json token into 2 tokens given a splitting character */
bool split_tok(const char *buffer, const jsmntok_t *tok,
				char split,
				jsmntok_t *a,
				jsmntok_t *b);

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

/* Extract a channel id + dir from this */
bool json_to_short_channel_id_dir(const char *buffer, const jsmntok_t *tok,
				  struct short_channel_id_dir *scidd);

/* Extract a coin movement 'tag' from this */
bool json_to_coin_mvt_tag(const char *buffer, const jsmntok_t *tok,
			  enum mvt_tag *tag);

bool json_tok_channel_id(const char *buffer, const jsmntok_t *tok,
			 struct channel_id *cid);

/* Guide is % for a token: each must be followed by JSON_SCAN().
 * Returns NULL on success, otherwise errmsg (asserts() on bad guide). */
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

#endif /* LIGHTNING_COMMON_JSON_PARSE_H */
