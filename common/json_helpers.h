/* More specialized (bitcoin, lightning-specific) JSON helpers. */
#ifndef LIGHTNING_COMMON_JSON_HELPERS_H
#define LIGHTNING_COMMON_JSON_HELPERS_H
#include "config.h"
#include <bitcoin/tx.h>
#include <common/json.h>
#include <wire/wire.h>

struct amount_msat;
struct amount_sat;
struct pubkey;
struct node_id;
struct short_channel_id;

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

/* Extract a channel id from this */
bool json_to_channel_id(const char *buffer, const jsmntok_t *tok,
			struct channel_id *cid);

/* Split a json token into 2 tokens given a splitting character */
bool split_tok(const char *buffer, const jsmntok_t *tok,
				char split,
				jsmntok_t *a,
				jsmntok_t *b);
#endif /* LIGHTNING_COMMON_JSON_HELPERS_H */
