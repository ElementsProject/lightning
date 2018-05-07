/* lightningd/json.h
 * Helpers for outputting JSON results that are specific only for
 * lightningd.
 */
#ifndef LIGHTNING_LIGHTNINGD_JSON_H
#define LIGHTNING_LIGHTNINGD_JSON_H
#include "config.h"
#include <stdbool.h>
#include <stddef.h>

#define JSMN_STRICT 1
# include <external/jsmn/jsmn.h>

struct bitcoin_txid;
struct channel_id;
struct json_result;
struct pubkey;
struct route_hop;
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

/* Extract a pubkey from this */
bool json_tok_pubkey(const char *buffer, const jsmntok_t *tok,
		     struct pubkey *pubkey);

/* Extract a short_channel_id from this */
bool json_tok_short_channel_id(const char *buffer, const jsmntok_t *tok,
			       struct short_channel_id *scid);

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
#endif /* LIGHTNING_LIGHTNINGD_JSON_H */
