/* More specialized (bitcoin, lightning-specific) JSON helpers. */
#ifndef LIGHTNING_COMMON_JSON_HELPERS_H
#define LIGHTNING_COMMON_JSON_HELPERS_H
#include "config.h"
#include <common/json.h>

struct pubkey;
struct short_channel_id;

/* Extract a pubkey from this */
bool json_to_pubkey(const char *buffer, const jsmntok_t *tok,
		    struct pubkey *pubkey);

/* Extract satoshis from this (may be a string, or a decimal number literal) */
bool json_to_bitcoin_amount(const char *buffer, const jsmntok_t *tok,
			    uint64_t *satoshi);

/* Extract a short_channel_id from this */
bool json_to_short_channel_id(const char *buffer, const jsmntok_t *tok,
			      struct short_channel_id *scid);

#endif /* LIGHTNING_COMMON_JSON_HELPERS_H */
