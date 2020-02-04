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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define JSMN_STRICT 1
# include <external/jsmn/jsmn.h>

struct bitcoin_txid;
struct chainparams;
struct channel_id;
struct command;
struct json_escape;
struct pubkey;
struct node_id;
struct short_channel_id;

struct command_result *param_pubkey(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    struct pubkey **pubkey);

struct command_result *param_txid(struct command *cmd, const char *name,
				  const char *buffer, const jsmntok_t *tok,
				  struct bitcoin_txid **txid);

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

bool json_tok_channel_id(const char *buffer, const jsmntok_t *tok,
			 struct channel_id *cid);

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
enum address_parse_result json_to_address_scriptpubkey(const tal_t *ctx,
			     const struct chainparams *chainparams,
			     const char *buffer,
			     const jsmntok_t *tok, const u8 **scriptpubkey);

struct command_result *param_bitcoin_address(struct command *cmd,
					     const char *name,
					     const char *buffer,
					     const jsmntok_t *tok,
					     const u8 **scriptpubkey);

#endif /* LIGHTNING_LIGHTNINGD_JSON_H */
