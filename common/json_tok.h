/* Helpers for use with param parsing. */
#ifndef LIGHTNING_COMMON_JSON_TOK_H
#define LIGHTNING_COMMON_JSON_TOK_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <common/bolt11.h>
#include <common/json.h>
#include <common/lease_rates.h>
#include <common/node_id.h>
#include <common/sphinx.h>
#include <wire/wire.h>

struct amount_msat;
struct amount_sat;
struct bitcoin_txid;
struct bitcoin_outpoint;
struct channel_id;
struct command;
struct command_result;
struct json_escape;
struct route_exclusion;
struct sha256;
struct wally_psbt;

/* Extract json array token */
struct command_result *param_array(struct command *cmd, const char *name,
				   const char *buffer, const jsmntok_t *tok,
				   const jsmntok_t **arr);

/* Extract boolean this (must be a true or false) */
struct command_result *param_bool(struct command *cmd, const char *name,
				  const char *buffer, const jsmntok_t *tok,
				  bool **b);

/*
 * Extract a non-negative (either 0 or positive) floating-point number from this
 * (must be a number literal), multiply it by 1 million and return it as an
 * integer.
 */
struct command_result *param_millionths(struct command *cmd, const char *name,
					const char *buffer,
					const jsmntok_t *tok, uint64_t **num);

/* Extract an escaped string (and unescape it) */
struct command_result *param_escaped_string(struct command *cmd,
					    const char *name,
					    const char *buffer,
					    const jsmntok_t *tok,
					    const char **str);

/* Extract a string */
struct command_result *param_string(struct command *cmd, const char *name,
				    const char * buffer, const jsmntok_t *tok,
				    const char **str);

/* Extract a label. It is either an escaped string or a number. */
struct command_result *param_label(struct command *cmd, const char *name,
				   const char * buffer, const jsmntok_t *tok,
				   struct json_escape **label);

/* Extract number from this (may be a string, or a number literal) */
struct command_result *param_number(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    unsigned int **num);

/* Extract sha256 hash */
struct command_result *param_sha256(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    struct sha256 **hash);

/* Extract number from this (may be a string, or a number literal) */
struct command_result *param_u64(struct command *cmd, const char *name,
				 const char *buffer, const jsmntok_t *tok,
				 uint64_t **num);

/* Extract msatoshi amount from this string */
struct command_result *param_msat(struct command *cmd, const char *name,
				  const char *buffer, const jsmntok_t *tok,
				  struct amount_msat **msat);

/* Extract satoshi amount from this string */
struct command_result *param_sat(struct command *cmd, const char *name,
				 const char *buffer, const jsmntok_t *tok,
				 struct amount_sat **sat);

/* Extract satoshi amount from this string. */
/* If the string is "all", set amonut as AMOUNT_SAT(-1ULL). */
struct command_result *param_sat_or_all(struct command *cmd, const char *name,
					const char *buffer, const jsmntok_t *tok,
					struct amount_sat **sat);


/* Extract node_id from this string. Makes sure *id is valid. */
struct command_result *param_node_id(struct command *cmd,
				     const char *name,
				     const char *buffer,
				     const jsmntok_t *tok,
				     struct node_id **id);

struct command_result *param_channel_id(struct command *cmd,
					const char *name,
					const char *buffer,
					const jsmntok_t *tok,
					struct channel_id **cid);

struct command_result *param_short_channel_id(struct command *cmd,
					      const char *name,
					      const char *buffer,
					      const jsmntok_t *tok,
					      struct short_channel_id **scid);

/*
 * Set the address of @out to @tok.  Used as a callback by handlers that
 * want to unmarshal @tok themselves.
 *
 * Usage of this is discouraged.  Writing a local static bespoke handler is
 * preferred.
 */
struct command_result *param_tok(struct command *cmd, const char *name,
				 const char *buffer, const jsmntok_t * tok,
				 const jsmntok_t **out);

/* Ignore the token.  Not usually used. */
struct command_result *param_ignore(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    const void *unused);

/* Extract a secret from this string */
struct command_result *param_secret(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    struct secret **secret);

/* Extract a binary value from the param and unhexlify it. */
struct command_result *param_bin_from_hex(struct command *cmd, const char *name,
					  const char *buffer, const jsmntok_t *tok,
					  u8 **bin);

struct command_result *param_hops_array(struct command *cmd, const char *name,
					const char *buffer, const jsmntok_t *tok,
					struct sphinx_hop **hops);

struct command_result *param_secrets_array(struct command *cmd,
					   const char *name, const char *buffer,
					   const jsmntok_t *tok,
					   struct secret **secrets);

struct command_result *param_feerate_val(struct command *cmd,
					 const char *name, const char *buffer,
					 const jsmntok_t *tok,
					 u32 **feerate_per_kw);

struct command_result *param_txid(struct command *cmd,
				  const char *name,
				  const char *buffer,
				  const jsmntok_t *tok,
				  struct bitcoin_txid **txid);

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

struct command_result *param_psbt(struct command *cmd,
				  const char *name,
				  const char *buffer,
				  const jsmntok_t *tok,
				  struct wally_psbt **psbt);

/**
 * Parse a list of `txid:output` outpoints.
 */
struct command_result *param_outpoint_arr(struct command *cmd,
					  const char *name,
					  const char *buffer,
					  const jsmntok_t *tok,
					  struct bitcoin_outpoint **outpoints);

struct command_result *param_extra_tlvs(struct command *cmd, const char *name,
					const char *buffer,
					const jsmntok_t *tok,
					struct tlv_field **fields);

struct command_result *
param_routehint_array(struct command *cmd, const char *name, const char *buffer,
		      const jsmntok_t *tok, struct route_info ***ris);

struct command_result *param_route_exclusion(struct command *cmd,
					const char *name, const char *buffer, const jsmntok_t *tok,
					struct route_exclusion **re);

struct command_result *
param_route_exclusion_array(struct command *cmd, const char *name,
					const char *buffer, const jsmntok_t *tok,
					struct route_exclusion ***res);

/**
 * Parse a 'compact-lease' (serialized lease_rates) back into lease_rates
 */
struct command_result *param_lease_hex(struct command *cmd,
				       const char *name,
				       const char *buffer,
				       const jsmntok_t *tok,
				       struct lease_rates **rates);
#endif /* LIGHTNING_COMMON_JSON_TOK_H */
