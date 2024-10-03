/* Helpers for use with param parsing. */
#ifndef LIGHTNING_COMMON_JSON_PARAM_H
#define LIGHTNING_COMMON_JSON_PARAM_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <common/bolt11.h>
#include <common/json_parse.h>
#include <common/lease_rates.h>
#include <common/node_id.h>
#include <common/sphinx.h>
#include <wire/wire.h>

/*~ Greetings adventurer!
 *
 * Do you want to automatically validate json input and unmarshal it into
 * local variables, all using typesafe callbacks?  And on error,
 * call command_fail with a proper error message? Then you've come to the
 * right place!
 *
 * Here is a simple example of using the system:
 *
 * 	unsigned *cltv;
 * 	u64 *msatoshi;
 * 	u64 *expiry;
 *
 * 	if (!param(cmd, buffer, params,
 * 		   p_req("cltv", param_number, &cltv),
 * 		   p_opt("msatoshi", param_u64, &msatoshi),
 * 		   p_opt_def("expiry", param_u64, &expiry, 3600),
 * 		   NULL))
 * 		return;
 *
 * If param() returns true then you're good to go.
 *
 * All the command handlers throughout the code use this system.
 * json_invoice() is a great example.  The common callbacks can be found in
 * common/json_param.c.  Use them directly or feel free to write your own.
 */
struct command;

/* A dummy type returned by command_ functions, to ensure you return them
 * immediately */
struct command_result;

/*
 * All-in-one: parse the json tokens.  @params can be an array of
 * values or an object of named values.
 */
bool param(struct command *cmd, const char *buffer,
	   const jsmntok_t params[], ...) LAST_ARG_NULL;

/*
 * Version which *doesn't* fail if command_check_only(cmd) is true:
 * allows you can do extra checks after, but MUST still fail with
 * command_param_failed(); if command_check_only(cmd) is true! */
bool param_check(struct command *cmd,
		 const char *buffer,
		 const jsmntok_t tokens[], ...) LAST_ARG_NULL;

/*
 * The callback signature.
 *
 * Callbacks must return NULL on success.  On failure they
 * must return command_fail(...).
 */
typedef struct command_result *(*param_cbx)(struct command *cmd,
					    const char *name,
					    const char *buffer,
					    const jsmntok_t *tok,
					    void **arg);

/**
 * Parse the first json value.
 *
 * name...: NULL-terminated array of valid values.
 *
 * Returns subcommand: if it returns NULL if you should return
 * command_param_failed() immediately.
 */
const char *param_subcommand(struct command *cmd, const char *buffer,
			     const jsmntok_t tokens[],
			     const char *name, ...) LAST_ARG_NULL;

enum param_style {
	PARAM_REQUIRED,
	PARAM_OPTIONAL,
	PARAM_OPTIONAL_WITH_DEFAULT,
	PARAM_OPTIONAL_DEV_WITH_DEFAULT,
};

/*
 * Add a required parameter.
 */
#define p_req_depr(name, depr_start, depr_end, cbx, arg)     \
	      name"",                                        \
	      PARAM_REQUIRED,                                \
	      (depr_start), (depr_end),			     \
	      (param_cbx)(cbx),				     \
	      (arg) + 0*sizeof((cbx)((struct command *)NULL, \
			       (const char *)NULL,           \
			       (const char *)NULL,           \
			       (const jsmntok_t *)NULL,      \
			       (arg)) == (struct command_result *)NULL)

#define p_req(name, cbx, arg) p_req_depr(name, NULL, NULL, (cbx), (arg))

/*
 * Add an optional parameter.  *arg is set to NULL if it isn't found.
 */
#define p_opt_depr(name, depr_start, depr_end, cbx, arg)	\
	      name"",                                           \
	      PARAM_OPTIONAL,                                   \
	      (depr_start), (depr_end),				\
	      (param_cbx)(cbx),                                 \
	      ({ *arg = NULL;                                   \
		 (arg) + 0*sizeof((cbx)((struct command *)NULL, \
		                  (const char *)NULL,           \
				  (const char *)NULL,           \
				  (const jsmntok_t *)NULL,      \
				  (arg)) == (struct command_result *)NULL); })

#define p_opt(name, cbx, arg) p_opt_depr(name, NULL, NULL, (cbx), (arg))

/*
 * Add an optional parameter.  *arg is set to @def if it isn't found.
 */
#define p_opt_def(name, cbx, arg, def)				    \
		  name"",					    \
		  PARAM_OPTIONAL_WITH_DEFAULT,			    \
		  NULL, NULL,					    \
		  (param_cbx)(cbx),				    \
		  ({ (*arg) = tal((cmd), typeof(**arg));            \
		     (**arg) = (def);                               \
		     (arg) + 0*sizeof((cbx)((struct command *)NULL, \
				   (const char *)NULL,		    \
				   (const char *)NULL,		    \
				   (const jsmntok_t *)NULL,	    \
				   (arg)) == (struct command_result *)NULL); })

/*
 * Add a dev-only parameter.  *arg is set to @def if it isn't found.
 */
#define p_opt_dev(name, cbx, arg, def)				    \
		  name"",					    \
		  PARAM_OPTIONAL_DEV_WITH_DEFAULT,		    \
		  NULL, NULL,					    \
		  (param_cbx)(cbx),				    \
		  ({ (*arg) = tal((cmd), typeof(**arg));            \
		     (**arg) = (def);                               \
		     (arg) + 0*sizeof((cbx)((struct command *)NULL, \
				   (const char *)NULL,		    \
				   (const char *)NULL,		    \
				   (const jsmntok_t *)NULL,	    \
				   (arg)) == (struct command_result *)NULL); })

/* Special flag for 'check' which allows any parameters. */
#define p_opt_any() "", PARAM_OPTIONAL, NULL, NULL, NULL, NULL, NULL

/* All the helper routines. */
struct amount_msat;
struct amount_sat;
struct bitcoin_txid;
struct bitcoin_outpoint;
struct channel_id;
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

/* Extract an invoice string from a generic string, strip the `lightning:`
 * prefix from it if needed. */
struct command_result *param_invstring(struct command *cmd, const char *name,
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
struct command_result *param_u16(struct command *cmd, const char *name,
				 const char *buffer, const jsmntok_t *tok,
				 uint16_t **num);

/* Extract number from this (may be a string, or a number literal) */
struct command_result *param_u32(struct command *cmd, const char *name,
				 const char *buffer, const jsmntok_t *tok,
				 uint32_t **num);

/* Extract number from this (may be a string, or a number literal) */
struct command_result *param_u64(struct command *cmd, const char *name,
				 const char *buffer, const jsmntok_t *tok,
				 uint64_t **num);

/* Extract number from this (may be a string, or a number literal) */
struct command_result *param_s64(struct command *cmd, const char *name,
				 const char *buffer, const jsmntok_t *tok,
				 int64_t **num);

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

struct command_result *param_short_channel_id_dir(struct command *cmd,
						  const char *name,
						  const char *buffer,
						  const jsmntok_t *tok,
						  struct short_channel_id_dir **scidd);

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

struct command_result *param_pubkey(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    struct pubkey **pubkey);

#endif /* LIGHTNING_COMMON_JSON_PARAM_H */
