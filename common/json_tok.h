/* Helpers for use with param parsing. */
#ifndef LIGHTNING_COMMON_JSON_TOK_H
#define LIGHTNING_COMMON_JSON_TOK_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <common/json.h>
#include <common/node_id.h>

struct amount_msat;
struct amount_sat;
struct command;
struct command_result;
struct json_escape;
struct sha256;

/* Extract json array token */
struct command_result *param_array(struct command *cmd, const char *name,
				   const char *buffer, const jsmntok_t *tok,
				   const jsmntok_t **arr);

/* Extract boolean this (must be a true or false) */
struct command_result *param_bool(struct command *cmd, const char *name,
				  const char *buffer, const jsmntok_t *tok,
				  bool **b);

/* Extract double from this (must be a number literal) */
struct command_result *param_double(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    double **num);

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

/* Extract double in range [0.0, 100.0] */
struct command_result *param_percent(struct command *cmd, const char *name,
				     const char *buffer, const jsmntok_t *tok,
				     double **num);

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
#endif /* LIGHTNING_COMMON_JSON_TOK_H */
