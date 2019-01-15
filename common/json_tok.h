/* Helpers for use with param parsing. */
#ifndef LIGHTNING_COMMON_JSON_TOK_H
#define LIGHTNING_COMMON_JSON_TOK_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <common/json.h>

struct command;
struct command_result;
struct json_escaped;
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
				   struct json_escaped **label);

/* Extract number from this (may be a string, or a number literal) */
struct command_result *param_number(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    unsigned int **num);

/* Extract sha256 hash */
struct command_result *param_sha256(struct command *cmd, const char *name,
				    const char *buffer, const jsmntok_t *tok,
				    struct sha256 **hash);

/* Extract positive integer, or NULL if tok is 'any'. */
struct command_result *param_msat(struct command *cmd, const char *name,
				  const char *buffer, const jsmntok_t * tok,
				  u64 **msatoshi_val);

/* Extract double in range [0.0, 100.0] */
struct command_result *param_percent(struct command *cmd, const char *name,
				     const char *buffer, const jsmntok_t *tok,
				     double **num);

/* Extract number from this (may be a string, or a number literal) */
struct command_result *param_u64(struct command *cmd, const char *name,
				 const char *buffer, const jsmntok_t *tok,
				 uint64_t **num);

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

#endif /* LIGHTNING_COMMON_JSON_TOK_H */
