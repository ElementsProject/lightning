/* Helpers for use with param parsing. */
#ifndef LIGHTNING_COMMON_JSON_TOK_H
#define LIGHTNING_COMMON_JSON_TOK_H
#include "config.h"
#include <common/json.h>

struct command;

/* Extract json array token */
bool json_tok_array(struct command *cmd, const char *name,
		    const char *buffer, const jsmntok_t *tok,
		    const jsmntok_t **arr);

/* Extract boolean this (must be a true or false) */
bool json_tok_bool(struct command *cmd, const char *name,
		   const char *buffer, const jsmntok_t *tok,
		   bool **b);

/* Extract double from this (must be a number literal) */
bool json_tok_double(struct command *cmd, const char *name,
		     const char *buffer, const jsmntok_t *tok,
		     double **num);

/* Extract an escaped string (and unescape it) */
bool json_tok_escaped_string(struct command *cmd, const char *name,
			     const char * buffer, const jsmntok_t *tok,
			     const char **str);

/* Extract a string */
bool json_tok_string(struct command *cmd, const char *name,
		     const char * buffer, const jsmntok_t *tok,
		     const char **str);

/* Extract a label. It is either an escaped string or a number. */
bool json_tok_label(struct command *cmd, const char *name,
		    const char * buffer, const jsmntok_t *tok,
		    struct json_escaped **label);

/* Extract number from this (may be a string, or a number literal) */
bool json_tok_number(struct command *cmd, const char *name,
		     const char *buffer, const jsmntok_t *tok,
		     unsigned int **num);

/* Extract sha256 hash */
bool json_tok_sha256(struct command *cmd, const char *name,
		     const char *buffer, const jsmntok_t *tok,
		     struct sha256 **hash);

/* Extract positive integer, or NULL if tok is 'any'. */
bool json_tok_msat(struct command *cmd, const char *name,
		   const char *buffer, const jsmntok_t * tok,
		   u64 **msatoshi_val);

/* Extract double in range [0.0, 100.0] */
bool json_tok_percent(struct command *cmd, const char *name,
		      const char *buffer, const jsmntok_t *tok,
		      double **num);

/* Extract number from this (may be a string, or a number literal) */
bool json_tok_u64(struct command *cmd, const char *name,
		  const char *buffer, const jsmntok_t *tok,
		  uint64_t **num);

/*
 * Set the address of @out to @tok.  Used as a callback by handlers that
 * want to unmarshal @tok themselves.
 *
 * Usage of this is discouraged.  Writing a local static bespoke handler is
 * preferred.
 */
bool json_tok_tok(struct command *cmd, const char *name,
		  const char *buffer, const jsmntok_t * tok,
		  const jsmntok_t **out);

#endif /* LIGHTNING_COMMON_JSON_TOK_H */
