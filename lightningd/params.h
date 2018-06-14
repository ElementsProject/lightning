#ifndef LIGHTNING_LIGHTNINGD_PARAMS_H
#define LIGHTNING_LIGHTNINGD_PARAMS_H
#include "config.h"
#include <ccan/ccan/typesafe_cb/typesafe_cb.h>

/*
  Typesafe callback system for unmarshalling and validating json parameters.

  Typical usage:
	uint64_t msatohi;
	unsigned cltv = 9;
	const jsmntok_t *seedtok;

	struct param_table *pt = new_param_table(cmd);
	param_add(pt, "msatoshi", json_tok_u64, &msatoshi);
	param_add(pt, "?cltv", json_tok_number, &cltv);
	param_add(pt, "?seed", json_tok_tok, &seedtok);
	if (!param_parse(pt, buffer, params))
		return;

  At this point in the code, you can be assured msatoshi, cltv, and seedtok are
  valid.  If not, param_parse() returned false, having already called
  command_fail() with a descriptive error message. The data section of the json
  result contains the offending parameter and its value.

  The '?' before cltv indicates it is optional.  You can see if cltv was
  specified by calling param_is_set(pt, &cltv).

  The seed parameter (also optional) uses a special callback, json_tok_tok(). It
  simply sets seedtok to the appropriate value and lets the handler do the
  validating. It has the added feature of setting seedtok to NULL if it is null
  or not specified.

  There are canned failure messages for common callbacks. An example:

	'msatoshi' should be an unsigned 64 bit integer, not '123z'

  Otherwise a generic message is provided.
 */

/*
 * This callback provided must follow this signature.
 * ex: bool json_tok_double(const char *buffer, const jsmntok_t *tok, double *arg)
 */
typedef bool(*param_cb)(const char *buffer, const jsmntok_t * tok, void *arg);

struct param_table;

/*
 * Initialize a new parameter table. This must be done first.
 */
struct param_table *new_param_table(struct command *cmd);

/*
 * Add a handler to unmarshal a json token into @arg. The handler must return
 * true on success and false on failure.  Upon failure, command_fail will be
 * automatically called with a descriptive error message.
 *
 * A compilation error will occur if the types of @arg and the last parameter of
 * @cb do not match.
 */
#define param_add(table, name, cb, arg)                   \
		  param_add_(table, name,                 \
		  typesafe_cb_preargs(bool, void *,       \
				      (cb), (arg),        \
				      const char *,       \
				      const jsmntok_t *), \
				      (arg))
void param_add_(struct param_table *table,
		char *name, param_cb cb, void *arg);

/*
 * Parse the parameters, calling appropriate callbacks.  Returns true on
 * success, false on failure with command_fail() already called.
 */
bool param_parse(const struct param_table *table,
		 const char *buffer, const jsmntok_t params[]);

/*
 * Check to see if an optional parameter was set during parsing (although it
 * works for all parameters).  abort() is called if @name is not a parameter.
 * Returns @arg if set, otherwise NULL.
 */
void * param_is_set(struct param_table *pt, void *arg);

#endif /* LIGHTNING_LIGHTNINGD_PARAMS_H */
