#ifndef LIGHTNING_LIGHTNINGD_PARAMS_H
#define LIGHTNING_LIGHTNINGD_PARAMS_H
#include "config.h"
#include <ccan/ccan/typesafe_cb/typesafe_cb.h>

struct param;

/*
  Typesafe callback system for unmarshalling and validating json parameters.

  Typical usage:
	unsigned cltv;
	const jsmntok_t *note;
	u64 msatoshi;
	struct param * mp;

	if (!param_parse(cmd, buffer, tokens,
			 param_req("cltv", json_tok_number, &cltv),
			 param_opt("note", json_tok_tok, &note),
			 mp = param_opt("msatoshi", json_tok_u64, &msatoshi),
			 NULL))
		return;

  At this point in the code you can be assured the json tokens were successfully
  parsed.  If not, param_parse() returned NULL, having already called
  command_fail() with a descriptive error message. The data section of the json
  result contains the offending parameter and its value.

  cltv is a required parameter, and is set correctly.

  note and msatoshi are optional parameters.  You can see if they have been set
  by calling param_is_set(); e.g.:

	if (param_is_set(mp))
		do_something()

  The note parameter uses a special callback, json_tok_tok(). It
  simply sets seedtok to the appropriate value and lets the handler do the
  validating. It has the added feature of setting seedtok to NULL if it is null
  or not specified.

  There are canned failure messages for common callbacks. An example:

	'msatoshi' should be an unsigned 64 bit integer, not '123z'

  Otherwise a generic message is provided.
 */
struct param **param_parse(struct command *cmd, const char *buffer,
			   const jsmntok_t params[], ...);

/*
 * This callback provided must follow this signature; e.g.,
 * bool json_tok_double(const char *buffer, const jsmntok_t *tok, double *arg)
 */
typedef bool(*param_cb)(const char *buffer, const jsmntok_t *tok, void *arg);

/*
 * Add a handler to unmarshal a required json token into @arg. The handler must
 * return true on success and false on failure.  Upon failure, command_fail will be
 * called with a descriptive error message.
 *
 * This operation is typesafe; i.e., a compilation error will occur if the types
 * of @arg and the last parameter of @cb do not match.
 *
 * Returns an opaque pointer that can be later used in param_is_set().
 */
#define param_req(name, cb, arg)         \
		  param_add_(true, name, \
			     typesafe_cb_preargs(bool, void *,       \
						 (cb), (arg),        \
						 const char *,       \
						 const jsmntok_t *), \
			     (arg))
/*
 * Same as above but for optional parameters.
 */
#define param_opt(name, cb, arg)          \
		  param_add_(false, name, \
			     typesafe_cb_preargs(bool, void *,       \
						 (cb), (arg),        \
						 const char *,       \
						 const jsmntok_t *), \
			     (arg))
struct param * param_add_(bool required, char *name, param_cb cb, void *arg);

/*
 * Check to see if an optional parameter was set during parsing (although it
 * works for all parameters).
 * Returns the @arg if set, otherwise NULL.
 */
void * param_is_set(struct param *p);

#endif /* LIGHTNING_LIGHTNINGD_PARAMS_H */
