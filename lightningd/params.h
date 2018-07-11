#ifndef LIGHTNING_LIGHTNINGD_PARAMS_H
#define LIGHTNING_LIGHTNINGD_PARAMS_H
#include "config.h"

struct param;

/*
  Typesafe callback system for unmarshalling and validating json parameters.

  Typical usage:
	unsigned cltv;
	const jsmntok_t *note;
	u64 *msatoshi;

	if (!param_parse(cmd, buffer, tokens,
			 param_req("cltv", json_tok_number, &cltv),
			 param_opt("note", json_tok_tok, &note),
			 param_opt("msatoshi", json_tok_u64, &msatoshi),
			 NULL))
		return;

  At this point in the code you can be assured the json tokens were successfully
  parsed.  If not, param_parse() returns false, having already called
  command_fail() with a descriptive error message. The data section of the json
  result contains the offending parameter and its value.

  cltv is a required parameter, and is set correctly.

  note and msatoshi are optional parameters.  Their argument will be set to NULL
  if they are not provided.

  The note parameter uses a special callback, param_opt_tok: it
  simply sets note to the appropriate value (or NULL) and lets the
  handler do the validating.

  There are canned failure messages for common callbacks. An example:

	'msatoshi' should be an unsigned 64 bit integer, not '123z'

  Otherwise a generic message is provided.
 */
bool param_parse(struct command *cmd, const char *buffer,
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
 * of @arg and the last parameter of @cb do not match (see the weird 0*sizeof).
 *
 * Returns an opaque pointer that can be later used in param_is_set().
 */
#define param_req(name, cb, arg)					\
		  name"",						\
		  true,							\
		  (cb),							\
		  (arg) + 0*sizeof((cb)((const char *)NULL,		\
					(const jsmntok_t *)NULL,	\
					(arg)) == true),		\
		  0
/*
 * Similar to above but for optional parameters.
 * @arg must be the address of a pointer. If found during parsing, it will be
 * allocated, otherwise it will be set to NULL.
 */
#define param_opt(name, cb, arg)				\
		  name"",					\
		  false,					\
		  (cb),						\
		  (arg) + 0*sizeof((cb)((const char *)NULL,	\
					(const jsmntok_t *)NULL,\
					*(arg)) == true),	\
		  sizeof(**(arg))

/*
 * Similar to param_req but for optional parameters.
 * If not found during parsing, @arg will be set to @def.
 * allocated, otherwise it will be set to NULL.
 */
#define param_opt_default(name, cb, arg, def)				\
		  name"",						\
		  false,						\
		  (cb),							\
		  (arg) + 0*sizeof((cb)((const char *)NULL,		\
					(const jsmntok_t *)NULL,	\
					(arg)) == true),		\
		  ((void)((*arg) = (def)), 0)

/*
 * For when you want an optional raw token.
 *
 * Note: weird sizeof() does type check that arg really is a (const) jsmntok_t **.
 */
#define param_opt_tok(name, arg)					\
		      name"",						\
		      false,						\
		      json_tok_tok,					\
		      (arg) + 0*sizeof(*(arg) == (jsmntok_t *)NULL),	\
		      sizeof(const jsmntok_t *)

#endif /* LIGHTNING_LIGHTNINGD_PARAMS_H */
