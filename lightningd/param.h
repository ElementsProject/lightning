#ifndef LIGHTNING_LIGHTNINGD_PARAM_H
#define LIGHTNING_LIGHTNINGD_PARAM_H
#include "config.h"

/*
  Typesafe callback system for unmarshalling and validating json parameters.

  Typical usage:
	unsigned cltv;
	u64 *msatoshi;
	const jsmntok_t *note;
	u64 expiry;

	if (!param(cmd, buffer, params,
		   p_req("cltv", json_tok_number, &cltv),
		   p_opt("msatoshi", json_tok_u64, &msatoshi),
		   p_opt_tok("note", &note),
		   p_opt_def("expiry", json_tok_u64, &expiry, 3600),
		   NULL))
		return;

  At this point in the code you can be assured the json tokens were successfully
  parsed.  If not, param() returned false, having already called command_fail()
  with a descriptive error message. The data section of the json result contains
  the offending parameter and its value.

  cltv is a required parameter. It must be present in the json input and will
  be set appropriately.

  msatoshi is optional.  If not present it will be set to NULL.

  note is also optional. It uses a special callback that simply sets note to the
  appropriate value (or NULL) and lets the handler do the validating.

  expiry is also optional and will be set to a default value if not present.

  There are canned failure messages for common callbacks. An example:

	'msatoshi' should be an unsigned 64 bit integer, not '123z'

  Otherwise a generic message is provided.
 */

/*
 * parse the json tokens.  @params can be an array of values, or an object
 * of named values.
 */
bool param(struct command *cmd, const char *buffer,
	   const jsmntok_t params[], ...);

/*
 * The callback provided must follow this signature; e.g.,
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
 */
#define p_req(name, cb, arg)					\
	      name"",						\
	      true,						\
	      (cb),				 		\
	      (arg) + 0*sizeof((cb)((const char *)NULL,		\
				    (const jsmntok_t *)NULL,	\
				    (arg)) == true),		\
	      (size_t)0

/*
 * Similar to above but for optional parameters.
 * @arg must be the address of a pointer. If found during parsing, it will be
 * allocated, otherwise it will be set to NULL.
 */
#define p_opt(name, cb, arg)					\
	      name"",						\
	      false,						\
	      (cb),				 		\
	      (arg) + 0*sizeof((cb)((const char *)NULL,		\
				    (const jsmntok_t *)NULL,	\
				    *(arg)) == true),		\
	      sizeof(**(arg))

/*
 * Similar to p_req but for optional parameters with defaults.
 * @arg will be set to @def if it isn't found during parsing.
 */
#define p_opt_def(name, cb, arg, def)					\
		  name"",						\
		  false,						\
		  (cb),							\
		  (arg) + 0*sizeof((cb)((const char *)NULL,		\
					(const jsmntok_t *)NULL,	\
					(arg)) == true),		\
		  ((void)((*arg) = (def)), (size_t)0)

/*
 * For when you want an optional raw token.
 *
 * Note: weird sizeof() does type check that arg really is a (const) jsmntok_t **.
 */
#define p_opt_tok(name, arg)						\
		  name"",						\
		  false,						\
		  json_tok_tok,						\
		  (arg) + 0*sizeof(*(arg) == (jsmntok_t *)NULL),	\
		  sizeof(const jsmntok_t *)

#endif /* LIGHTNING_LIGHTNINGD_PARAM_H */
