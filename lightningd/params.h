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
	u64 *msatoshi;

	if (!param_parse(cmd, buffer, tokens,
			 param_req("cltv", json_tok_number, &cltv),
			 param_opt_tok("note", &note),
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
 * of @arg and the last parameter of @cb do not match.
 *
 * Returns an opaque pointer.
 */
#define param_req(name, cb, arg)					\
		  param_add(name"",					\
			    typesafe_cb_preargs(bool, void *,		\
					        (cb), (arg),		\
					        const char *,		\
					        const jsmntok_t *),	\
			    (arg), 0)

/*
 * Similar to above but for optional parameters.
 * @arg must be the address of a pointer. If found during parsing, it will be
 * allocated, otherwise it will be set to NULL.
 */
#define param_opt(name, cb, arg)				\
		  param_add(name"",				\
		  typesafe_cb_preargs(bool, void *,		\
				      (cb), *(arg),		\
				      const char *,		\
				      const jsmntok_t *),	\
		  (arg), sizeof(**arg))

/*
 * For when you want an optional raw token.
 *
 * Note: We use sizeof() to comiple-time type check that @arg really is a
 * (const) jsmntok_t **.
 */
#define param_opt_tok(name, arg)                                      \
		      param_add(name"",                               \
		      (param_cb) json_tok_tok,                        \
		      (arg) + 0*sizeof(*(arg) == (jsmntok_t *)NULL),  \
		      sizeof(const jsmntok_t *))

struct param *param_add(const char *name, param_cb cb, void *arg,
			size_t argsize);
#endif /* LIGHTNING_LIGHTNINGD_PARAMS_H */
