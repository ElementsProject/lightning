#ifndef LIGHTNING_LIGHTNINGD_PARAM_H
#define LIGHTNING_LIGHTNINGD_PARAM_H
#include "config.h"

/*
  Typesafe callback system for unmarshalling and validating json parameters.

  Typical usage:
	unsigned *cltv;
	u64 *msatoshi;
	const jsmntok_t *note;
	u64 *expiry;

	if (!param(cmd, buffer, params,
		   p_req("cltv", json_tok_number, &cltv),
		   p_opt("msatoshi", json_tok_u64, &msatoshi),
		   p_opt_tok("note", &note),
		   p_opt_def("expiry", json_tok_u64, &expiry, 3600),
		   NULL))
		return;

  See json_invoice() for a good example.  The common callbacks can be found in
  lightningd/json.c.  Use them as an example for writing your own custom
  callbacks.
 */

/*
 * Parse the json tokens.  @params can be an array of values or an object
 * of named values.
 */
bool param(struct command *cmd, const char *buffer,
	   const jsmntok_t params[], ...);

/*
 * The callback signature.  Callbacks must return true on success.  On failure they
 * must call comand_fail and return false.
 */
typedef bool(*param_cbx)(struct command *cmd,
			 const char *name,
			 const char *buffer,
			 const jsmntok_t *tok,
			 void **arg);

/*
 * Add a required parameter.
 */
#define p_req(name, cbx, arg)                                \
	      name"",                                        \
	      true,                                          \
	      (cbx),                                         \
	      (arg) + 0*sizeof((cbx)((struct command *)NULL, \
			       (const char *)NULL,           \
			       (const char *)NULL,           \
			       (const jsmntok_t *)NULL,      \
			       (arg)) == true)

/*
 * Add an optional parameter.  *arg is set to NULL if it isn't found.
 */
#define p_opt(name, cbx, arg)                                   \
	      name"",                                           \
	      false,                                            \
	      (cbx),                                            \
	      ({ *arg = NULL;                                   \
		 (arg) + 0*sizeof((cbx)((struct command *)NULL, \
		                  (const char *)NULL,           \
				  (const char *)NULL,           \
				  (const jsmntok_t *)NULL,      \
				  (arg)) == true); })

/*
 * Add an optional parameter.  *arg is set to @def if it isn't found.
 */
#define p_opt_def(name, cbx, arg, def)				    \
		  name"",					    \
		  false,					    \
		  (cbx),				 	    \
		  ({ (*arg) = tal((cmd), typeof(**arg));            \
		     (**arg) = (def);                               \
		     (arg) + 0*sizeof((cbx)((struct command *)NULL, \
				   (const char *)NULL,		    \
				   (const char *)NULL,		    \
				   (const jsmntok_t *)NULL,	    \
				   (arg)) == true); })

#endif /* LIGHTNING_LIGHTNINGD_PARAM_H */
