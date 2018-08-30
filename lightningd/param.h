#ifndef LIGHTNING_LIGHTNINGD_PARAM_H
#define LIGHTNING_LIGHTNINGD_PARAM_H
#include "config.h"

/*~ Greetings adventurer!
 *
 * Do you want to automatically validate json input and unmarshall it into
 * local variables, all using typesafe callbacks?  And on error,
 * call command_fail with a proper error message? Then you've come to the
 * right place!
 *
 * Here is a simple example of using the system:
 *
 * 	unsigned *cltv;
 * 	u64 *msatoshi;
 * 	const jsmntok_t *note;
 * 	u64 *expiry;
 *
 * 	if (!param(cmd, buffer, params,
 * 		   p_req("cltv", json_tok_number, &cltv),
 * 		   p_opt("msatoshi", json_tok_u64, &msatoshi),
 * 		   p_opt("note", json_tok_tok, &note),
 * 		   p_opt_def("expiry", json_tok_u64, &expiry, 3600),
 * 		   NULL))
 * 		return;
 *
 * If param() returns true then you're good to go.
 *
 * All the command handlers throughout the code use this system.
 * json_invoice() is a great example.  The common callbacks can be found in
 * lightningd/json.c.  Use them directly or feel free to write your own.
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
