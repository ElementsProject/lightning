#ifndef LIGHTNING_COMMON_PARAM_H
#define LIGHTNING_COMMON_PARAM_H
#include "config.h"
#include <common/json.h>

/*~ Greetings adventurer!
 *
 * Do you want to automatically validate json input and unmarshal it into
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
 * common/json_tok.c.  Use them directly or feel free to write your own.
 */
struct command;

/* A dummy type returned by command_ functions, to ensure you return them
 * immediately */
struct command_result;

/*
 * Parse the json tokens.  @params can be an array of values or an object
 * of named values.
 */
bool param(struct command *cmd, const char *buffer,
	   const jsmntok_t params[], ...) LAST_ARG_NULL;

/*
 * The callback signature.
 *
 * Callbacks must return NULL on success.  On failure they
 * must return command_fail(...).
 */
typedef struct command_result *(*param_cbx)(struct command *cmd,
					    const char *name,
					    const char *buffer,
					    const jsmntok_t *tok,
					    void **arg);

/**
 * Parse the first json value.
 *
 * name...: NULL-terminated array of valid values.
 *
 * Returns subcommand: if it returns NULL if you should return
 * command_param_failed() immediately.
 */
const char *param_subcommand(struct command *cmd, const char *buffer,
			     const jsmntok_t tokens[],
			     const char *name, ...) LAST_ARG_NULL;

/*
 * Add a required parameter.
 */
#define p_req(name, cbx, arg)				     \
	      name"",                                        \
	      true,                                          \
	      (param_cbx)(cbx),				     \
	      (arg) + 0*sizeof((cbx)((struct command *)NULL, \
			       (const char *)NULL,           \
			       (const char *)NULL,           \
			       (const jsmntok_t *)NULL,      \
			       (arg)) == (struct command_result *)NULL)

/*
 * Add an optional parameter.  *arg is set to NULL if it isn't found.
 */
#define p_opt(name, cbx, arg)                                   \
	      name"",                                           \
	      false,                                            \
	      (param_cbx)(cbx),                                 \
	      ({ *arg = NULL;                                   \
		 (arg) + 0*sizeof((cbx)((struct command *)NULL, \
		                  (const char *)NULL,           \
				  (const char *)NULL,           \
				  (const jsmntok_t *)NULL,      \
				  (arg)) == (struct command_result *)NULL); })

/*
 * Add an optional parameter.  *arg is set to @def if it isn't found.
 */
#define p_opt_def(name, cbx, arg, def)				    \
		  name"",					    \
		  false,					    \
		  (param_cbx)(cbx),				    \
		  ({ (*arg) = tal((cmd), typeof(**arg));            \
		     (**arg) = (def);                               \
		     (arg) + 0*sizeof((cbx)((struct command *)NULL, \
				   (const char *)NULL,		    \
				   (const char *)NULL,		    \
				   (const jsmntok_t *)NULL,	    \
				   (arg)) == (struct command_result *)NULL); })

/* Special flag for 'check' which allows any parameters. */
#define p_opt_any() "", false, NULL, NULL
#endif /* LIGHTNING_COMMON_PARAM_H */
