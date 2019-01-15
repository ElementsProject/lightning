/* Helper library for C plugins. */
#ifndef LIGHTNING_PLUGINS_LIBPLUGIN_H
#define LIGHTNING_PLUGINS_LIBPLUGIN_H
#include "config.h"

#include <common/json.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/param.h>

struct command;
struct plugin_conn;

/* Create an array of these, one for each command you support. */
struct plugin_command {
	const char *name;
	const char *description;
	const char *long_description;
	struct command_result *(*handle)(struct command *cmd,
					 const char *buf,
					 const jsmntok_t *params);
};

/* Return this iff the param() call failed in your handler. */
struct command_result *command_param_failed(void);

/* Call this on fatal error. */
void NORETURN plugin_err(const char *fmt, ...);

/* This command is finished, here's a detailed error. data can be NULL. */
struct command_result *WARN_UNUSED_RESULT
command_done_err(struct command *cmd,
		 int code,
		 const char *errmsg,
		 const char *data);

/* This command is finished, here's the success msg. */
struct command_result *WARN_UNUSED_RESULT
command_success(struct command *cmd, const char *result);

/* Synchronous helper to send command and extract single field from
 * response; can only be used in init callback. */
const char *rpc_delve(const tal_t *ctx,
		      const char *method, const char *params,
		      struct plugin_conn *rpc, const char *guide);

/* Async rpc request.  For convenience, and single ' are turned into ". */
PRINTF_FMT(6,7) struct command_result *
send_outreq_(struct command *cmd,
	     const char *method,
	     struct command_result *(*cb)(struct command *command,
					  const char *buf,
					  const jsmntok_t *result,
					  void *arg),
	     struct command_result *(*errcb)(struct command *command,
					     const char *buf,
					     const jsmntok_t *result,
					     void *arg),
	     void *arg,
	     const char *paramfmt_single_ticks, ...);

#define send_outreq(cmd, method, cb, errcb, arg, ...)			\
	send_outreq_((cmd), (method),					\
		     typesafe_cb_preargs(struct command_result *, void *, \
					 (cb), (arg),			\
					 struct command *command,	\
					 const char *buf,		\
					 const jsmntok_t *result),	\
		     typesafe_cb_preargs(struct command_result *, void *, \
					 (errcb), (arg),		\
					 struct command *command,	\
					 const char *buf,		\
					 const jsmntok_t *result),	\
		     (arg), __VA_ARGS__)

/* Callback to just forward error and close request. */
struct command_result *forward_error(struct command *cmd,
				     const char *buf,
				     const jsmntok_t *error,
				     void *arg);

/* Callback to just forward result and close request. */
struct command_result *forward_result(struct command *cmd,
				      const char *buf,
				      const jsmntok_t *result,
				      void *arg);

/* The main plugin runner. */
void NORETURN plugin_main(char *argv[],
			  void (*init)(struct plugin_conn *rpc),
			  const struct plugin_command *commands,
			  size_t num_commands);
#endif /* LIGHTNING_PLUGINS_LIBPLUGIN_H */
