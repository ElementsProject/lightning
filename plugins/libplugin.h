/* Helper library for C plugins. */
#ifndef LIGHTNING_PLUGINS_LIBPLUGIN_H
#define LIGHTNING_PLUGINS_LIBPLUGIN_H
#include "config.h"

#include <ccan/intmap/intmap.h>
#include <ccan/membuf/membuf.h>
#include <ccan/strmap/strmap.h>
#include <ccan/time/time.h>
#include <ccan/timer/timer.h>
#include <common/errcode.h>
#include <common/json.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/param.h>
#include <common/status_levels.h>

struct json_out;

enum plugin_restartability {
	PLUGIN_STATIC,
	PLUGIN_RESTARTABLE
};

struct rpc_conn {
	int fd;
	MEMBUF(char) mb;
};

struct plugin {
	/* lightningd interaction */
	struct io_conn *stdin_conn;
	struct io_conn *stdout_conn;

	/* To read from lightningd */
	char *buffer;
	size_t used, len_read;

	/* To write to lightningd */
	struct json_stream **js_arr;

	/* Asynchronous RPC interaction */
	struct io_conn *io_rpc_conn;
	struct json_stream **rpc_js_arr;
	char *rpc_buffer;
	size_t rpc_used, rpc_len_read;
	/* Tracking async RPC requests */
	UINTMAP(struct out_req *) out_reqs;
	u64 next_outreq_id;

	/* Synchronous RPC interaction */
	struct rpc_conn rpc_conn;

	/* Plugin informations */
	enum plugin_restartability restartability;
	const struct plugin_command *commands;
	size_t num_commands;
	const struct plugin_notification *notif_subs;
	size_t num_notif_subs;
	const struct plugin_hook *hook_subs;
	size_t num_hook_subs;
	struct plugin_option *opts;

	/* Anything special to do at init ? */
	void (*init)(struct plugin *p,
		     const char *buf, const jsmntok_t *);
	/* Has the manifest been sent already ? */
	bool manifested;
	/* Has init been received ? */
	bool initialized;

	/* Map from json command names to usage strings: we don't put this inside
	 * struct json_command as it's good practice to have those const. */
	STRMAP(const char *) usagemap;
	/* Timers */
	struct timers timers;
	size_t in_timer;

	bool deprecated_apis;
};

struct command {
	u64 *id;
	const char *methodname;
	bool usage_only;
	struct plugin *plugin;
};

/* Create an array of these, one for each command you support. */
struct plugin_command {
	const char *name;
	const char *category;
	const char *description;
	const char *long_description;
	struct command_result *(*handle)(struct command *cmd,
					 const char *buf,
					 const jsmntok_t *params);
};

/* Create an array of these, one for each --option you support. */
struct plugin_option {
	const char *name;
	const char *type;
	const char *description;
	char *(*handle)(const char *str, void *arg);
	void *arg;
};

/* Create an array of these, one for each notification you subscribe to. */
struct plugin_notification {
	const char *name;
	void (*handle)(struct command *cmd,
	               const char *buf,
	               const jsmntok_t *params);
};

/* Create an array of these, one for each hook you subscribe to. */
struct plugin_hook {
	const char *name;
	struct command_result *(*handle)(struct command *cmd,
	                                 const char *buf,
	                                 const jsmntok_t *params);
};

/* Helper to create a zero or single-value JSON object; if @str is NULL,
 * object is empty. */
struct json_out *json_out_obj(const tal_t *ctx,
			      const char *fieldname,
			      const char *str);

/* Return this iff the param() call failed in your handler. */
struct command_result *command_param_failed(void);

/* Call this on fatal error. */
void NORETURN plugin_err(struct plugin *p, const char *fmt, ...);

/* This command is finished, here's a detailed error; @cmd cannot be
 * NULL, data can be NULL; otherwise it must be a JSON object. */
struct command_result *WARN_UNUSED_RESULT
command_done_err(struct command *cmd,
		 errcode_t code,
		 const char *errmsg,
		 const struct json_out *data);

/* Send a raw error response. Useful for forwarding a previous
 * error after cleanup */
struct command_result *command_err_raw(struct command *cmd,
				       const char *json_str);

/* This command is finished, here's the result object; @cmd cannot be NULL. */
struct command_result *WARN_UNUSED_RESULT
command_success(struct command *cmd, const struct json_out *result);

/* Simple version where we just want to send a string, or NULL means an empty
 * result object.  @cmd cannot be NULL. */
struct command_result *WARN_UNUSED_RESULT
command_success_str(struct command *cmd, const char *str);

/* Synchronous helper to send command and extract single field from
 * response; can only be used in init callback. */
const char *rpc_delve(const tal_t *ctx,
		      struct plugin *plugin,
		      const char *method,
		      const struct json_out *params TAKES,
		      const char *guide);

/* Async rpc request.
 * @cmd can be NULL if we're coming from a timer callback.
 * @params can be NULL, otherwise it's an array or object.
 */
struct command_result *
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
	     const struct json_out *params TAKES);

#define send_outreq(cmd, method, cb, errcb, arg, params)		\
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
		     (arg), (params))

/* Callback to just forward error and close request; @cmd cannot be NULL */
struct command_result *forward_error(struct command *cmd,
				     const char *buf,
				     const jsmntok_t *error,
				     void *arg);

/* Callback to just forward result and close request; @cmd cannot be NULL */
struct command_result *forward_result(struct command *cmd,
				      const char *buf,
				      const jsmntok_t *result,
				      void *arg);

/* Callback for timer where we expect a 'command_result'.  All timers
 * must return this eventually, though they may do so via a convoluted
 * send_req() path. */
struct command_result *timer_complete(struct plugin *p);

/* Access timer infrastructure to add a timer.
 *
 * Freeing this releases the timer, otherwise it's freed after @cb
 * if it hasn't been freed already.
 */
struct plugin_timer *plugin_timer(struct plugin *p,
				  struct timerel t,
				  struct command_result *(*cb)(struct plugin *p));

/* Log something */
void plugin_log(struct plugin *p, enum log_level l, const char *fmt, ...) PRINTF_FMT(3, 4);

/* Macro to define arguments */
#define plugin_option(name, type, description, set, arg)			\
	(name),								\
	(type),								\
	(description),							\
	typesafe_cb_preargs(char *, void *, (set), (arg), const char *),	\
	(arg)

/* Standard helpers */
char *u64_option(const char *arg, u64 *i);
char *charp_option(const char *arg, char **p);

/* The main plugin runner: append with 0 or more plugin_option(), then NULL. */
void NORETURN LAST_ARG_NULL plugin_main(char *argv[],
					void (*init)(struct plugin *p,
						     const char *buf, const jsmntok_t *),
					const enum plugin_restartability restartability,
					const struct plugin_command *commands,
					size_t num_commands,
					const struct plugin_notification *notif_subs,
					size_t num_notif_subs,
					const struct plugin_hook *hook_subs,
					size_t num_hook_subs,
					...);
#endif /* LIGHTNING_PLUGINS_LIBPLUGIN_H */
