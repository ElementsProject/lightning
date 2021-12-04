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
#include <common/features.h>
#include <common/json.h>
#include <common/json_command.h>
#include <common/json_helpers.h>
#include <common/jsonrpc_errors.h>
#include <common/node_id.h>
#include <common/param.h>
#include <common/status_levels.h>
#include <common/utils.h>

struct json_out;
struct plugin;
struct rpc_conn;

extern bool deprecated_apis;

enum plugin_restartability {
	PLUGIN_STATIC,
	PLUGIN_RESTARTABLE
};

struct out_req {
	/* The unique id of this request. */
	u64 id;
	/* The command which is why we're calling this rpc. */
	struct command *cmd;
	/* The request stream. */
	struct json_stream *js;
	/* The callback when we get a response. */
	struct command_result *(*cb)(struct command *command,
				     const char *buf,
				     const jsmntok_t *result,
				     void *arg);
	/* The callback when we get an error. */
	struct command_result *(*errcb)(struct command *command,
					const char *buf,
					const jsmntok_t *error,
					void *arg);
	void *arg;
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
	/* If true, this command *disabled* if allow-deprecated-apis = false */
	bool deprecated;
};

/* Create an array of these, one for each --option you support. */
struct plugin_option {
	const char *name;
	const char *type;
	const char *description;
	char *(*handle)(const char *str, void *arg);
	void *arg;
	/* If true, this options *disabled* if allow-deprecated-apis = false */
	bool deprecated;
};

/* Create an array of these, one for each notification you subscribe to. */
struct plugin_notification {
	const char *name;
	/* The handler must eventually trigger a `notification_handled`
	 * call.  */
	struct command_result* (*handle)(struct command *cmd,
					 const char *buf,
					 const jsmntok_t *params);
};

/* Create an array of these, one for each hook you subscribe to. */
struct plugin_hook {
	const char *name;
	struct command_result *(*handle)(struct command *cmd,
	                                 const char *buf,
	                                 const jsmntok_t *params);
	/* If non-NULL, these are NULL-terminated arrays of deps */
	const char **before, **after;
};

/* Return the feature set of the current lightning node */
const struct feature_set *plugin_feature_set(const struct plugin *p);

/* Helper to create a JSONRPC2 request stream. Send it with `send_outreq`. */
struct out_req *jsonrpc_request_start_(struct plugin *plugin,
				       struct command *cmd,
				       const char *method,
				       struct command_result *(*cb)(struct command *command,
								    const char *buf,
								    const jsmntok_t *result,
								    void *arg),
				       struct command_result *(*errcb)(struct command *command,
								       const char *buf,
								       const jsmntok_t *result,
								       void *arg),
				       void *arg);

#define jsonrpc_request_start(plugin, cmd, method, cb, errcb, arg)	\
	jsonrpc_request_start_((plugin), (cmd), (method),		\
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
		     (arg))


/* Helper to create a JSONRPC2 response stream with a "result" object. */
struct json_stream *jsonrpc_stream_success(struct command *cmd);

/* Helper to create a JSONRPC2 response stream with an "error" object. */
struct json_stream *jsonrpc_stream_fail(struct command *cmd,
					int code,
					const char *err);

/* Helper to create a JSONRPC2 response stream with an "error" object,
 * to which will be added a "data" object. */
struct json_stream *jsonrpc_stream_fail_data(struct command *cmd,
					     int code,
					     const char *err);

/* This command is finished, here's the response (the content of the
 * "result" or "error" field) */
WARN_UNUSED_RESULT
struct command_result *command_finished(struct command *cmd, struct json_stream *response);

/* Helper for a command that'll be finished in a callback. */
WARN_UNUSED_RESULT
struct command_result *command_still_pending(struct command *cmd);

/* Helper to create a zero or single-value JSON object; if @str is NULL,
 * object is empty. */
struct json_out *json_out_obj(const tal_t *ctx,
			      const char *fieldname,
			      const char *str);

/* Return this iff the param() call failed in your handler. */
struct command_result *command_param_failed(void);

/* Call this on fatal error. */
void NORETURN plugin_err(struct plugin *p, const char *fmt, ...);

/* Normal exit (makes sure to flush output!). */
void NORETURN plugin_exit(struct plugin *p, int exitcode);

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

/* End a hook normally (with "result": "continue") */
struct command_result *WARN_UNUSED_RESULT
command_hook_success(struct command *cmd);

/* End a notification handler.  */
struct command_result *WARN_UNUSED_RESULT
notification_handled(struct command *cmd);

/* Helper for notification handler that will be finished in a callback.  */
#define notification_handler_pending(cmd) command_still_pending(cmd)

/* Synchronous helper to send command and extract fields from
 * response; can only be used in init callback. */
void rpc_scan(struct plugin *plugin,
	      const char *method,
	      const struct json_out *params TAKES,
	      const char *guide,
	      ...);

/* Send an async rpc request to lightningd. */
struct command_result *send_outreq(struct plugin *plugin,
				   const struct out_req *req);

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

/* Signals that we've completed a command. Useful for when
 * there's no `cmd` present */
struct command_result *command_done(void);

/* Access timer infrastructure to add a timer.
 *
 * Freeing this releases the timer, otherwise it's freed after @cb
 * if it hasn't been freed already.
 */
struct plugin_timer *plugin_timer_(struct plugin *p,
				   struct timerel t,
				   void (*cb)(void *cb_arg),
				   void *cb_arg);

#define plugin_timer(plugin, time, cb, cb_arg)		\
	plugin_timer_((plugin), (time),			\
		      typesafe_cb(void, void *,		\
				  (cb), (cb_arg)),	\
		      (cb_arg))				\

/* Log something */
void plugin_log(struct plugin *p, enum log_level l, const char *fmt, ...) PRINTF_FMT(3, 4);

/* Notify the caller of something. */
struct json_stream *plugin_notify_start(struct command *cmd, const char *method);
void plugin_notify_end(struct command *cmd, struct json_stream *js);

/* Send a notification for a custom notification topic. These are sent
 * to lightningd and distributed to subscribing plugins. */
struct json_stream *plugin_notification_start(struct plugin *plugins,
					      const char *method);
void plugin_notification_end(struct plugin *plugin,
			     struct json_stream *stream TAKES);

/* Convenience wrapper for notify "message" */
void plugin_notify_message(struct command *cmd,
			   enum log_level level,
			   const char *fmt, ...)
	PRINTF_FMT(3, 4);

/* Convenience wrapper for progress: num_stages is normally 0. */
void plugin_notify_progress(struct command *cmd,
			    u32 num_stages, u32 stage,
			    u32 num_progress, u32 progress);

/* Macro to define arguments */
#define plugin_option_(name, type, description, set, arg, deprecated)	\
	(name),								\
	(type),								\
	(description),							\
	typesafe_cb_preargs(char *, void *, (set), (arg), const char *),	\
	(arg),								\
	(deprecated)

#define plugin_option(name, type, description, set, arg) \
	plugin_option_((name), (type), (description), (set), (arg), false)

#define plugin_option_deprecated(name, type, description, set, arg) \
	plugin_option_((name), (type), (description), (set), (arg), true)

/* Standard helpers */
char *u64_option(const char *arg, u64 *i);
char *u32_option(const char *arg, u32 *i);
char *u16_option(const char *arg, u16 *i);
char *bool_option(const char *arg, bool *i);
char *charp_option(const char *arg, char **p);
char *flag_option(const char *arg, bool *i);

/* The main plugin runner: append with 0 or more plugin_option(), then NULL. */
void NORETURN LAST_ARG_NULL plugin_main(char *argv[],
					const char *(*init)(struct plugin *p,
							    const char *buf,
							    const jsmntok_t *),
					const enum plugin_restartability restartability,
					bool init_rpc,
					struct feature_set *features STEALS,
					const struct plugin_command *commands TAKES,
					size_t num_commands,
					const struct plugin_notification *notif_subs TAKES,
					size_t num_notif_subs,
					const struct plugin_hook *hook_subs TAKES,
					size_t num_hook_subs,
					const char **notif_topics TAKES,
					size_t num_notif_topics,
					...);

struct listpeers_channel {
	bool private;
	struct bitcoin_txid funding_txid;
	const char *state;
	struct short_channel_id *scid;
	int *direction;
	struct amount_msat total_msat;
	struct amount_msat spendable_msat;
	/* TODO Add fields as we need them. */
};

struct listpeers_peer {
	struct node_id id;
	bool connected;
	const char **netaddr;
	struct feature_set *features;
	struct listpeers_channel **channels;
};

struct listpeers_result {
	struct listpeers_peer **peers;
};

struct listpeers_result *json_to_listpeers_result(const tal_t *ctx,
						  const char *buffer,
						  const jsmntok_t *tok);

struct createonion_response {
	u8 *onion;
	struct secret *shared_secrets;
};

struct createonion_response *json_to_createonion_response(const tal_t *ctx,
							  const char *buffer,
							  const jsmntok_t *toks);

struct route_hop *json_to_route(const tal_t *ctx, const char *buffer,
				const jsmntok_t *toks);

#if DEVELOPER
struct htable;
void plugin_set_memleak_handler(struct plugin *plugin,
				void (*mark_mem)(struct plugin *plugin,
						 struct htable *memtable));
#endif /* DEVELOPER */

#endif /* LIGHTNING_PLUGINS_LIBPLUGIN_H */
