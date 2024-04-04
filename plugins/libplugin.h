/* Helper library for C plugins. */
#ifndef LIGHTNING_PLUGINS_LIBPLUGIN_H
#define LIGHTNING_PLUGINS_LIBPLUGIN_H
#include "config.h"

#include <bitcoin/tx.h>
#include <ccan/intmap/intmap.h>
#include <ccan/membuf/membuf.h>
#include <ccan/strmap/strmap.h>
#include <ccan/time/time.h>
#include <ccan/timer/timer.h>
#include <common/errcode.h>
#include <common/features.h>
#include <common/htlc.h>
#include <common/json_command.h>
#include <common/jsonrpc_errors.h>
#include <common/node_id.h>
#include <common/status_levels.h>
#include <common/utils.h>
#include <stdarg.h>

struct json_out;
struct htable;
struct plugin;
struct rpc_conn;

enum plugin_restartability {
	PLUGIN_STATIC,
	PLUGIN_RESTARTABLE
};

struct out_req {
	/* The unique id of this request. */
	const char *id;
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
	const char *id;
	const char *methodname;
	bool usage_only;
	bool check;
	struct plugin *plugin;
	/* Optional output field filter. */
	struct json_filter *filter;
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
	/* If it's deprecated from a particular release (or NULL) */
	const char *depr_start, *depr_end;
	/* If true, this option requires --developer to be enabled */
	bool dev_only;
};

/* Create an array of these, one for each --option you support. */
struct plugin_option {
	const char *name;
	const char *type;
	const char *description;
	char *(*handle)(struct plugin *plugin, const char *str, void *arg);
	void *arg;
	/* If true, this option requires --developer to be enabled */
	bool dev_only;
	/* If it's deprecated from a particular release (or NULL) */
	const char *depr_start, *depr_end;
	/* If true, allow setting after plugin has initialized */
	bool dynamic;
};

/* Create an array of these, one for each notification you subscribe to. */
struct plugin_notification {
	/* "*" means wildcard: notify me on everything (should be last!) */
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
				       const char *id_prefix,
				       struct command_result *(*cb)(struct command *command,
								    const char *buf,
								    const jsmntok_t *result,
								    void *arg),
				       struct command_result *(*errcb)(struct command *command,
								       const char *buf,
								       const jsmntok_t *result,
								       void *arg),
				       void *arg);

/* This variant has callbacks received whole obj, not "result" or
 * "error" members. */
#define jsonrpc_request_start(plugin, cmd, method, cb, errcb, arg)	\
	jsonrpc_request_start_((plugin), (cmd), (method),		\
		     json_id_prefix(tmpctx, (cmd)),			\
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


/* This variant has callbacks received whole obj, not "result" or
 * "error" members.  It also doesn't start params{}. */
#define jsonrpc_request_whole_object_start(plugin, cmd, method, id_prefix, cb, arg) \
	jsonrpc_request_start_((plugin), (cmd), (method), (id_prefix),	\
			       typesafe_cb_preargs(struct command_result *, void *, \
						   (cb), (arg),		\
						   struct command *command, \
						   const char *buf,	\
						   const jsmntok_t *result), \
			       NULL,					\
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

/* Helper to jsonrpc_request_start() and send_outreq() to update datastore.
 * NULL cb means ignore, NULL errcb means plugin_error.
 */
struct command_result *jsonrpc_set_datastore_(struct plugin *plugin,
					      struct command *cmd,
					      const char *path,
					      const void *value,
					      bool value_is_string,
					      const char *mode,
					      struct command_result *(*cb)(struct command *command,
									   const char *buf,
									   const jsmntok_t *result,
									   void *arg),
					      struct command_result *(*errcb)(struct command *command,
									      const char *buf,
									      const jsmntok_t *result,
									      void *arg),
					      void *arg);

#define jsonrpc_set_datastore_string(plugin, cmd, path, str, mode, cb, errcb, arg) \
	jsonrpc_set_datastore_((plugin), (cmd), (path), (str), true, (mode), \
			       typesafe_cb_preargs(struct command_result *, void *, \
						   (cb), (arg),		\
						   struct command *command, \
						   const char *buf,	\
						   const jsmntok_t *result), \
			       typesafe_cb_preargs(struct command_result *, void *, \
						   (errcb), (arg),	\
						   struct command *command, \
						   const char *buf,	\
						   const jsmntok_t *result), \
			       (arg))

#define jsonrpc_set_datastore_binary(plugin, cmd, path, tal_ptr, mode, cb, errcb, arg) \
	jsonrpc_set_datastore_((plugin), (cmd), (path), (tal_ptr), false, (mode), \
			       typesafe_cb_preargs(struct command_result *, void *, \
						   (cb), (arg),		\
						   struct command *command, \
						   const char *buf,	\
						   const jsmntok_t *result), \
			       typesafe_cb_preargs(struct command_result *, void *, \
						   (errcb), (arg),	\
						   struct command *command, \
						   const char *buf,	\
						   const jsmntok_t *result), \
			       (arg))

/* Helper to jsonrpc_request_start() and send_outreq() to read datastore.
 * If the value not found, cb gets NULL @val.
 */
struct command_result *jsonrpc_get_datastore_(struct plugin *plugin,
					      struct command *cmd,
					      const char *path,
					      struct command_result *(*string_cb)(struct command *command,
									   const char *val,
									   void *arg),
					      struct command_result *(*binary_cb)(struct command *command,
									   const u8 *val,
									   void *arg),
					      void *arg);

#define jsonrpc_get_datastore_string(plugin, cmd, path, cb, arg)	\
	jsonrpc_get_datastore_((plugin), (cmd), (path),			\
			       typesafe_cb_preargs(struct command_result *, \
						   void *,		\
						   (cb), (arg),		\
						   struct command *command, \
						   const char *val),	\
			       NULL,				     \
			       (arg))

#define jsonrpc_get_datastore_binary(plugin, cmd, path, cb, arg)	\
	jsonrpc_get_datastore_((plugin), (cmd), (path),			\
			       NULL,					\
			       typesafe_cb_preargs(struct command_result *, \
						   void *,		\
						   (cb), (arg),		\
						   struct command *command, \
						   const u8 *val),	\
			       (arg))


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

/* Helper for sql command, which is a front-end to other commands. */
bool command_deprecated_in_named_ok(struct command *cmd,
				    const char *cmdname,
				    const char *param,
				    const char *depr_start,
				    const char *depr_end);

/* For commando, which doesn't have a "cmd" incoming */
bool command_deprecated_in_nocmd_ok(struct plugin *plugin,
				    const char *name,
				    const char *depr_start,
				    const char *depr_end);

/* Call this on fatal error. */
void NORETURN plugin_err(struct plugin *p, const char *fmt, ...);

/* Call this on fatal error. */
void NORETURN plugin_errv(struct plugin *p, const char *fmt, va_list ap);

/* Normal exit (makes sure to flush output!). */
void NORETURN plugin_exit(struct plugin *p, int exitcode);

/* This command is finished, here's a detailed error; @cmd cannot be
 * NULL, data can be NULL; otherwise it must be a JSON object. */
struct command_result *WARN_UNUSED_RESULT
command_done_err(struct command *cmd,
		 enum jsonrpc_errcode code,
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

/**
 * What's the deprecation_ok state for this cmd?
 * @cmd: the command.
 *
 * Either the default, or the explicit connection override.
 */
bool command_deprecated_ok_flag(const struct command *cmd);

/* Helper for notification handler that will be finished in a callback.  */
#define notification_handler_pending(cmd) command_still_pending(cmd)

/* Synchronous helper to send command and extract fields from
 * response; can only be used in init callback. */
void rpc_scan(struct plugin *plugin,
	      const char *method,
	      const struct json_out *params TAKES,
	      const char *guide,
	      ...);

/* Helper to scan datastore: can only be used in init callback.  Returns error
 * msg (usually meaning field does not exist), or NULL on success. path is
 * /-separated.  Final arg is JSON_SCAN or JSON_SCAN_TAL.
 */
const char *rpc_scan_datastore_str(const tal_t *ctx,
				   struct plugin *plugin,
				   const char *path,
				   ...);
/* This variant scans the hex encoding, not the string */
const char *rpc_scan_datastore_hex(const tal_t *ctx,
				   struct plugin *plugin,
				   const char *path,
				   ...);

/* This sets batching of database commitments */
void rpc_enable_batching(struct plugin *plugin);

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
void plugin_logv(struct plugin *p, enum log_level l, const char *fmt, va_list ap);

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

/* Simply exists to check that `set` to plugin_option* is correct type */
static inline void *plugin_option_cb_check(char *(*set)(struct plugin *plugin,
							const char *arg, void *))
{
	return set;
}

/* Is --developer enabled? */
bool plugin_developer_mode(const struct plugin *plugin);

/* Macro to define arguments */
#define plugin_option_(name, type, description, set, arg, dev_only, depr_start, depr_end, dynamic) \
	(name),								\
	(type),								\
	(description),							\
	plugin_option_cb_check(typesafe_cb_preargs(char *, void *,	\
						   (set), (arg),	\
						   struct plugin *,	\
						   const char *)),	\
	(arg),								\
	(dev_only),							\
	(depr_start),							\
	(depr_end),							\
	(dynamic)

#define plugin_option(name, type, description, set, arg) \
	plugin_option_((name), (type), (description), (set), (arg), false, NULL, NULL, false)

#define plugin_option_dev(name, type, description, set, arg) \
	plugin_option_((name), (type), (description), (set), (arg), true, NULL, NULL, false)

#define plugin_option_dynamic(name, type, description, set, arg) \
	plugin_option_((name), (type), (description), (set), (arg), false, NULL, NULL, true)

#define plugin_option_deprecated(name, type, description, depr_start, depr_end, set, arg) \
	plugin_option_((name), (type), (description), (set), (arg), false, (depr_start), (depr_end), false)

/* Standard helpers */
char *u64_option(struct plugin *plugin, const char *arg, u64 *i);
char *u32_option(struct plugin *plugin, const char *arg, u32 *i);
char *u16_option(struct plugin *plugin, const char *arg, u16 *i);
char *bool_option(struct plugin *plugin, const char *arg, bool *i);
char *charp_option(struct plugin *plugin, const char *arg, char **p);
char *flag_option(struct plugin *plugin, const char *arg, bool *i);

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
	struct node_id id;
	bool connected;
	bool private;
	struct bitcoin_txid funding_txid;
	const char *state;
	/* scid or alias[LOCAL] is always non-NULL */
	struct short_channel_id *alias[NUM_SIDES];
	struct short_channel_id *scid;
	int direction;
	struct amount_msat total_msat;
	struct amount_msat spendable_msat;
	u16 max_accepted_htlcs;
	size_t num_htlcs;
	/* TODO Add fields as we need them. */
};

/* Returns an array of listpeers_channel from listpeerchannels * */
struct listpeers_channel **json_to_listpeers_channels(const tal_t *ctx,
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

/* Create a prefix (ending in /) for this cmd_id, if any. */
const char *json_id_prefix(const tal_t *ctx, const struct command *cmd);

void plugin_set_memleak_handler(struct plugin *plugin,
				void (*mark_mem)(struct plugin *plugin,
						 struct htable *memtable));

/* Synchronously call a JSON-RPC method and return its contents and
 * the parser token. */
const jsmntok_t *jsonrpc_request_sync(const tal_t *ctx, struct plugin *plugin,
				      const char *method,
				      const struct json_out *params TAKES,
				      const char **resp);

#endif /* LIGHTNING_PLUGINS_LIBPLUGIN_H */
