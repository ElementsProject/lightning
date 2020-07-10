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
#include <common/param.h>
#include <common/status_levels.h>

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

/* Return the feature set of the current lightning node */
const struct feature_set *plugin_feature_set(const struct plugin *p);

/* Helper to create a JSONRPC2 request stream. Send it with `send_outreq`. */
struct out_req *
jsonrpc_request_start_(struct plugin *plugin, struct command *cmd,
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
struct command_result *WARN_UNUSED_RESULT
command_finished(struct command *cmd, struct json_stream *response);

/* Helper for a command that'll be finished in a callback. */
struct command_result *WARN_UNUSED_RESULT
command_still_pending(struct command *cmd);

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

/* Send an async rpc request to lightningd. */
struct command_result *
send_outreq(struct plugin *plugin, const struct out_req *req);

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

/* Macro to define arguments */
#define plugin_option(name, type, description, set, arg)			\
	(name),								\
	(type),								\
	(description),							\
	typesafe_cb_preargs(char *, void *, (set), (arg), const char *),	\
	(arg)

/* Standard helpers */
char *u64_option(const char *arg, u64 *i);
char *u32_option(const char *arg, u32 *i);
char *bool_option(const char *arg, bool *i);
char *charp_option(const char *arg, char **p);
char *flag_option(const char *arg, bool *i);

/* The main plugin runner: append with 0 or more plugin_option(), then NULL. */
void NORETURN LAST_ARG_NULL plugin_main(char *argv[],
					void (*init)(struct plugin *p,
						     const char *buf, const jsmntok_t *),
					const enum plugin_restartability restartability,
					struct feature_set *features,
					const struct plugin_command *commands,
					size_t num_commands,
					const struct plugin_notification *notif_subs,
					size_t num_notif_subs,
					const struct plugin_hook *hook_subs,
					size_t num_hook_subs,
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

enum route_hop_style {
	ROUTE_HOP_LEGACY = 1,
	ROUTE_HOP_TLV = 2,
};

struct route_hop {
	struct short_channel_id channel_id;
	int direction;
	struct node_id nodeid;
	struct amount_msat amount;
	u32 delay;
	struct pubkey *blinding;
	enum route_hop_style style;
};

struct route_hop *json_to_route(const tal_t *ctx, const char *buffer,
				const jsmntok_t *toks);

#endif /* LIGHTNING_PLUGINS_LIBPLUGIN_H */
