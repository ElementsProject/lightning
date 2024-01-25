#ifndef LIGHTNING_LIGHTNINGD_JSONRPC_H
#define LIGHTNING_LIGHTNINGD_JSONRPC_H
#include "config.h"
#include <ccan/list/list.h>
#include <common/autodata.h>
#include <common/json_stream.h>
#include <common/status_levels.h>

struct jsonrpc;

/* The command mode tells param() how to process. */
enum command_mode {
	/* Normal command processing */
	CMD_NORMAL,
	/* Create command usage string, nothing else. */
	CMD_USAGE,
	/* Check parameters, nothing else. */
	CMD_CHECK,
	/* Check parameters, and one failed. */
	CMD_CHECK_FAILED,
};

/* Context for a command (from JSON, but might outlive the connection!). */
/* FIXME: move definition into jsonrpc.c */
struct command {
	/* Off list jcon->commands */
	struct list_node list;
	/* The global state */
	struct lightningd *ld;
	/* The 'id' which we need to include in the response. */
	const char *id;
	/* If 'id' needs to be quoted (i.e. it's a string) */
	bool id_is_string;
	/* What command we're running (for logging) */
	const struct json_command *json_cmd;
	/* The connection, or NULL if it closed. */
	struct json_connection *jcon;
	/* Does this want notifications? */
	bool send_notifications;
	/* Have we been marked by command_still_pending?  For debugging... */
	bool pending;
	/* Tell param() how to process the command */
	enum command_mode mode;
	/* Have we started a json stream already?  For debugging. */
	struct json_stream *json_stream;
	/* Optional output field filter. */
	struct json_filter *filter;
};

/**
 * Dummy structure to make sure you call one of
 * command_success / command_failed / command_still_pending.
 */
struct command_result;

struct json_command {
	const char *name;
	const char *category;
	struct command_result *(*dispatch)(struct command *,
					   const char *buffer,
					   const jsmntok_t *obj,
					   const jsmntok_t *params);
	const char *description;
	const char *verbose;
	bool dev_only;
	const char *depr_start, *depr_end;
};

struct jsonrpc_notification {
	/* The topic that this notification is for. Internally this
	 * will be serialized as "method", hence the different name
	 * here */
	const char *method;
	struct json_stream *stream;
};

struct jsonrpc_request {
	const char *id;
	bool id_is_string;
	const char *method;
	struct json_stream *stream;
	void (*notify_cb)(const char *buffer,
			  const jsmntok_t *idtok,
			  const jsmntok_t *methodtok,
			  const jsmntok_t *paramtoks,
			  void *);
	void (*response_cb)(const char *buffer, const jsmntok_t *toks,
			    const jsmntok_t *idtok, void *);
	void *response_cb_arg;
};

/**
 * json_stream_success - start streaming a successful json result object.
 * @cmd: the command we're running.
 *
 * The returned value should go to command_success() when done.
 * json_add_* will be placed into the 'result' field of the JSON reply.
 */
struct json_stream *json_stream_success(struct command *cmd);

/**
 * json_stream_fail - start streaming a failed json result, with data object.
 * @cmd: the command we're running.
 * @code: the error code from common/jsonrpc_errors.h
 * @errmsg: the error string.
 *
 * The returned value should go to command_failed() when done;
 * json_add_* will be placed into the 'data' field of the 'error' JSON reply.
 * You need to json_object_end() once you're done!
 */
struct json_stream *json_stream_fail(struct command *cmd,
				     enum jsonrpc_errcode code,
				     const char *errmsg);

/**
 * json_stream_fail_nodata - start streaming a failed json result.
 * @cmd: the command we're running.
 * @code: the error code from common/jsonrpc_errors.h
 * @errmsg: the error string.
 *
 * This is used by command_fail(), which doesn't add any JSON data.
 */
struct json_stream *json_stream_fail_nodata(struct command *cmd,
					    enum jsonrpc_errcode code,
					    const char *errmsg);

/* These returned values are never NULL. */
struct command_result *command_success(struct command *cmd,
				       struct json_stream *response)
	 WARN_UNUSED_RESULT;

struct command_result *command_failed(struct command *cmd,
				      struct json_stream *result)
	 WARN_UNUSED_RESULT;

/* Mainly for documentation, that we plan to close this later. */
struct command_result *command_still_pending(struct command *cmd)
	 WARN_UNUSED_RESULT;

/* For low-level JSON stream access: */
struct json_stream *json_stream_raw_for_cmd(struct command *cmd);
void json_stream_log_suppress_for_cmd(struct json_stream *js,
					    const struct command *cmd);
struct command_result *command_raw_complete(struct command *cmd,
					    struct json_stream *result);

/* Logging point to use for this command (usually, the JSON connection). */
struct logger *command_log(struct command *cmd);

/* To return if param() fails. */
extern struct command_result *command_param_failed(void)
	 WARN_UNUSED_RESULT;

/* To return after param_check() succeeds but we're still
 * command_check_only(cmd). */
struct command_result *command_check_done(struct command *cmd)
	 WARN_UNUSED_RESULT;

/* Wrapper for pending commands (ignores return) */
static inline void was_pending(const struct command_result *res)
{
	assert(res);
}

/* Transition for ignoring command */
static inline void fixme_ignore(const struct command_result *res)
{
}

/* Notifier to the caller. */
void json_notify_fmt(struct command *cmd,
		     enum log_level level,
		     const char *fmt, ...)
	PRINTF_FMT(3, 4);

/* FIXME: For the few cases where return value is indeterminate */
struct command_result *command_its_complicated(const char *why);

/* command can override ld->deprecated_ok */
bool command_deprecated_ok_flag(const struct command *cmd);

/**
 * Create a new jsonrpc to wrap all related information.
 *
 * This doesn't setup the listener yet, see `jsonrpc_listen` for
 * that. This just creates the container for all jsonrpc-related
 * information so we can start gathering it before actually starting.
 *
 * It initializes ld->jsonrpc.
 */
void jsonrpc_setup(struct lightningd *ld);


/**
 * Start listening on ld->rpc_filename.
 *
 * Sets up the listener effectively starting the RPC interface.
 */
void jsonrpc_listen(struct jsonrpc *rpc, struct lightningd *ld);

/**
 * Stop listening on ld->rpc_filename.
 *
 * No new connections from here in.
 */
void jsonrpc_stop_listening(struct jsonrpc *jsonrpc);

/**
 * Kill any remaining JSON-RPC connections.
 */
void jsonrpc_stop_all(struct lightningd *ld);

/**
 * Add a new command/method to the JSON-RPC interface.
 *
 * Returns true if the command was added correctly, false if adding
 * this would clobber a command name.
 *
 * Free @command to remove it.
 */
bool jsonrpc_command_add(struct jsonrpc *rpc, struct json_command *command,
			 const char *usage TAKES);

/**
 * Begin a JSON-RPC notification with the specified topic.
 *
 * Automatically starts the `params` object, hence only key-value
 * based params are supported at the moment.
 */
struct jsonrpc_notification *jsonrpc_notification_start(const tal_t *ctx, const char *topic);

/**
 * Counterpart to jsonrpc_notification_start.
 */
void jsonrpc_notification_end(struct jsonrpc_notification *n);

/**
 * start a JSONRPC request; id_prefix is non-NULL if this was triggered by
 * another JSONRPC request.
 */
#define jsonrpc_request_start(ctx, method, id_prefix, id_as_string, log, notify_cb, response_cb, response_cb_arg) \
	jsonrpc_request_start_(					\
	    (ctx), (method), (id_prefix), (id_as_string), (log), true, \
	    typesafe_cb_preargs(void, void *, (notify_cb), (response_cb_arg),	\
				const char *buffer,		\
				const jsmntok_t *idtok,		\
				const jsmntok_t *methodtok,	\
				const jsmntok_t *paramtoks),	\
	    typesafe_cb_preargs(void, void *, (response_cb), (response_cb_arg),	\
				const char *buffer,		\
				const jsmntok_t *toks,		\
				const jsmntok_t *idtok),	\
	    (response_cb_arg))

#define jsonrpc_request_start_raw(ctx, method, id_prefix, id_as_string,log, notify_cb, response_cb, response_cb_arg) \
	jsonrpc_request_start_(						\
		(ctx), (method), (id_prefix), (id_as_string), (log), false, \
	    typesafe_cb_preargs(void, void *, (notify_cb), (response_cb_arg), \
				const char *buffer,			\
				const jsmntok_t *idtok,			\
				const jsmntok_t *methodtok,		\
				const jsmntok_t *paramtoks),		\
	    typesafe_cb_preargs(void, void *, (response_cb), (response_cb_arg),	\
				const char *buffer,			\
				const jsmntok_t *toks,			\
				const jsmntok_t *idtok),		\
	    (response_cb_arg))

struct jsonrpc_request *jsonrpc_request_start_(
    const tal_t *ctx, const char *method,
    const char *id_prefix TAKES,
    bool id_as_string,
    struct logger *log, bool add_header,
    void (*notify_cb)(const char *buffer,
		      const jsmntok_t *idtok,
		      const jsmntok_t *methodtok,
		      const jsmntok_t *paramtoks,
		      void *),
    void (*response_cb)(const char *buffer, const jsmntok_t *toks,
			const jsmntok_t *idtok, void *),
    void *response_cb_arg);

void jsonrpc_request_end(struct jsonrpc_request *request);

AUTODATA_TYPE(json_command, struct json_command);

#endif /* LIGHTNING_LIGHTNINGD_JSONRPC_H */
