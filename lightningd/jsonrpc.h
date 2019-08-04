#ifndef LIGHTNING_LIGHTNINGD_JSONRPC_H
#define LIGHTNING_LIGHTNINGD_JSONRPC_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/autodata/autodata.h>
#include <ccan/list/list.h>
#include <common/json.h>
#include <lightningd/json_stream.h>
#include <stdarg.h>

struct jsonrpc;

/* The command mode tells param() how to process. */
enum command_mode {
	/* Normal command processing */
	CMD_NORMAL,
	/* Create command usage string, nothing else. */
	CMD_USAGE,
	/* Check parameters, nothing else. */
	CMD_CHECK
};

/* Context for a command (from JSON, but might outlive the connection!). */
/* FIXME: move definition into jsonrpc.c */
struct command {
	/* Off json_cmd->commands */
	struct list_node list;
	/* The global state */
	struct lightningd *ld;
	/* The 'id' which we need to include in the response. */
	const char *id;
	/* What command we're running (for logging) */
	const struct json_command *json_cmd;
	/* The connection, or NULL if it closed. */
	struct json_connection *jcon;
	/* Have we been marked by command_still_pending?  For debugging... */
	bool pending;
	/* Tell param() how to process the command */
	enum command_mode mode;
	/* Have we started a json stream already?  For debugging. */
	struct json_stream *json_stream;

	/* Only one filed between `jcon` and `in_jcon` is not NULL; */
	struct internal_json_connection *in_jcon;
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
	bool deprecated;
	const char *verbose;
	/* This flag indicates if the json_command will be exposed
	 * to user in `help` and be called by `lightningd` to expand
	 * rpcmethods of plugins.
	 */
	bool internal;
};

/* `lightningd` will register their interested topic. */
struct json_internal_command {
	const char *name;
	/* Not null if any plugin supply the corresponding rpcmethod.
	 * But only one plugin can register here at the same time. */
	struct json_command *cmd;
	void (*serialize_payload)(void *src, struct json_stream *dest);
};

struct jsonrpc_notification {
	/* The topic that this notification is for. Internally this
	 * will be serialized as "method", hence the different name
	 * here */
	const char *method;
	struct json_stream *stream;
};

struct jsonrpc_request {
	u64 id;
	const char *method;
	struct json_stream *stream;
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
				     int code,
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
					    int code,
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

/* To return if param() fails. */
extern struct command_result *command_param_failed(void)
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

/* FIXME: For the few cases where return value is indeterminate */
struct command_result *command_its_complicated(const char *why);

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
 * Start listeing on ld->rpc_filename.
 *
 * Sets up the listener effectively starting the RPC interface.
 */
void jsonrpc_listen(struct jsonrpc *rpc, struct lightningd *ld);

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

#define jsonrpc_request_start(ctx, method, log, response_cb, response_cb_arg) \
	jsonrpc_request_start_(					\
		(ctx), (method), (log),					\
	    typesafe_cb_preargs(void, void *, (response_cb), (response_cb_arg),	\
				const char *buffer,		\
				const jsmntok_t *toks,		\
				const jsmntok_t *idtok),	\
	    (response_cb_arg))

struct jsonrpc_request *jsonrpc_request_start_(
    const tal_t *ctx, const char *method, struct log *log,
    void (*response_cb)(const char *buffer, const jsmntok_t *toks,
			const jsmntok_t *idtok, void *),
    void *response_cb_arg);

void jsonrpc_request_end(struct jsonrpc_request *request);

AUTODATA_TYPE(json_command, struct json_command);

AUTODATA_TYPE(json_internal_command, struct json_internal_command);

#if DEVELOPER
struct htable;
struct jsonrpc;

void jsonrpc_remove_memleak(struct htable *memtable,
			    const struct jsonrpc *jsonrpc);
#endif /* DEVELOPER */

bool json_command_internal_call_(struct lightningd *ld, const char *name,
				void *payload,
				void (*response_cb)(void *arg, bool retry, char *output,
						    size_t output_bytes),
				void *response_cb_arg,
				char **err);

/* Wrapper for calling internal rpcmethod.
 *
 * Return false when no plugin supplies corresponding rpcmethod
 * or when this call meets any error, this means we can't use this
 * rpcmethod anyway. In this case, we shouldn't retry.
 * If we meet error, the `err` will be filled with error message,
 * Otherwise, it will be NULL.
 *
 * Return true when it dispatch rpcmethod to the plugin successfully,
 * or when we can't use this rpcmethod temporarily.
 * For the latter, we will call `response_cb` immediately with NULL
 * data buffer and set `retry` field as true.
 */
#define json_command_internal_call(ld, name, payload, response_cb, response_cb_arg, err)            \
	json_command_internal_call_(ld, name, payload,                                              \
				    typesafe_cb_cast(void (*)(void *, bool,                         \
							      char*, size_t),                       \
						     void (*)(typeof(response_cb_arg), bool,        \
							      char *, size_t),                      \
						     (response_cb)),                                \
				    response_cb_arg,                                                \
				    err)

#define REGISTER_JSON_INTERNAL_COMMAND(name, serialize_payload, payload_type)                       \
	struct json_internal_command name##_internal_command_gen = {                                \
	    stringify(name),                                                                        \
	    NULL, /* .cmd */                                                                        \
	    typesafe_cb_cast(void (*)(void *, struct json_stream *),                                \
			     void (*)(payload_type, struct json_stream *),                          \
			     serialize_payload),                                                    \
	};                                                                                          \
	AUTODATA(json_internal_command, &name##_internal_command_gen);

bool internal_command_register(struct json_command *cmd);

struct internal_rpcmethod_calls;

/* Create a new internal rpcmethod call manager. */
struct internal_rpcmethod_calls *new_internal_rpcmethod_calls(const tal_t *ctx, struct lightningd *ld);

/* Use this interface when all plugins have replied `getmanifest`. */
void internal_rpcmethod_registered(struct internal_rpcmethod_calls *call);

/* Use the interface when we have sent all plugins `init`. */
void initial_internal_repcmethod_calls(struct internal_rpcmethod_calls *call);

/* Used to resolve the response of plugins fo internal rpcmethod call. */
void internal_command_complete(struct command *cmd, const char *buffer,
			       const jsmntok_t *toks);

#endif /* LIGHTNING_LIGHTNINGD_JSONRPC_H */
