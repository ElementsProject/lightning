#ifndef LIGHTNING_LIGHTNINGD_JSONRPC_H
#define LIGHTNING_LIGHTNINGD_JSONRPC_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/autodata/autodata.h>
#include <ccan/list/list.h>
#include <common/json.h>
#include <lightningd/json_stream.h>
#include <stdarg.h>

/* The command mode tells param() how to process. */
enum command_mode {
	/* Normal command processing */
	CMD_NORMAL,
	/* Create command usage string, nothing else. */
	CMD_USAGE
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
	/* This is created if mode is CMD_USAGE */
	const char *usage;
	bool *ok;
	/* Have we started a json stream already?  For debugging. */
	bool have_json_stream;
};

struct json_command {
	const char *name;
	void (*dispatch)(struct command *,
			 const char *buffer, const jsmntok_t *params);
	const char *description;
	bool deprecated;
	const char *verbose;
};

/**
 * json_stream_success - start streaming a successful json result.
 * @cmd: the command we're running.
 *
 * The returned value should go to command_success() when done.
 * json_add_* will be placed into the 'result' field of the JSON reply.
 */
struct json_stream *json_stream_success(struct command *cmd);

/**
 * json_stream_fail - start streaming a failed json result.
 * @cmd: the command we're running.
 * @code: the error code from lightningd/jsonrpc_errors.h
 * @errmsg: the error string.
 *
 * The returned value should go to command_failed() when done;
 * json_add_* will be placed into the 'data' field of the 'error' JSON reply.
 */
struct json_stream *json_stream_fail(struct command *cmd,
				     int code,
				     const char *errmsg);

/**
 * json_stream_fail_nodata - start streaming a failed json result.
 * @cmd: the command we're running.
 * @code: the error code from lightningd/jsonrpc_errors.h
 * @errmsg: the error string.
 *
 * This is used by command_fail(), which doesn't add any JSON data.
 */
struct json_stream *json_stream_fail_nodata(struct command *cmd,
					    int code,
					    const char *errmsg);

struct json_stream *null_response(struct command *cmd);
void command_success(struct command *cmd, struct json_stream *response);
void command_failed(struct command *cmd, struct json_stream *result);
void PRINTF_FMT(3, 4) command_fail(struct command *cmd, int code,
				   const char *fmt, ...);

/* Mainly for documentation, that we plan to close this later. */
void command_still_pending(struct command *cmd);

/**
 * Create a new jsonrpc to wrap all related information.
 *
 * This doesn't setup the listener yet, see `jsonrpc_listen` for
 * that. This just creates the container for all jsonrpc-related
 * information so we can start gathering it before actually starting.
 */
struct jsonrpc *jsonrpc_new(const tal_t *ctx, struct lightningd *ld);


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
 */
bool jsonrpc_command_add(struct jsonrpc *rpc, struct json_command *command);

/**
 * Remove a command/method from the JSON-RPC.
 *
 * Used to dynamically remove a `struct json_command` from the
 * JSON-RPC dispatch table by its name.
 */
void jsonrpc_command_remove(struct jsonrpc *rpc, const char *method);

AUTODATA_TYPE(json_command, struct json_command);
#endif /* LIGHTNING_LIGHTNINGD_JSONRPC_H */
