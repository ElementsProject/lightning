#ifndef LIGHTNING_DAEMON_JSONRPC_H
#define LIGHTNING_DAEMON_JSONRPC_H
#include "config.h"
#include "json.h"
#include <ccan/autodata/autodata.h>
#include <ccan/list/list.h>

/* Context for a command (from JSON, but might outlive the connection!)
 * You can allocate off this for temporary objects. */
struct command {
	/* The global state */
	struct lightningd_state *dstate;
	/* The 'id' which we need to include in the response. */
	const char *id;
	/* The connection, or NULL if it closed. */
	struct json_connection *jcon;
};

struct json_connection {
	/* The global state */
	struct lightningd_state *dstate;

	/* Logging for this json connection. */
	struct log *log;

	/* The buffer (required to interpret tokens). */
	char *buffer;

	/* Internal state: */
	/* How much is already filled. */
	size_t used;
	/* How much has just been filled. */
	size_t len_read;

	/* We've been told to stop. */
	bool stop;

	/* Current command. */
	struct command *current;

	struct list_head output;
	const char *outbuf;
};

struct json_command {
	const char *name;
	void (*dispatch)(struct command *,
			 const char *buffer, const jsmntok_t *params);
	const char *description;
	const char *help;
};

struct json_result *null_response(const tal_t *ctx);
void command_success(struct command *cmd, struct json_result *response);
void PRINTF_FMT(2, 3) command_fail(struct command *cmd, const char *fmt, ...);

/* For initialization */
void setup_jsonrpc(struct lightningd_state *dstate, const char *rpc_filename);

AUTODATA_TYPE(json_command, struct json_command);
#endif /* LIGHTNING_DAEMON_JSONRPC_H */
