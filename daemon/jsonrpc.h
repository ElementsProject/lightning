#ifndef LIGHTNING_DAEMON_JSONRPC_H
#define LIGHTNING_DAEMON_JSONRPC_H
#include "config.h"
#include "json.h"
#include <ccan/list/list.h>

struct json_connection {
	/* The global state */
	struct lightningd_state *state;

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

	struct list_head output;
	const char *outbuf;
};

struct json_command {
	const char *name;
	char *(*dispatch)(struct json_connection *jcon,
			  const jsmntok_t *params,
			  struct json_result *result);
	const char *description;
	const char *help;
};

/* Add notification about something. */
void json_notify(struct json_connection *jcon, const char *result);

/* For initialization */
void setup_jsonrpc(struct lightningd_state *state, const char *rpc_filename);

/* Commands (from other files) */
extern const struct json_command connect_command;

#endif /* LIGHTNING_DAEMON_JSONRPC_H */
