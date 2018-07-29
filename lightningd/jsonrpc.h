#ifndef LIGHTNING_LIGHTNINGD_JSONRPC_H
#define LIGHTNING_LIGHTNINGD_JSONRPC_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/autodata/autodata.h>
#include <ccan/list/list.h>
#include <common/json.h>

struct bitcoin_txid;
struct wireaddr;
struct wallet_tx;

/* Context for a command (from JSON, but might outlive the connection!)
 * You can allocate off this for temporary objects. */
struct command {
	/* Off jcon->commands */
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
};

struct json_connection {
	/* The global state */
	struct lightningd *ld;

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

	/* Current commands. */
	struct list_head commands;

	struct list_head output;
	const char *outbuf;
};

struct json_command {
	const char *name;
	void (*dispatch)(struct command *,
			 const char *buffer, const jsmntok_t *params);
	const char *description;
	bool deprecated;
	const char *verbose;
};

struct json_result *null_response(const tal_t *ctx);
void command_success(struct command *cmd, struct json_result *response);
void PRINTF_FMT(3, 4) command_fail(struct command *cmd, int code,
				   const char *fmt, ...);
void PRINTF_FMT(4, 5) command_fail_detailed(struct command *cmd,
					     int code,
					     const struct json_result *data,
					     const char *fmt, ...);

/* Mainly for documentation, that we plan to close this later. */
void command_still_pending(struct command *cmd);


/* For initialization */
void setup_jsonrpc(struct lightningd *ld, const char *rpc_filename);

enum address_parse_result {
	/* Not recognized as an onchain address */
	ADDRESS_PARSE_UNRECOGNIZED,
	/* Recognized as an onchain address, but targets wrong network */
	ADDRESS_PARSE_WRONG_NETWORK,
	/* Recognized and succeeds */
	ADDRESS_PARSE_SUCCESS,
};
/* Return result of address parsing and fills in *scriptpubkey
 * allocated off ctx if ADDRESS_PARSE_SUCCESS
 */
enum address_parse_result
json_tok_address_scriptpubkey(const tal_t *ctx,
			      const struct chainparams *chainparams,
			      const char *buffer,
			      const jsmntok_t *tok, const u8 **scriptpubkey);

bool json_tok_newaddr(const char *buffer, const jsmntok_t *tok, bool *is_p2wpkh);

/* Parse the satoshi token in wallet_tx. */
bool json_tok_wtx(struct wallet_tx * tx, const char * buffer,
		  const jsmntok_t * sattok, u64 max);

AUTODATA_TYPE(json_command, struct json_command);
#endif /* LIGHTNING_LIGHTNINGD_JSONRPC_H */
