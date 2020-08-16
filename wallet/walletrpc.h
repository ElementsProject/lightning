#ifndef LIGHTNING_WALLET_WALLETRPC_H
#define LIGHTNING_WALLET_WALLETRPC_H
#include "config.h"
#include <common/json.h>

struct command;
struct json_stream;
struct utxo;
struct wally_psbt;

void json_add_utxos(struct json_stream *response,
		    struct wallet *wallet,
		    struct utxo **utxos);

/* We evaluate reserved timeouts lazily, so use this. */
bool is_reserved(const struct utxo *utxo, u32 current_height);

struct command_result *param_psbt(struct command *cmd,
				  const char *name,
				  const char *buffer,
				  const jsmntok_t *tok,
				  struct wally_psbt **psbt);
#endif /* LIGHTNING_WALLET_WALLETRPC_H */
