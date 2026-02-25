#ifndef LIGHTNING_PLUGINS_BWATCH_BWATCH_INTERFACE_H
#define LIGHTNING_PLUGINS_BWATCH_BWATCH_INTERFACE_H

#include "config.h"
#include "bwatch.h"

/* Send watch_found notification to lightningd */
void bwatch_send_watch_found(struct command *cmd,
			     const struct bitcoin_tx *tx,
			     u32 blockheight,
			     const struct watch *w,
			     u32 txindex,
			     u32 outnum,
			     u32 innum);

/* Send block_processed notification to watchman */
void bwatch_send_block_processed(struct command *cmd, u32 blockheight);

/* Sync with watchman height on startup */
struct command_result *bwatch_sync_with_watchman(struct command *cmd, void *unused);

/* RPC command handlers (called by plugin_main) */
struct command_result *json_bwatch_add(struct command *cmd,
				       const char *buffer,
				       const jsmntok_t *params);

struct command_result *json_bwatch_del(struct command *cmd,
				       const char *buffer,
				       const jsmntok_t *params);

struct command_result *json_bwatch_list(struct command *cmd,
					const char *buffer,
					const jsmntok_t *params);

struct command_result *json_bwatch_addutxo(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *params);

struct command_result *json_bwatch_get_transaction(struct command *cmd,
						   const char *buffer,
						   const jsmntok_t *params);

#endif /* LIGHTNING_PLUGINS_BWATCH_BWATCH_INTERFACE_H */
