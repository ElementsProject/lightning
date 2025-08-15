#ifndef LIGHTNING_PLUGINS_BKPR_BOOKKEEPER_H
#define LIGHTNING_PLUGINS_BKPR_BOOKKEEPER_H

#include "config.h"
#include <common/json_parse.h>

struct command;

struct bkpr {
	/* The datastore-backed lookup tables for our annotations */
	struct accounts *accounts;
	struct onchain_fees *onchain_fees;
	struct descriptions *descriptions;
	struct rebalances *rebalances;
	struct blockheights *blockheights;

	/* Where we're up to in listchainmoves, listchannelmoves */
	u64 chainmoves_index, channelmoves_index;

	char *db_dsn;
	char *datadir;
};

/* Helper to ignore returns from datastore */
struct command_result *ignore_datastore_reply(struct command *cmd,
					      const char *method,
					      const char *buf,
					      const jsmntok_t *result,
					      void *arg);

#endif /* LIGHTNING_PLUGINS_BKPR_BOOKKEEPER_H */
