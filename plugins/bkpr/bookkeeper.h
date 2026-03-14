#ifndef LIGHTNING_PLUGINS_BKPR_BOOKKEEPER_H
#define LIGHTNING_PLUGINS_BKPR_BOOKKEEPER_H

#include "config.h"
#include <ccan/intmap/intmap.h>
#include <common/json_parse.h>

struct command;

/* For allocation convenience. */
typedef UINTMAP(double *) currencymap_t;

struct bkpr {
	/* The datastore-backed lookup tables for our annotations */
	struct accounts *accounts;
	struct onchain_fees *onchain_fees;
	struct descriptions *descriptions;
	struct rebalances *rebalances;
	struct blockheights *blockheights;

	/* Where we're up to in listchainmoves, listchannelmoves */
	u64 chainmoves_index, channelmoves_index;

	/* Optional currency if we're doing currencyconvert lookups */
	char *currency;
	/* Map of UNIX time -> currency rate */
	currencymap_t *currency_rates;
	/* True if we've warned about currency failures */
	bool warned_currency_fail;
};

/* Add optional currencyrate for this timestamp */
void json_add_currencyrate(struct json_stream *result,
			   const char *fieldname,
			   const struct bkpr *bkpr,
			   u64 timestamp);

/* Helper to ignore returns from datastore */
struct command_result *ignore_datastore_reply(struct command *cmd,
					      const char *method,
					      const char *buf,
					      const jsmntok_t *result,
					      void *arg);

#endif /* LIGHTNING_PLUGINS_BKPR_BOOKKEEPER_H */
