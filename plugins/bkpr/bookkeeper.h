#ifndef LIGHTNING_PLUGINS_BKPR_BOOKKEEPER_H
#define LIGHTNING_PLUGINS_BKPR_BOOKKEEPER_H

#include "config.h"
#include <ccan/intmap/intmap.h>
#include <common/json_parse.h>

struct command;
struct plugin;
struct iso4217_name_and_divisor;

struct currencyrate {
	u32 duration;
	u64 raw_rate;
};

/* For allocation convenience. */
typedef UINTMAP(struct currencyrate *) currencymap_t;

struct bkpr {
	/* The datastore-backed lookup tables for our annotations */
	struct accounts *accounts;
	struct onchain_fees *onchain_fees;
	struct descriptions *descriptions;
	struct rebalances *rebalances;
	struct blockheights *blockheights;

	/* Any outstanding refresh. */
	struct refresh_info *rinfo;

	/* Where we're up to in listchainmoves, listchannelmoves */
	u64 chainmoves_index, channelmoves_index;

	/* Optional currency if we're doing currencyconvert lookups */
	const struct iso4217_name_and_divisor *currency;
	/* Map of UNIX time -> currency rate */
	currencymap_t *currency_rates;
	/* True if we've warned about currency failures */
	bool warned_currency_fail;
	/* aux_command and parent of currency queries */
	struct command *currency_cmds;
};

/* Get bkpr struct for the plugin */
struct bkpr *bkpr_of(struct plugin *plugin);

/* Get currency rate for this timestamp, as string, or NULL.
 * If msat is non-NULL, amount for that number of msat (otherwise 1 btc)*/
const char *currencyrate_str(const tal_t *ctx,
			     const struct bkpr *bkpr,
			     u64 timestamp,
			     const struct amount_msat *msat);

/* Get the struct currencyrate covering this timestamp, if any. */
const struct currencyrate *covering_currencyrate(const struct bkpr *bkpr,
						 u64 timestamp);

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
