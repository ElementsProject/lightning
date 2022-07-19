#ifndef LIGHTNING_PLUGINS_BKPR_INCOMESTMT_H
#define LIGHTNING_PLUGINS_BKPR_INCOMESTMT_H

#include "config.h"
#include <ccan/tal/tal.h>

struct income_event {
	char *acct_name;
	char *tag;
	struct amount_msat credit;
	struct amount_msat debit;
	char *currency;
	u64 timestamp;

	struct bitcoin_outpoint *outpoint;
	struct bitcoin_txid *txid;
	struct sha256 *payment_id;
};

/* List all the events that are income related (gain/loss) */
struct income_event **list_income_events_all(const tal_t *ctx, struct db *db);

/* List all the events that are income related (gain/loss),
 * by a start and end date */
struct income_event **list_income_events(const tal_t *ctx,
					 struct db *db,
					 u64 start_time,
					 u64 end_time);

/* Given an event and a json_stream, add a new event object to the stream */
void json_add_income_event(struct json_stream *str, struct income_event *ev);

#endif /* LIGHTNING_PLUGINS_BKPR_INCOMESTMT_H */
