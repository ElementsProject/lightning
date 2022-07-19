#ifndef LIGHTNING_PLUGINS_BKPR_INCOMESTMT_H
#define LIGHTNING_PLUGINS_BKPR_INCOMESTMT_H

#include "config.h"
#include <ccan/tal/tal.h>
#include <stdio.h>

struct income_event {
	char *acct_name;
	char *tag;
	char *desc;
	struct amount_msat credit;
	struct amount_msat debit;
	/* Some CSVs require us to put fees on the
	 * same line as another entry */
	struct amount_msat fees;
	char *currency;
	u64 timestamp;

	struct bitcoin_outpoint *outpoint;
	struct bitcoin_txid *txid;
	struct sha256 *payment_id;
};

/* Each csv format has a header and a 'row print' function */
struct csv_fmt {
	char *fmt_name;
	void (*emit_header)(FILE *);
	void (*emit_entry)(const tal_t *, FILE *, struct income_event *);
};

/* List all the events that are income related (gain/loss) */
struct income_event **list_income_events_all(const tal_t *ctx, struct db *db,
					     bool consolidate_fees);

/* List all the events that are income related (gain/loss),
 * by a start and end date */
struct income_event **list_income_events(const tal_t *ctx,
					 struct db *db,
					 u64 start_time,
					 u64 end_time,
					 bool consolidate_fees);

/* Given an event and a json_stream, add a new event object to the stream */
void json_add_income_event(struct json_stream *str, struct income_event *ev);

char *csv_print_income_events(const tal_t *ctx,
			      const struct csv_fmt *csvfmt,
			      const char *filename,
			      struct income_event **evs);

const struct csv_fmt *csv_match_token(const char *buffer, const jsmntok_t *tok);

/* Returns concatenated string of all available fmts */
const char *csv_list_fmts(const tal_t *ctx);

/* Generic income statement filename generator */
const char *csv_filename(const tal_t *ctx, const struct csv_fmt *fmt);

#endif /* LIGHTNING_PLUGINS_BKPR_INCOMESTMT_H */
