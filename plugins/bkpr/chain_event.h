#ifndef LIGHTNING_PLUGINS_BKPR_CHAIN_EVENT_H
#define LIGHTNING_PLUGINS_BKPR_CHAIN_EVENT_H

#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/short_types/short_types.h>

struct amount_msat;
struct bitcoin_outpoint;
struct bitcoin_txid;
struct json_stream;

struct chain_event {

	/* Id of this chain event in the database */
	u64 db_id;

	/* db_id of account this event belongs to */
	u64 acct_db_id;

	/* Name of the account this belongs to */
	char *acct_name;

	/* Name of account this originated from */
	char *origin_acct;

	/* Tag describing the event */
	const char *tag;

	/* Is the node's wallet ignoring this? */
	bool ignored;

	/* Is this chain output stealable? If so
	 * we'll need to watch it for longer */
	bool stealable;

	/* Is this chain event because of a splice
	 * confirmation? */
	bool splice_close;

	/* Is this a rebalance event? */
	bool rebalance;

	/* Amount we received in this event */
	struct amount_msat credit;

	/* Amount we paid in this event */
	struct amount_msat debit;

	/* Total 'amount' of output on this chain event */
	struct amount_msat output_value;

	/* What token are the credit/debits? */
	const char *currency;

	/* What time did the event happen */
	u64 timestamp;

	/* What block did the event happen */
	u32 blockheight;

	/* What txo did this event concern */
	struct bitcoin_outpoint outpoint;

	/* What tx was the outpoint spent in (if spent) */
	struct bitcoin_txid *spending_txid;

	/* Sometimes chain events resolve payments */
	struct sha256 *payment_id;

	/* Desc of event (maybe useful for printing notes) */
	const char *desc;
};

void json_add_chain_event(struct json_stream *out,
                          struct chain_event *ev);

#endif /* LIGHTNING_PLUGINS_BKPR_CHAIN_EVENT_H */
