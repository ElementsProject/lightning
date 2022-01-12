#ifndef LIGHTNING_PLUGINS_BKPR_CHANNEL_EVENT_H
#define LIGHTNING_PLUGINS_BKPR_CHANNEL_EVENT_H

#include "config.h"
#include <ccan/short_types/short_types.h>

struct amount_msat;
struct sha256;

struct channel_event {

	/* Id of this chain event in the database */
	u64 db_id;

	/* db_id of account this event belongs to */
	u64 acct_db_id;

	/* Tag describing the event */
	const char *tag;

	/* Amount we received in this event */
	struct amount_msat credit;

	/* Amount we paid in this event */
	struct amount_msat debit;

	/* Total 'fees' related to this channel event */
	struct amount_msat fees;

	/* What token are the credit/debits? */
	const char *currency;

	/* Payment identifier (typically the preimage hash) */
	struct sha256 *payment_id;

	/* Some payments share a payment_id, and are differentiable via id */
	u32 part_id;

	/* What time did the event happen */
	u64 timestamp;
};

#endif /* LIGHTNING_PLUGINS_BKPR_CHANNEL_EVENT_H */
