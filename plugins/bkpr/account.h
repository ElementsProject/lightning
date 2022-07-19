#ifndef LIGHTNING_PLUGINS_BKPR_ACCOUNT_H
#define LIGHTNING_PLUGINS_BKPR_ACCOUNT_H

#include "config.h"
#include <ccan/short_types/short_types.h>

struct node_id;

struct account {

	/* Id of this account in the database */
	u64 db_id;

	/* Name of account, typically channel id */
	const char *name;

	/* Peer we have this account with (NULL if not a channel) */
	struct node_id *peer_id;

	/* Is this our internal wallet account? */
	bool is_wallet;

	/* Is this an account we initiated open for? */
	bool we_opened;

	/* Was any portion of this account's funds leased? */
	bool leased;

	/* Block account was totally resolved at */
	u64 onchain_resolved_block;

	/* db_id of chain event that opened this account */
	u64 *open_event_db_id;

	/* db_id of chain event that closed this account */
	u64 *closed_event_db_id;

	/* Number of outputs to expect on close */
	u32 closed_count;
};

/* Get a new account */
struct account *new_account(const tal_t *ctx,
			    const char *name STEALS,
			    struct node_id *peer_id);

/* Is this a channel account? */
bool is_channel_account(const struct account *acct);
/* is this the 'external' account */
bool is_external_account(const struct account *acct);
#endif /* LIGHTNING_PLUGINS_BKPR_ACCOUNT_H */
