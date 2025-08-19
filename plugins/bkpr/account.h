#ifndef LIGHTNING_PLUGINS_BKPR_ACCOUNT_H
#define LIGHTNING_PLUGINS_BKPR_ACCOUNT_H

#include "config.h"
#include <ccan/short_types/short_types.h>
#include <common/coin_mvt.h>

struct node_id;
struct chain_event;

struct account {
	/* Unique name of account, typically channel id */
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

struct bkpr;

/* Initialize the accounts subsystem */
struct accounts *init_accounts(const tal_t *ctx, struct db *db);

/* Get all accounts */
struct account **list_accounts(const tal_t *ctx, const struct bkpr *bkpr);

/* Given an account name, find that account record */
struct account *find_account(const struct bkpr *bkpr,
			     const char *name);

/* Create it if it's not found */
struct account *find_or_create_account(struct bkpr *bkpr,
				       const char *name);

/* Some events update account information */
void maybe_update_account(struct bkpr *bkpr,
			  struct account *acct,
			  struct chain_event *e,
			  const enum mvt_tag *tags,
			  u32 closed_count,
			  struct node_id *peer_id);

/* Update the account with the highest blockheight that has a
 * resolving tx in it.
 *
 * The point of this is to allow us to prune data, eventually */
void account_update_closeheight(struct bkpr *bkpr, struct account *acct, u64 close_height);

#endif /* LIGHTNING_PLUGINS_BKPR_ACCOUNT_H */
