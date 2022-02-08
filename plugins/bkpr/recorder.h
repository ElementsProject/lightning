#ifndef LIGHTNING_PLUGINS_BKPR_RECORDER_H
#define LIGHTNING_PLUGINS_BKPR_RECORDER_H

#include "config.h"
#include <ccan/tal/tal.h>

struct account;
struct bitcoin_txid;
struct chain_event;
struct channel_event;
struct db;
enum mvt_tag;
struct onchain_fee;

#define EXTERNAL_ACCT "external"
#define WALLET_ACCT WALLET

struct acct_balance {
	char *currency;
	struct amount_msat credit;
	struct amount_msat debit;
	struct amount_msat balance;
};

struct fee_sum {
	struct bitcoin_txid *txid;
	struct amount_msat fees_paid;
};

struct txo_pair {
	struct chain_event *txo;
	struct chain_event *spend;
};

struct txo_set {
	struct bitcoin_txid *txid;
	struct txo_pair **pairs;
};

/* Get all accounts */
struct account **list_accounts(const tal_t *ctx, struct db *db);

/* Get all onchain fee records for this account */
struct onchain_fee **account_onchain_fees(const tal_t *ctx,
					  struct db *db,
					  struct account *acct);

/* Get all channel events for this account */
struct channel_event **account_get_channel_events(const tal_t *ctx,
						  struct db *db,
						  struct account *acct);

/* Get all channel events, ordered by timestamp */
struct channel_event **list_channel_events(const tal_t *ctx, struct db *db);

/* Get all chain events for this account */
struct chain_event **account_get_chain_events(const tal_t *ctx,
					      struct db *db,
					      struct account *acct);

/* Get all chain events, ordered by timestamp */
struct chain_event **list_chain_events(const tal_t *ctx, struct db *db);

/* Calculate the balances for an account
 *
 * @calc_sum - compute the total balance. error if negative
 * */
char *account_get_balance(const tal_t *ctx,
			  struct db *db,
			  const char *acct_name,
			  bool calc_sum,
			  struct acct_balance ***balances);

/* Get chain fees for account */
struct onchain_fee **account_get_chain_fees(const tal_t *ctx, struct db *db,
					    struct account *acct);

/* Find a chain event by its database id */
struct chain_event *find_chain_event_by_id(const tal_t *ctx,
					   struct db *db,
					   u64 event_db_id);

/* Find the utxos for this account.
 *
 * Returns true if chain is complete:
 * (all outputs terminate either to wallet or external)
 */
bool find_txo_chain(const tal_t *ctx,
		    struct db *db,
		    struct account *acct,
		    struct txo_set ***sets);

/* List all chain fees, for all accounts */
struct onchain_fee **list_chain_fees(const tal_t *ctx, struct db *db);

/* Returns a list of sums of the fees we've recorded for every txid
 * for the given account */
struct fee_sum **find_account_onchain_fees(const tal_t *ctx,
					   struct db *db,
					   struct account *acct);

/* Add the given account to the database */
void account_add(struct db *db, struct account *acct);
/* Given an account name, find that account record */
struct account *find_account(const tal_t *ctx,
			     struct db *db,
			     const char *name);

/* Some events update account information */
void maybe_update_account(struct db *db,
			  struct account *acct,
			  struct chain_event *e,
			  const enum mvt_tag *tags);

/* Update our onchain fees now? */
char *maybe_update_onchain_fees(const tal_t *ctx,
			        struct db *db,
			        struct bitcoin_txid *txid);

/* Have all the outputs for this account's close tx
 * been resolved onchain? If so, update the account with the
 * highest blockheight that has a resolving tx in it.
 *
 * The point of this is to allow us to prune data, eventually */
void maybe_mark_account_onchain(struct db *db, struct account *acct);

/* Log a channel event */
void log_channel_event(struct db *db,
		       const struct account *acct,
		       struct channel_event *e);

/* Log a chain event.
 * Returns true if inserted, false if already exists */
bool log_chain_event(struct db *db,
		     const struct account *acct,
		     struct chain_event *e);

#endif /* LIGHTNING_PLUGINS_BKPR_RECORDER_H */
