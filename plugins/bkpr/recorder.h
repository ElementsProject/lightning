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
#define SQLITE_MAX_UINT 0x7FFFFFFFFFFFFFFF

struct acct_balance {
	char *currency;
	struct amount_msat credit;
	struct amount_msat debit;
	struct amount_msat balance;
};

struct fee_sum {
	u64 acct_db_id;
	char *acct_name;
	char *currency;
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

struct rebalance {
	u64 in_ev_id;
	u64 out_ev_id;
	char *in_acct_name;
	char *out_acct_name;
	struct amount_msat rebal_msat;
	struct amount_msat fee_msat;
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

/* Get all channel events for a payment id, order by timestamp */
struct channel_event **get_channel_events_by_id(const tal_t *ctx,
						struct db *db,
						struct sha256 *id);

/* Get all channel events, ordered by timestamp */
struct channel_event **list_channel_events(const tal_t *ctx, struct db *db);

/* Get all channel events, order by timestamp.
 *
 * @ctx - context to allocate from
 * @db  - database to query
 * @start_time - UNIX timestamp to query after (exclusive)
 * @end_time   - UNIX timestamp to query until (inclusive)
 */
struct channel_event **list_channel_events_timebox(const tal_t *ctx,
						   struct db *db,
						   u64 start_time,
						   u64 end_time);

/* Get all chain events for this account */
struct chain_event **account_get_chain_events(const tal_t *ctx,
					      struct db *db,
					      struct account *acct);

/* Get all chain events for a transaction id, order by timestamp */
struct chain_event **find_chain_events_bytxid(const tal_t *ctx, struct db *db,
					      struct bitcoin_txid *txid);

/* Get all chain events, order by timestamp.  */
struct chain_event **list_chain_events(const tal_t *ctx, struct db *db);

/* Get all chain events, order by timestamp.
 *
 * @ctx - context to allocate from
 * @db  - database to query
 * @start_time - UNIX timestamp to query after (exclusive)
 * @end_time   - UNIX timestamp to query until (inclusive)
 */
struct chain_event **list_chain_events_timebox(const tal_t *ctx,
					       struct db *db,
					       u64 start_time,
					       u64 end_time);

/* Calculate the balances for an account
 *
 * @calc_sum     - compute the total balance. error if negative
 * @skip_ignored - don't include ignored payments in the balance sum
 * */
char *account_get_balance(const tal_t *ctx,
			  struct db *db,
			  const char *acct_name,
			  bool calc_sum,
			  bool skip_ignored,
			  struct acct_balance ***balances,
			  bool *account_exists);

/* Get chain fees for account */
struct onchain_fee **account_get_chain_fees(const tal_t *ctx, struct db *db,
					    struct account *acct);

/* Get all chain fees for a transaction id, order by timestamp */
struct onchain_fee **get_chain_fees_by_txid(const tal_t *ctx, struct db *db,
					    struct bitcoin_txid *txid);

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

/* Get all chain fees, order by timestamp.
 *
 * @ctx - context to allocate from
 * @db  - database to query
 * @start_time - UNIX timestamp to query after (exclusive)
 * @end_time   - UNIX timestamp to query until (inclusive)
 */
struct onchain_fee **list_chain_fees_timebox(const tal_t *ctx, struct db *db,
					     u64 start_time, u64 end_time);

/* Returns a list of sums of the fees we've recorded for every txid
 * for the given account */
struct fee_sum **find_account_onchain_fees(const tal_t *ctx,
					   struct db *db,
					   struct account *acct);

/* Final all the onchain fees */
struct fee_sum **calculate_onchain_fee_sums(const tal_t *ctx, struct db *db);

/* Find the last timestamp for the onchain fees for this txid + account */
u64 onchain_fee_last_timestamp(struct db *db,
			       u64 acct_db_id,
			       struct bitcoin_txid *txid);
/* Add the given account to the database */
void account_add(struct db *db, struct account *acct);
/* Given an account name, find that account record */
struct account *find_account(const tal_t *ctx,
			     struct db *db,
			     const char *name);

/* Find the account that was closed by this txid.
 * Returns NULL if none  */
struct account *find_close_account(const tal_t *ctx,
				   struct db *db,
				   struct bitcoin_txid *txid);

/* Some events update account information */
void maybe_update_account(struct db *db,
			  struct account *acct,
			  struct chain_event *e,
			  const enum mvt_tag *tags,
			  u32 closed_count,
			  struct node_id *peer_id);

/* Update our onchain fees now? */
char *maybe_update_onchain_fees(const tal_t *ctx,
			        struct db *db,
			        struct bitcoin_txid *txid);

/* We calculate onchain fees for channel closes a bit different */
char *update_channel_onchain_fees(const tal_t *ctx,
				  struct db *db,
				  struct account *acct);

/* Have all the outputs for this account's close tx
 * been resolved onchain? If so, update the account with the
 * highest blockheight that has a resolving tx in it.
 *
 * The point of this is to allow us to prune data, eventually */
void maybe_mark_account_onchain(struct db *db, struct account *acct);

/* We fetch invoice desc data after the fact and then update it
 * Updates both the chain_event and channel_event tables for all
 * matching payment_hashes
 * */
void add_payment_hash_desc(struct db *db,
			   struct sha256 *payment_hash,
			   const char *desc);

/* When we make external deposits from the wallet, we don't
 * count them until any output that was spent *into* them is
 * confirmed onchain.
 *
 * This method updates the blockheight on these events to the
 * height an input was spent into */
void maybe_closeout_external_deposits(struct db *db,
				      const struct bitcoin_txid *txid,
				      u32 blockheight);

/* Keep track of rebalancing payments (payments paid to/from ourselves.
 * Returns true if was rebalance */
void maybe_record_rebalance(struct db *db,
			    struct channel_event *out);

/* List all rebalances */
struct rebalance **list_rebalances(const tal_t *ctx, struct db *db);

/* Log a channel event */
void log_channel_event(struct db *db,
		       const struct account *acct,
		       struct channel_event *e);

/* Log a chain event.
 * Returns true if inserted, false if already exists;
 * ctx is for allocating objects onto chain_event `e` */
bool log_chain_event(struct db *db,
                     const struct account *acct,
                     struct chain_event *e);

#endif /* LIGHTNING_PLUGINS_BKPR_RECORDER_H */
