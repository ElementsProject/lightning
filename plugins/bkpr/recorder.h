#ifndef LIGHTNING_PLUGINS_BKPR_RECORDER_H
#define LIGHTNING_PLUGINS_BKPR_RECORDER_H

#include "config.h"
#include <ccan/tal/tal.h>

struct account;
struct bitcoin_txid;
struct chain_event;
struct channel_event;
struct plugin;
enum mvt_tag;
struct onchain_fee;

#define SQLITE_MAX_UINT 0x7FFFFFFFFFFFFFFF

struct fee_sum {
	const char *acct_name;
	struct bitcoin_txid *txid;
	struct amount_msat fees_paid;
	u64 last_timestamp;
};

struct txo_pair {
	struct chain_event *txo;
	struct chain_event *spend;
};

struct txo_set {
	struct bitcoin_txid *txid;
	struct txo_pair **pairs;
};

/* Get all channel events for this account */
struct channel_event **account_get_channel_events(const tal_t *ctx,
						  const struct bkpr *bkpr,
						  struct command *cmd,
						  struct account *acct);

/* Get all channel events for a payment id, order by timestamp */
struct channel_event **get_channel_events_by_id(const tal_t *ctx,
						const struct bkpr *bkpr,
						struct command *cmd,
						const struct sha256 *id);

/* Get all channel events, ordered by timestamp */
struct channel_event **list_channel_events(const tal_t *ctx,
					   const struct bkpr *bkpr,
					   struct command *cmd);

/* Get all channel events, order by timestamp.
 *
 * @ctx - context to allocate from
 * @start_time - UNIX timestamp to query after (exclusive)
 * @end_time   - UNIX timestamp to query until (inclusive)
 */
struct channel_event **list_channel_events_timebox(const tal_t *ctx,
						   const struct bkpr *bkpr,
						   struct command *cmd,
						   u64 start_time,
						   u64 end_time);

/* Get all chain events for this account */
struct chain_event **account_get_chain_events(const tal_t *ctx,
					      const struct bkpr *bkpr,
					      struct command *cmd,
					      struct account *acct);

/* Get all chain events for a transaction id, order by timestamp */
struct chain_event **find_chain_events_bytxid(const tal_t *ctx,
					      const struct bkpr *bkpr,
					      struct command *cmd,
					      const struct bitcoin_txid *txid);

/* Get all chain events, order by timestamp.  */
struct chain_event **list_chain_events(const tal_t *ctx,
				       const struct bkpr *bkpr,
				       struct command *cmd);

/* Get all chain events, order by timestamp.
 *
 * @ctx - context to allocate from
 * @start_time - UNIX timestamp to query after (exclusive)
 * @end_time   - UNIX timestamp to query until (inclusive)
 */
struct chain_event **list_chain_events_timebox(const tal_t *ctx,
					       const struct bkpr *bkpr,
					       struct command *cmd,
					       u64 start_time,
					       u64 end_time);

/* Get all chain events for a payment hash */
struct chain_event **get_chain_events_by_id(const tal_t *ctx,
					    const struct bkpr *bkpr,
					    struct command *cmd,
					    const struct sha256 *id);

/* Get all chain events for a utxo */
struct chain_event **get_chain_events_by_outpoint(const tal_t *ctx,
						  const struct bkpr *bkpr,
						  struct command *cmd,
						  const struct bitcoin_outpoint *outpoint);

/* Get total credits and debits for this account: returns false if no entries at all
 * (in which case, credit and debit will both be AMOUNT_MSAT(0)). */
bool account_get_credit_debit(const struct bkpr *bkpr,
			      struct command *cmd,
			      const char *acct_name,
			      struct amount_msat *credit,
			      struct amount_msat *debit);


/* Find a chain event by its database id */
struct chain_event *find_chain_event_by_id(const tal_t *ctx,
					   const struct bkpr *bkpr,
					   struct command *cmd,
					   u64 event_db_id);

/* Find the utxos for this account.
 *
 * Returns true if chain is complete:
 * (all outputs terminate either to wallet or external)
 */
bool find_txo_chain(const tal_t *ctx,
		    const struct bkpr *bkpr,
		    struct command *cmd,
		    const struct account *acct,
		    struct txo_set ***sets);

/* Find the account that was closed by this txid.
 * Returns NULL if none  */
const char *find_close_account_name(const tal_t *ctx,
				    const struct bkpr *bkpr,
				    struct command *cmd,
				    const struct bitcoin_txid *txid);

/* Have all the outputs for this account's close tx
 * been resolved onchain? If so, return the
 * highest blockheight that has a resolving tx in it.
 *
 * The point of this is to allow us to prune data, eventually */
u64 account_onchain_closeheight(const struct bkpr *bkpr,
				struct command *cmd,
				const struct account *acct);

/* When we make external deposits from the wallet, we don't
 * count them until any output that was spent *into* them is
 * confirmed onchain.
 *
 * This method updates bkpr->blockheights to show the
 * height an input was spent into */
void maybe_closeout_external_deposits(struct command *cmd,
				      struct bkpr *bkpr,
				      const struct bitcoin_txid *txid,
				      u32 blockheight);

/* Keep track of rebalancing payments (payments paid to/from ourselves. */
void maybe_record_rebalance(struct command *cmd,
			    struct bkpr *bkpr,
			    const struct channel_event *out);
#endif /* LIGHTNING_PLUGINS_BKPR_RECORDER_H */
