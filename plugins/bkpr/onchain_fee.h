#ifndef LIGHTNING_PLUGINS_BKPR_ONCHAIN_FEE_H
#define LIGHTNING_PLUGINS_BKPR_ONCHAIN_FEE_H

#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/short_types/short_types.h>
#include <plugins/bkpr/bookkeeper.h>

struct account;
struct amount_msat;
struct bitcoin_txid;
struct db;
struct onchain_fees;

struct onchain_fee {
	/* Name of the account this belongs to */
	const char *acct_name;

	/* Transaction that we're recording fees for */
	struct bitcoin_txid txid;

	/* Incremental change in onchain fees */
	struct amount_msat credit;
	struct amount_msat debit;

	/* Timestamp of the event that created this fee update */
	u64 timestamp;

	/* Count of records we've recorded for this tx */
	u32 update_count;
};

void json_add_onchain_fee(struct json_stream *out,
			  const struct onchain_fee *fee);

/* List all chain fees, for all accounts */
struct onchain_fee **list_chain_fees(const tal_t *ctx, const struct bkpr *bkpr);

/* Get all chain fees, order by timestamp.
 *
 * @ctx - context to allocate from
 * @db  - database to query
 * @start_time - UNIX timestamp to query after (exclusive)
 * @end_time   - UNIX timestamp to query until (inclusive)
 */
struct onchain_fee **list_chain_fees_timebox(const tal_t *ctx,
					     const struct bkpr *bkpr,
					     u64 start_time, u64 end_time);

/* Get all chain fees for a transaction id, order by timestamp */
struct onchain_fee **get_chain_fees_by_txid(const tal_t *ctx,
					    const struct bkpr *bkpr,
					    const struct bitcoin_txid *txid);

/* Get chain fees for account */
struct onchain_fee **account_get_chain_fees(const tal_t *ctx,
					    const struct bkpr *bkpr,
					    const char *acct_name);

/* Returns a list of sums of the fees we've recorded for every txid
 * for the given account */
struct fee_sum **find_account_onchain_fees(const tal_t *ctx,
					   const struct bkpr *bkpr,
					   const struct account *acct);

/* Final all the onchain fees */
struct fee_sum **calculate_onchain_fee_sums(const tal_t *ctx,
					    const struct bkpr *bkpr);

/* Find the last timestamp for the onchain fees for this txid + account */
u64 onchain_fee_last_timestamp(const struct bkpr *bkpr,
			       const char *acct_name,
			       const struct bitcoin_txid *txid);

/* Update our onchain fees now? */
char *maybe_update_onchain_fees(const tal_t *ctx,
				struct bkpr *bkpr,
			        struct bitcoin_txid *txid);

/* We calculate onchain fees for channel closes a bit different */
char *update_channel_onchain_fees(const tal_t *ctx,
				  struct bkpr *bkpr,
				  struct account *acct);

/* Set up the onchain_fees struct */
struct onchain_fees *init_onchain_fees(const tal_t *ctx,
				       struct db *db,
				       struct command *init_cmd);

#endif /* LIGHTNING_PLUGINS_BKPR_ONCHAIN_FEE_H */
