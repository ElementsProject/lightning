#ifndef LIGHTNING_COMMON_COIN_MVT_H
#define LIGHTNING_COMMON_COIN_MVT_H
#include "config.h"

#include <common/amount.h>
#include <common/channel_id.h>
#include <common/utils.h>

#define COIN_MVT_VERSION 2
#define WALLET "wallet"

enum mvt_type {
	CHAIN_MVT = 0,
	CHANNEL_MVT = 1,
};

enum mvt_tag {
	DEPOSIT = 0,
	WITHDRAWAL = 1,
	PENALTY = 2,
	INVOICE = 3,
	ROUTED = 4,
	PUSHED = 5,
	CHANNEL_OPEN = 6,
	CHANNEL_CLOSE = 7,
	CHANNEL_TO_US = 8,
	HTLC_TIMEOUT = 9,
	HTLC_FULFILL = 10,
	HTLC_TX = 11,
	TO_WALLET = 12,
	IGNORED = 13,
	ANCHOR = 14,
	TO_THEM = 15,
	PENALIZED = 16,
	STOLEN = 17,
	TO_MINER = 18,
	OPENER = 19,
	LEASE_FEE = 20,
	LEASED = 21,
};

struct channel_coin_mvt {
	/* account_id */
	struct channel_id chan_id;

	/* identifier */
	struct sha256 *payment_hash;

	/* mutli-part payments may share a payment hash,
	 * so we should also record a 'part-id' for them */
	u64 *part_id;

	/* label / tag array */
	enum mvt_tag *tags;

	/* only one or the other */
	struct amount_msat credit;
	struct amount_msat debit;

	/* Fees collected (or paid) on this mvt */
	struct amount_msat fees;
};

struct chain_coin_mvt {
	/* account_id */
	const char *account_name;
	const struct bitcoin_txid *tx_txid;
	const struct bitcoin_outpoint *outpoint;

	/* some on-chain movements have a payment hash */
	struct sha256 *payment_hash;

	/* label / tag array */
	enum mvt_tag *tags;

	/* block this transaction is confirmed in
	 * zero means it's unknown/unconfirmed */
	u32 blockheight;

	/* only one or the other */
	struct amount_msat credit;
	struct amount_msat debit;

	/* total value of output (useful for tracking external outs) */
	struct amount_sat output_val;

	/* When we pay to external accounts, it's useful
	 * to track which internal account it originated from */
	const char *originating_acct;
};

/* differs depending on type!? */
struct mvt_id {
	struct sha256 *payment_hash;
	u64 *part_id;
	const struct bitcoin_txid *tx_txid;
	const struct bitcoin_outpoint *outpoint;
};

struct coin_mvt {
	/* name of 'account': wallet, external, <channel_id> */
	const char *account_id;

	/* if account_id is external, the account this 'impacted' */
	const char *originating_acct;

	/* Chain name: BIP 173, except signet lightning-style: tbs not tb */
	const char *hrp_name;

	/* type of movement: channel or chain */
	enum mvt_type type;

	/* identifier */
	struct mvt_id id;

	/* label / tag array */
	enum mvt_tag *tags;

	/* only one or the other */
	struct amount_msat credit;
	struct amount_msat debit;

	/* Value of the output. May be different than
	 * our credit/debit amount, eg channel opens */
	struct amount_sat *output_val;

	/* Amount of fees collected/paid by channel mvt */
	struct amount_msat *fees;

	u32 timestamp;
	u32 blockheight;

	/* version is a counter of the format of the data payload that
	 * makes up a coin movement */
	u8 version;

	/* node originating this movement */
	struct node_id *node_id;
};

enum mvt_tag *new_tag_arr(const tal_t *ctx, enum mvt_tag tag);

struct channel_coin_mvt *new_channel_coin_mvt(const tal_t *ctx,
					      const struct channel_id *cid,
					      const struct sha256 *payment_hash TAKES,
					      u64 *part_id TAKES,
					      struct amount_msat amount,
					      const enum mvt_tag *tags TAKES,
					      bool is_credit,
					      struct amount_msat fees)
	NON_NULL_ARGS(2);

struct chain_coin_mvt *new_onchaind_withdraw(const tal_t *ctx,
					     const struct bitcoin_outpoint *outpoint,
					     const struct bitcoin_txid *spend_txid,
					     u32 blockheight,
					     struct amount_sat amount,
					     enum mvt_tag tag)
	NON_NULL_ARGS(2, 3);

struct chain_coin_mvt *new_onchaind_deposit(const tal_t *ctx,
					    const struct bitcoin_outpoint *outpoint,
					    u32 blockheight,
					    struct amount_sat amount,
					    enum mvt_tag tag)
	NON_NULL_ARGS(2);

struct chain_coin_mvt *new_coin_channel_close(const tal_t *ctx,
					      const struct bitcoin_txid *txid,
					      const struct bitcoin_outpoint *out,
					      u32 blockheight,
					      const struct amount_msat amount,
					      const struct amount_sat output_val)
	NON_NULL_ARGS(2, 3);

struct chain_coin_mvt *new_coin_channel_open(const tal_t *ctx,
					     const struct channel_id *chan_id,
					     const struct bitcoin_outpoint *out,
					     u32 blockheight,
					     const struct amount_msat amount,
					     const struct amount_sat output_val,
					     bool is_opener,
					     bool is_leased)
	NON_NULL_ARGS(2, 3);

struct chain_coin_mvt *new_onchain_htlc_deposit(const tal_t *ctx,
						const struct bitcoin_outpoint *outpoint,
						u32 blockheight,
						struct amount_sat amount,
						const struct sha256 *payment_hash)
	NON_NULL_ARGS(2, 5);

struct chain_coin_mvt *new_onchain_htlc_withdraw(const tal_t *ctx,
						 const struct bitcoin_outpoint *outpoint,
						 u32 blockheight,
						 struct amount_sat amount,
						 const struct sha256 *payment_hash)
	NON_NULL_ARGS(2, 5);

struct chain_coin_mvt *new_coin_wallet_deposit(const tal_t *ctx,
					       const struct bitcoin_outpoint *outpoint,
					       u32 blockheight,
					       struct amount_sat amount,
					       enum mvt_tag tag)
	NON_NULL_ARGS(2);

struct chain_coin_mvt *new_coin_wallet_withdraw(const tal_t *ctx,
						const struct bitcoin_txid *spend_txid,
						const struct bitcoin_outpoint *outpoint,
						u32 blockheight,
						struct amount_sat amount,
						enum mvt_tag tag)
	NON_NULL_ARGS(2, 3);

struct chain_coin_mvt *new_coin_external_spend(const tal_t *ctx,
					       const struct bitcoin_outpoint *outpoint,
					       const struct bitcoin_txid *txid,
					       u32 blockheight,
					       struct amount_sat amount,
					       enum mvt_tag tag)
	NON_NULL_ARGS(2, 3);

struct chain_coin_mvt *new_coin_external_deposit(const tal_t *ctx,
						 const struct bitcoin_outpoint *outpoint,
						 u32 blockheight,
						 struct amount_sat amount,
						 enum mvt_tag tag)
	NON_NULL_ARGS(2);

struct channel_coin_mvt *new_coin_channel_push(const tal_t *ctx,
					       const struct channel_id *cid,
					       struct amount_msat amount,
					       enum mvt_tag tag,
					       bool is_credit)
	NON_NULL_ARGS(2);

struct coin_mvt *finalize_chain_mvt(const tal_t *ctx,
				    const struct chain_coin_mvt *chain_mvt,
				    const char *hrp_name,
				    u32 timestamp,
				    struct node_id *node_id)
	NON_NULL_ARGS(2, 3);

struct coin_mvt *finalize_channel_mvt(const tal_t *ctx,
				      const struct channel_coin_mvt *chan_mvt,
				      const char *hrp_name,
				      u32 timestamp,
				      const struct node_id *node_id)
	NON_NULL_ARGS(2, 3, 5);

/* Is this an xternal account? */
bool chain_mvt_is_external(const struct chain_coin_mvt *mvt);

const char *mvt_type_str(enum mvt_type type);
const char *mvt_tag_str(enum mvt_tag tag);

void towire_chain_coin_mvt(u8 **pptr, const struct chain_coin_mvt *mvt);
void fromwire_chain_coin_mvt(const u8 **cursor, size_t *max, struct chain_coin_mvt *mvt);

#endif /* LIGHTNING_COMMON_COIN_MVT_H */
