#ifndef LIGHTNING_COMMON_COIN_MVT_H
#define LIGHTNING_COMMON_COIN_MVT_H
#include "config.h"

#include <common/amount.h>
#include <common/channel_id.h>

#define COIN_MVT_VERSION 2

#define COIN_MVT_ACCT_WALLET "wallet"

enum mvt_type {
	CHAIN_MVT = 0,
	CHANNEL_MVT = 1,
};

enum mvt_tag {
	DEPOSIT = 0,
	WITHDRAWAL = 1,
	/* 2, CHAIN_FEES has been removed */
	PENALTY = 3,
	INVOICE = 4,
	ROUTED = 5,
	JOURNAL = 6,
	/* 7, ONCHAIN_HTLC has been removed */
	PUSHED = 8,
	/* 9, SPEND_TRACK has been removed */
	CHANNEL_OPEN = 10,
	CHANNEL_CLOSE = 11,
	CHANNEL_TO_US = 12,
	HTLC_TIMEOUT = 13,
	HTLC_FULFILL = 14,
	HTLC_TX = 15,
	TO_WALLET = 16,
	IGNORED = 17,
	ANCHOR = 18,
	TO_THEM = 19,
	PENALIZED = 20,
	STOLEN = 21,
	TO_MINER = 22,
};

struct channel_coin_mvt {
	/* account_id */
	struct channel_id chan_id;

	/* identifier */
	struct sha256 *payment_hash;

	/* mutli-part payments may share a payment hash,
	 * so we should also record a 'part-id' for them */
	u64 *part_id;

	/* label / tag */
	enum mvt_tag tag;

	/* only one or the other */
	struct amount_msat credit;
	struct amount_msat debit;

};

struct chain_coin_mvt {
	/* account_id */
	const char *account_name;
	const struct bitcoin_txid *tx_txid;
	const struct bitcoin_outpoint *outpoint;

	/* some on-chain movements have a payment hash */
	struct sha256 *payment_hash;

	/* label / tag */
	enum mvt_tag tag;

	/* block this transaction is confirmed in
	 * zero means it's unknown/unconfirmed */
	u32 blockheight;

	/* only one or the other */
	struct amount_msat credit;
	struct amount_msat debit;

	/* total value of output (useful for tracking external outs) */
	struct amount_sat output_val;
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
	const char *bip173_name;

	/* type of movement: channel or chain */
	enum mvt_type type;

	/* identifier */
	struct mvt_id id;

	/* label / tag */
	enum mvt_tag tag;

	/* only one or the other */
	struct amount_msat credit;
	struct amount_msat debit;

	/* Value of the output. May be different than
	 * our credit/debit amount, eg channel opens */
	struct amount_sat *output_val;

	u32 timestamp;
	u32 blockheight;

	/* version is a counter of the format of the data payload that
	 * makes up a coin movement */
	u8 version;

	/* node originating this movement */
	struct node_id *node_id;
};

struct channel_coin_mvt *new_channel_coin_mvt(const tal_t *ctx,
					      const struct channel_id *cid,
					      struct sha256 payment_hash,
					      u64 *part_id,
					      struct amount_msat amount,
					      enum mvt_tag tag,
					      bool is_credit);

struct chain_coin_mvt *new_onchaind_withdraw(const tal_t *ctx,
					     const struct bitcoin_outpoint *outpoint,
					     const struct bitcoin_txid *spend_txid,
					     u32 blockheight,
					     struct amount_sat amount,
					     enum mvt_tag tag);

struct chain_coin_mvt *new_onchaind_deposit(const tal_t *ctx,
					    const struct bitcoin_outpoint *outpoint,
					    u32 blockheight,
					    struct amount_sat amount,
					    enum mvt_tag tag);

struct chain_coin_mvt *new_coin_journal_entry(const tal_t *ctx,
					      const struct bitcoin_txid *txid,
					      const struct bitcoin_outpoint *outpoint,
					      u32 blockheight,
					      struct amount_msat amount,
					      bool is_credit);

struct chain_coin_mvt *new_coin_channel_close(const tal_t *ctx,
					      const struct bitcoin_txid *txid,
					      const struct bitcoin_outpoint *out,
					      u32 blockheight,
					      const struct amount_msat amount,
					      const struct amount_sat output_val);
struct chain_coin_mvt *new_coin_channel_open(const tal_t *ctx,
					     const struct channel_id *chan_id,
					     const struct bitcoin_outpoint *out,
					     u32 blockheight,
					     const struct amount_msat amount,
					     const struct amount_sat output_val);

struct chain_coin_mvt *new_onchain_htlc_deposit(const tal_t *ctx,
						const struct bitcoin_outpoint *outpoint,
						u32 blockheight,
						struct amount_sat amount,
						struct sha256 *payment_hash);

struct chain_coin_mvt *new_onchain_htlc_withdraw(const tal_t *ctx,
						 const struct bitcoin_outpoint *outpoint,
						 u32 blockheight,
						 struct amount_sat amount,
						 struct sha256 *payment_hash);

struct chain_coin_mvt *new_coin_wallet_deposit(const tal_t *ctx,
					       const struct bitcoin_outpoint *outpoint,
					       u32 blockheight,
					       struct amount_sat amount,
					       enum mvt_tag tag);

struct chain_coin_mvt *new_coin_wallet_withdraw(const tal_t *ctx,
						const struct bitcoin_txid *spend_txid,
						const struct bitcoin_outpoint *outpoint,
						u32 blockheight,
						struct amount_sat amount,
						enum mvt_tag tag);

struct chain_coin_mvt *new_coin_external_spend(const tal_t *ctx,
					       const struct bitcoin_outpoint *outpoint,
					       const struct bitcoin_txid *txid,
					       u32 blockheight,
					       struct amount_sat amount,
					       enum mvt_tag tag);

struct chain_coin_mvt *new_coin_external_deposit(const tal_t *ctx,
						 const struct bitcoin_outpoint *outpoint,
						 u32 blockheight,
						 struct amount_sat amount,
						 enum mvt_tag tag);

struct chain_coin_mvt *new_coin_penalty_sat(const tal_t *ctx,
					    const char *account_name,
					    const struct bitcoin_txid *txid,
					    const struct bitcoin_outpoint *outpoint,
					    u32 blockheight,
					    struct amount_sat amount);

struct channel_coin_mvt *new_coin_pushed(const tal_t *ctx,
					 const struct channel_id *cid,
					 struct amount_msat amount);

struct coin_mvt *finalize_chain_mvt(const tal_t *ctx,
				    const struct chain_coin_mvt *chain_mvt,
				    const char *bip173_name,
				    u32 timestamp,
				    struct node_id *node_id);

struct coin_mvt *finalize_channel_mvt(const tal_t *ctx,
				      const struct channel_coin_mvt *chan_mvt,
				      const char *bip173_name,
				      u32 timestamp, struct node_id *node_id);

const char *mvt_type_str(enum mvt_type type);
const char *mvt_tag_str(enum mvt_tag tag);

void towire_chain_coin_mvt(u8 **pptr, const struct chain_coin_mvt *mvt);
void fromwire_chain_coin_mvt(const u8 **cursor, size_t *max, struct chain_coin_mvt *mvt);

#endif /* LIGHTNING_COMMON_COIN_MVT_H */
