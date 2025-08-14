#ifndef LIGHTNING_COMMON_COIN_MVT_H
#define LIGHTNING_COMMON_COIN_MVT_H
#include "config.h"

#include <common/amount.h>
#include <common/channel_id.h>
#include <common/utils.h>

#define COIN_MVT_VERSION 2
#define WALLET "wallet"

enum mvt_tag {
	MVT_DEPOSIT = 0,
	MVT_WITHDRAWAL = 1,
	MVT_PENALTY = 2,
	MVT_INVOICE = 3,
	MVT_ROUTED = 4,
	MVT_PUSHED = 5,
	MVT_CHANNEL_OPEN = 6,
	MVT_CHANNEL_CLOSE = 7,
	MVT_CHANNEL_TO_US = 8,
	MVT_HTLC_TIMEOUT = 9,
	MVT_HTLC_FULFILL = 10,
	MVT_HTLC_TX = 11,
	MVT_TO_WALLET = 12,
	MVT_ANCHOR = 13,
	MVT_TO_THEM = 14,
	MVT_PENALIZED = 15,
	MVT_STOLEN = 16,
	MVT_TO_MINER = 17,
	MVT_OPENER = 18,
	MVT_LEASE_FEE = 19,
	MVT_LEASED = 20,
	MVT_STEALABLE = 21,
	MVT_CHANNEL_PROPOSED = 22,
	MVT_SPLICE = 23,
#define NUM_MVT_TAGS (MVT_SPLICE + 1)
};

struct mvt_tags {
	u64 bits;
};

enum coin_mvt_dir {
	COIN_CREDIT = 1,
	COIN_DEBIT = 2,
};

struct channel_coin_mvt_id {
	/* multi-part payments may share a payment hash,
	 * so we should also record part-id and group-id for them */
	u64 part_id;
	u64 group_id;
};

/* Only one of these is set. */
struct mvt_account_id {
	const struct channel *channel;
	const char *alt_account;
};

struct channel_coin_mvt {
	/* Common fields */
	struct mvt_account_id account;
	struct mvt_tags tags;
	/* only one or the other */
	struct amount_msat credit;
	struct amount_msat debit;

	/* identifier */
	const struct sha256 *payment_hash;

	/* multi-part payments may share a payment hash,
	 * so we should also record part-id and group-id for them */
	const struct channel_coin_mvt_id *part_and_group;

	/* Fees collected (or paid) on this mvt */
	struct amount_msat fees;
};

struct chain_coin_mvt {
	/* account_id */
	struct mvt_account_id account;
	struct mvt_tags tags;
	/* only one or the other */
	struct amount_msat credit;
	struct amount_msat debit;

	const struct bitcoin_txid *tx_txid;
	const struct bitcoin_outpoint *outpoint;

	/* The id of the peer we have this channel with.
	 * Only on our channel_open events */
	const struct node_id *peer_id;

	/* some on-chain movements have a payment hash */
	const struct sha256 *payment_hash;

	/* block this transaction is confirmed in */
	u32 blockheight;

	/* total value of output (useful for tracking external outs) */
	struct amount_sat output_val;

	/* When we pay to external accounts, it's useful
	 * to track which internal account it originated from */
	const struct mvt_account_id *originating_acct;

	/* Number of outputs in spending tx; used by the
	 * `channel_close` event */
	u32 output_count;
};

/* Convenience macro for creating tag bitmaps */
#define mk_mvt_tags(...) mk_mvt_tags_(__VA_ARGS__, 999)
struct mvt_tags mk_mvt_tags_(enum mvt_tag tag, ...);

static inline struct mvt_tags tag_to_mvt_tags(enum mvt_tag tag)
{
	struct mvt_tags tags;
	tags.bits = ((u64)1) << tag;
	return tags;
}

/* Useful constructor for mvt_account_id: exactly one of channel/account_name must be NULL */
void set_mvt_account_id(struct mvt_account_id *acct_id,
			const struct channel *channel,
			const char *account_name TAKES);

/* Allocating version */
struct mvt_account_id *new_mvt_account_id(const tal_t *ctx,
					  const struct channel *channel,
					  const char *account_name TAKES);

/* Either part_id and group_id both NULL, or neither are */
struct channel_coin_mvt *new_channel_coin_mvt(const tal_t *ctx,
					      const struct channel *channel,
					      const struct sha256 *payment_hash TAKES,
					      const u64 *part_id,
					      const u64 *group_id,
					      enum coin_mvt_dir direction,
					      struct amount_msat amount,
					      struct mvt_tags tags,
					      struct amount_msat fees)
	NON_NULL_ARGS(2);

struct chain_coin_mvt *new_onchaind_withdraw(const tal_t *ctx,
					     const struct bitcoin_outpoint *outpoint,
					     const struct bitcoin_txid *spend_txid,
					     u32 blockheight,
					     struct amount_sat amount,
					     struct mvt_tags tags)
	NON_NULL_ARGS(2, 3);

struct chain_coin_mvt *new_onchaind_deposit(const tal_t *ctx,
					    const struct bitcoin_outpoint *outpoint,
					    u32 blockheight,
					    struct amount_sat amount,
					    struct mvt_tags tags)
	NON_NULL_ARGS(2);

struct chain_coin_mvt *new_coin_channel_close(const tal_t *ctx,
					      const struct channel *channel,
					      const char *alt_account,
					      const struct bitcoin_txid *txid,
					      const struct bitcoin_outpoint *out,
					      u32 blockheight,
					      const struct amount_msat amount,
					      const struct amount_sat output_val,
					      u32 output_count,
					      bool is_splice)
	NON_NULL_ARGS(4, 5);

struct chain_coin_mvt *new_coin_channel_open_proposed(const tal_t *ctx,
						      const struct channel *channel,
						      const struct bitcoin_outpoint *out,
						      const struct node_id *peer_id,
						      const struct amount_msat amount,
						      const struct amount_sat output_val,
						      bool is_opener,
						      bool is_leased)
	NON_NULL_ARGS(2, 3, 4);

struct chain_coin_mvt *new_coin_channel_open(const tal_t *ctx,
					     const struct channel *channel,
					     const struct bitcoin_outpoint *out,
					     const struct node_id *peer_id,
					     u32 blockheight,
					     const struct amount_msat amount,
					     const struct amount_sat output_val,
					     bool is_opener,
					     bool is_leased)
	NON_NULL_ARGS(2, 3, 4);

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
					       struct mvt_tags tags)
	NON_NULL_ARGS(2);


struct chain_coin_mvt *new_coin_wallet_withdraw(const tal_t *ctx,
						const struct bitcoin_txid *spend_txid,
						const struct bitcoin_outpoint *outpoint,
						u32 blockheight,
						struct amount_sat amount,
						struct mvt_tags tags)
	NON_NULL_ARGS(2, 3);

struct chain_coin_mvt *new_coin_external_spend(const tal_t *ctx,
					       const struct bitcoin_outpoint *outpoint,
					       const struct bitcoin_txid *txid,
					       u32 blockheight,
					       struct amount_sat amount,
					       struct mvt_tags tags)
	NON_NULL_ARGS(2, 3);

struct chain_coin_mvt *new_coin_external_deposit(const tal_t *ctx,
						 const struct bitcoin_outpoint *outpoint,
						 u32 blockheight,
						 struct amount_sat amount,
						 struct mvt_tags tags)
	NON_NULL_ARGS(2);

struct channel_coin_mvt *new_coin_channel_push(const tal_t *ctx,
					       const struct channel *channel,
					       enum coin_mvt_dir direction,
					       struct amount_msat amount,
					       struct mvt_tags tags)
	NON_NULL_ARGS(2);

/* Is this an xternal account? */
bool chain_mvt_is_external(const struct chain_coin_mvt *mvt);

const char *mvt_tag_str(enum mvt_tag tag);
const char **mvt_tag_strs(const tal_t *ctx, struct mvt_tags tags);

/* Parse a single mvt tag.  Returns false or populates *tag */
bool mvt_tag_parse(const char *buf, size_t len, enum mvt_tag *tag);

void towire_chain_coin_mvt(u8 **pptr, const struct chain_coin_mvt *mvt);
void fromwire_chain_coin_mvt(const u8 **cursor, size_t *max, struct chain_coin_mvt *mvt);

#endif /* LIGHTNING_COMMON_COIN_MVT_H */
