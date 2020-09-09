#ifndef LIGHTNING_COMMON_COIN_MVT_H
#define LIGHTNING_COMMON_COIN_MVT_H
#include "config.h"

#include <bitcoin/tx.h>
#include <ccan/ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <common/amount.h>
#include <common/channel_id.h>
#include <stdbool.h>
#include <wire/wire.h>

#define COIN_MVT_VERSION 1

#define COIN_MVT_ACCT_WALLET "wallet"

enum mvt_type {
	CHAIN_MVT = 0,
	CHANNEL_MVT = 1,
};

enum mvt_tag {
	DEPOSIT = 0,
	WITHDRAWAL = 1,
	CHAIN_FEES = 2,
	PENALTY = 3,
	INVOICE = 4,
	ROUTED = 5,
	JOURNAL = 6,
	ONCHAIN_HTLC = 7,
	PUSHED = 8,
	SPEND_TRACK = 9,
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
	const struct bitcoin_txid *output_txid;
	u32 vout;

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
};

/* differs depending on type!? */
struct mvt_id {
	struct sha256 *payment_hash;
	u64 *part_id;
	const struct bitcoin_txid *tx_txid;
	const struct bitcoin_txid *output_txid;
	u32 vout;
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

	u32 timestamp;
	u32 blockheight;

	/* version is a counter of the format of the data payload that
	 * makes up a coin movement */
	u8 version;

	/* node originating this movement */
	struct node_id *node_id;

	/* id of this movement (on this node) */
	u64 counter;
};

struct channel_coin_mvt *new_channel_coin_mvt(const tal_t *ctx,
					      const struct channel_id *cid,
					      struct sha256 payment_hash,
					      u64 *part_id,
					      struct amount_msat amount,
					      enum mvt_tag tag,
					      bool is_credit);

struct chain_coin_mvt *new_coin_withdrawal(const tal_t *ctx,
					  const char *account_name,
					  const struct bitcoin_txid *tx_txid,
					  const struct bitcoin_txid *out_txid,
					  u32 vout,
					  u32 blockheight,
					  struct amount_msat amount);
struct chain_coin_mvt *new_coin_withdrawal_sat(const tal_t *ctx,
					       const char *account_name,
					       const struct bitcoin_txid *tx_txid,
					       const struct bitcoin_txid *out_txid,
					       u32 vout,
					       u32 blockheight,
					       struct amount_sat amount);
struct chain_coin_mvt *new_coin_chain_fees(const tal_t *ctx,
					   const char *account_name,
					   const struct bitcoin_txid *tx_txid,
					   u32 blockheight,
					   struct amount_msat amount);
struct chain_coin_mvt *new_coin_chain_fees_sat(const tal_t *ctx,
					       const char *account_name,
					       const struct bitcoin_txid *tx_txid,
					       u32 blockheight,
					       struct amount_sat amount);
struct chain_coin_mvt *new_coin_journal_entry(const tal_t *ctx,
					      const char *account_name,
					      const struct bitcoin_txid *txid,
					      const struct bitcoin_txid *out_txid,
					      u32 vout,
					      u32 blockheight,
					      struct amount_msat amount,
					      bool is_credit);
struct chain_coin_mvt *new_coin_deposit(const tal_t *ctx,
					const char *account_name,
					const struct bitcoin_txid *txid,
					u32 vout, u32 blockheight,
					struct amount_msat amount);
struct chain_coin_mvt *new_coin_deposit_sat(const tal_t *ctx,
					    const char *account_name,
					    const struct bitcoin_txid *txid,
					    u32 vout,
					    u32 blockheight,
					    struct amount_sat amount);
struct chain_coin_mvt *new_coin_penalty_sat(const tal_t *ctx,
					    const char *account_name,
					    const struct bitcoin_txid *txid,
					    const struct bitcoin_txid *out_txid,
					    u32 vout,
					    u32 blockheight,
					    struct amount_sat amount);

struct chain_coin_mvt *new_coin_onchain_htlc_sat(const tal_t *ctx,
						 const char *account_name,
						 const struct bitcoin_txid *txid,
						 const struct bitcoin_txid *out_txid,
						 u32 vout,
						 struct sha256 payment_hash,
						 u32 blockheight,
						 struct amount_sat amount,
						 bool is_credit);
struct chain_coin_mvt *new_coin_spend_track(const tal_t *ctx,
					    const struct bitcoin_txid *txid,
					    const struct bitcoin_txid *out_txid,
					    u32 vout, u32 blockheight);
struct chain_coin_mvt *new_coin_pushed(const tal_t *ctx,
				       const char *account_name,
				       const struct bitcoin_txid *txid,
				       u32 blockheight,
				       struct amount_msat amount);
struct coin_mvt *finalize_chain_mvt(const tal_t *ctx,
				    const struct chain_coin_mvt *chain_mvt,
				    const char *bip173_name,
				    u32 timestamp,
				    struct node_id *node_id,
				    s64 mvt_count);
struct coin_mvt *finalize_channel_mvt(const tal_t *ctx,
				      const struct channel_coin_mvt *chan_mvt,
				      const char *bip173_name,
				      u32 timestamp, struct node_id *node_id,
				      s64 mvt_count);

const char *mvt_type_str(enum mvt_type type);
const char *mvt_tag_str(enum mvt_tag tag);

void towire_chain_coin_mvt(u8 **pptr, const struct chain_coin_mvt *mvt);
void fromwire_chain_coin_mvt(const u8 **cursor, size_t *max, struct chain_coin_mvt *mvt);

#endif /* LIGHTNING_COMMON_COIN_MVT_H */
