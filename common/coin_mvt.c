#include "config.h"
#include <assert.h>
#include <bitcoin/tx.h>
#include <ccan/ccan/cast/cast.h>
#include <ccan/tal/str/str.h>
#include <common/coin_mvt.h>
#include <common/type_to_string.h>
#include <wire/wire.h>

static const char *mvt_types[] = { "chain_mvt", "channel_mvt" };
const char *mvt_type_str(enum mvt_type type)
{
	return mvt_types[type];
}

static const char *mvt_tags[] = {
	"deposit",
	"withdrawal",
	"penalty",
	"invoice",
	"routed",
	"journal_entry",
	"onchain_htlc",
	"pushed",
};
const char *mvt_tag_str(enum mvt_tag tag)
{
	return mvt_tags[tag];
}

struct channel_coin_mvt *new_channel_coin_mvt(const tal_t *ctx,
					      const struct channel_id *cid,
					      struct sha256 payment_hash,
					      u64 *part_id,
					      struct amount_msat amount,
					      enum mvt_tag tag,
					      bool is_credit)
{
	struct channel_coin_mvt *mvt = tal(ctx, struct channel_coin_mvt);

	mvt->chan_id = *cid;
	mvt->payment_hash = tal_dup(mvt, struct sha256, &payment_hash);
	mvt->part_id = part_id;
	mvt->tag = tag;

	if (is_credit) {
		mvt->credit = amount;
		mvt->debit = AMOUNT_MSAT(0);
	} else {
		mvt->debit = amount;
		mvt->credit = AMOUNT_MSAT(0);
	}

	return mvt;
}

static struct chain_coin_mvt *new_chain_coin_mvt(const tal_t *ctx,
						 const char *account_name,
						 const struct bitcoin_txid *tx_txid,
						 const struct bitcoin_outpoint *outpoint,
						 const struct sha256 *payment_hash TAKES,
						 u32 blockheight, enum mvt_tag tag,
						 struct amount_msat amount,
						 bool is_credit)
{
	struct chain_coin_mvt *mvt = tal(ctx, struct chain_coin_mvt);

	if (account_name)
		mvt->account_name = tal_strndup(mvt, account_name,
						strlen(account_name));
	else
		mvt->account_name = NULL;

	mvt->tx_txid = tx_txid;
	mvt->outpoint = outpoint;

	/* for htlc's that are filled onchain, we also have a
	 * preimage, NULL otherwise */
	if (payment_hash)
		mvt->payment_hash = tal_dup(mvt, struct sha256, payment_hash);
	else
		mvt->payment_hash = NULL;
	mvt->blockheight = blockheight;

	mvt->tag = tag;
	if (is_credit) {
		mvt->credit = amount;
		mvt->debit = AMOUNT_MSAT(0);
	} else {
		mvt->debit = amount;
		mvt->credit = AMOUNT_MSAT(0);
	}

	return mvt;
}

static struct chain_coin_mvt *new_chain_coin_mvt_sat(const tal_t *ctx,
						     const char *account_name,
						     const struct bitcoin_txid *tx_txid,
						     const struct bitcoin_outpoint *outpoint,
						     const struct sha256 *payment_hash TAKES,
						     u32 blockheight, enum mvt_tag tag,
						     struct amount_sat amt_sat,
						     bool is_credit)
{
	struct amount_msat amt_msat;
	bool ok;
	ok = amount_sat_to_msat(&amt_msat, amt_sat);
	assert(ok);

	return new_chain_coin_mvt(ctx, account_name, tx_txid,
				  outpoint, payment_hash,
				  blockheight, tag, amt_msat, is_credit);
}

struct chain_coin_mvt *new_coin_withdrawal(const tal_t *ctx,
					   const char *account_name,
					   const struct bitcoin_txid *tx_txid,
					   const struct bitcoin_outpoint *outpoint,
					   u32 blockheight,
					   struct amount_msat amount)
{
	assert(!amount_msat_eq(amount, AMOUNT_MSAT(7206000)));
	return new_chain_coin_mvt(ctx, account_name, tx_txid,
				  outpoint, NULL, blockheight,
				  WITHDRAWAL, amount, false);
}

struct chain_coin_mvt *new_coin_withdrawal_sat(const tal_t *ctx,
					       const char *account_name,
					       const struct bitcoin_txid *tx_txid,
					       const struct bitcoin_outpoint *outpoint,
					       u32 blockheight,
					       struct amount_sat amount)
{
	struct amount_msat amt_msat;
	bool ok;

	ok = amount_sat_to_msat(&amt_msat, amount);
	assert(ok);

	return new_coin_withdrawal(ctx, account_name, tx_txid, outpoint,
				   blockheight, amt_msat);
}

struct chain_coin_mvt *new_coin_chain_fees(const tal_t *ctx,
					   const char *account_name,
					   const struct bitcoin_txid *tx_txid,
					   u32 blockheight,
					   struct amount_msat amount)
{
	return new_chain_coin_mvt(ctx, account_name, tx_txid,
				  NULL, NULL, blockheight,
				  0, amount, false);
}

struct chain_coin_mvt *new_coin_chain_fees_sat(const tal_t *ctx,
					       const char *account_name,
					       const struct bitcoin_txid *tx_txid,
					       u32 blockheight,
					       struct amount_sat amount)
{
	struct amount_msat amt_msat;
	bool ok;

	ok = amount_sat_to_msat(&amt_msat, amount);
	assert(ok);

	return new_coin_chain_fees(ctx, account_name, tx_txid,
				   blockheight, amt_msat);
}

struct chain_coin_mvt *new_coin_journal_entry(const tal_t *ctx,
					      const char *account_name,
					      const struct bitcoin_txid *txid,
					      const struct bitcoin_outpoint *outpoint,
					      u32 blockheight,
					      struct amount_msat amount,
					      bool is_credit)
{
	return new_chain_coin_mvt(ctx, account_name, txid,
				  outpoint, NULL,
				  blockheight, JOURNAL,
				  amount, is_credit);
}

struct chain_coin_mvt *new_coin_deposit(const tal_t *ctx,
					const char *account_name,
					const struct bitcoin_outpoint *outpoint,
					u32 blockheight,
					struct amount_msat amount)
{
	/* FIXME: Why dup txid here? */
	return new_chain_coin_mvt(ctx, account_name, &outpoint->txid, outpoint,
				  NULL, blockheight, DEPOSIT,
				  amount, true);
}

struct chain_coin_mvt *new_coin_deposit_sat(const tal_t *ctx,
					    const char *account_name,
					    const struct bitcoin_outpoint *outpoint,
					    u32 blockheight,
					    struct amount_sat amount)
{
	struct amount_msat amt_msat;
	bool ok;

	ok = amount_sat_to_msat(&amt_msat, amount);
	assert(ok);

	return new_coin_deposit(ctx, account_name, outpoint,
				blockheight, amt_msat);
}
struct chain_coin_mvt *new_coin_penalty_sat(const tal_t *ctx,
					    const char *account_name,
					    const struct bitcoin_txid *txid,
					    const struct bitcoin_outpoint *outpoint,
					    u32 blockheight,
					    struct amount_sat amount)
{
	struct amount_msat amt_msat;
	bool ok;

	ok = amount_sat_to_msat(&amt_msat, amount);
	assert(ok);

	return new_chain_coin_mvt(ctx, account_name,
				  txid, outpoint, NULL,
				  blockheight, PENALTY,
				  amt_msat, false);
}

struct chain_coin_mvt *new_coin_onchain_htlc_sat(const tal_t *ctx,
						 const char *account_name,
						 const struct bitcoin_txid *txid,
						 const struct bitcoin_outpoint *outpoint,
						 struct sha256 payment_hash,
						 u32 blockheight,
						 struct amount_sat amount,
						 bool is_credit)
{
	return new_chain_coin_mvt_sat(ctx, account_name,
				      txid, outpoint,
				      take(tal_dup(NULL, struct sha256,
						   &payment_hash)), blockheight,
				      ONCHAIN_HTLC, amount, is_credit);
}

struct chain_coin_mvt *new_coin_pushed(const tal_t *ctx,
				       const char *account_name,
				       const struct bitcoin_txid *txid,
				       u32 blockheight,
				       struct amount_msat amount)
{
	return new_chain_coin_mvt(ctx, account_name, txid, NULL,
				  NULL, blockheight, PUSHED, amount,
				  false);
}

struct coin_mvt *finalize_chain_mvt(const tal_t *ctx,
				    const struct chain_coin_mvt *chain_mvt,
				    const char *bip173_name,
				    u32 timestamp,
				    struct node_id *node_id,
				    s64 count)
{
	struct coin_mvt *mvt = tal(ctx, struct coin_mvt);

	mvt->account_id = tal_strndup(mvt, chain_mvt->account_name,
				      strlen(chain_mvt->account_name));
	mvt->bip173_name = tal_strndup(mvt, bip173_name, strlen(bip173_name));
	mvt->type = CHAIN_MVT;

	mvt->id.tx_txid = chain_mvt->tx_txid;
	mvt->id.outpoint = chain_mvt->outpoint;
	mvt->id.payment_hash = chain_mvt->payment_hash;
	mvt->tag = chain_mvt->tag;
	mvt->credit = chain_mvt->credit;
	mvt->debit = chain_mvt->debit;
	mvt->timestamp = timestamp;
	mvt->blockheight = chain_mvt->blockheight;
	mvt->version = COIN_MVT_VERSION;
	mvt->node_id = node_id;
	mvt->counter = count;

	return mvt;
}

struct coin_mvt *finalize_channel_mvt(const tal_t *ctx,
				      const struct channel_coin_mvt *chan_mvt,
				      const char *bip173_name,
				      u32 timestamp, struct node_id *node_id,
				      s64 count)
{
	struct coin_mvt *mvt = tal(ctx, struct coin_mvt);

	mvt->account_id = type_to_string(mvt, struct channel_id,
					 &chan_mvt->chan_id);
	mvt->bip173_name = tal_strndup(mvt, bip173_name, strlen(bip173_name));
	mvt->type = CHANNEL_MVT;
	mvt->id.payment_hash = chan_mvt->payment_hash;
	mvt->id.part_id = chan_mvt->part_id;
	mvt->id.tx_txid = NULL;
	mvt->id.outpoint = NULL;
	mvt->tag = chan_mvt->tag;
	mvt->credit = chan_mvt->credit;
	mvt->debit = chan_mvt->debit;
	mvt->timestamp = timestamp;
	/* channel movements don't have a blockheight */
	mvt->blockheight = 0;
	mvt->version = COIN_MVT_VERSION;
	mvt->node_id = node_id;
	mvt->counter = count;

	return mvt;
}

void towire_chain_coin_mvt(u8 **pptr, const struct chain_coin_mvt *mvt)
{
	if (mvt->account_name) {
		towire_u16(pptr, strlen(mvt->account_name));
		towire_u8_array(pptr, (u8 *)mvt->account_name, strlen(mvt->account_name));
	} else
		towire_u16(pptr, 0);
	towire_bitcoin_txid(pptr, cast_const(struct bitcoin_txid *, mvt->tx_txid));

	if (mvt->outpoint) {
		towire_bool(pptr, true);
		towire_bitcoin_outpoint(pptr, mvt->outpoint);
	} else
		towire_bool(pptr, false);
	if (mvt->payment_hash) {
		towire_bool(pptr, true);
		towire_sha256(pptr, mvt->payment_hash);
	} else
		towire_bool(pptr, false);
	towire_u32(pptr, mvt->blockheight);
	towire_u8(pptr, mvt->tag);
	towire_amount_msat(pptr, mvt->credit);
	towire_amount_msat(pptr, mvt->debit);
}

void fromwire_chain_coin_mvt(const u8 **cursor, size_t *max, struct chain_coin_mvt *mvt)
{
	u16 account_name_len;
	account_name_len = fromwire_u16(cursor, max);

	if (account_name_len) {
		mvt->account_name = tal_arr(mvt, char, account_name_len);
		fromwire_u8_array(cursor, max, (u8 *)mvt->account_name, account_name_len);
	} else
		mvt->account_name = NULL;

	mvt->tx_txid = tal(mvt, struct bitcoin_txid);
	fromwire_bitcoin_txid(cursor, max,
			      cast_const(struct bitcoin_txid *, mvt->tx_txid));
	if (fromwire_bool(cursor, max)) {
		/* Read into non-const version */
		struct bitcoin_outpoint *outpoint
			= tal(mvt, struct bitcoin_outpoint);
		fromwire_bitcoin_outpoint(cursor, max, outpoint);
		mvt->outpoint = outpoint;
	} else
		mvt->outpoint = NULL;
	if (fromwire_bool(cursor, max)) {
		mvt->payment_hash = tal(mvt, struct sha256);
		fromwire_sha256(cursor, max, mvt->payment_hash);
	} else
		mvt->payment_hash = NULL;
	mvt->blockheight = fromwire_u32(cursor, max);
	mvt->tag = fromwire_u8(cursor, max);
	mvt->credit = fromwire_amount_msat(cursor, max);
	mvt->debit = fromwire_amount_msat(cursor, max);
}
