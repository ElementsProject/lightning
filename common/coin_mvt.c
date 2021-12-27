#include "config.h"
#include <assert.h>
#include <bitcoin/tx.h>
#include <ccan/ccan/cast/cast.h>
#include <ccan/tal/str/str.h>
#include <common/coin_mvt.h>
#include <common/type_to_string.h>
#include <wire/wire.h>

#define EXTERNAL "external"

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
	"pushed",
	"channel_open",
	"channel_close",
	"delayed_to_us",
	"htlc_timeout",
	"htlc_fulfill",
	"htlc_tx",
	"to_wallet",
	"ignored",
	"anchor",
	"to_them",
	"penalized",
	"stolen",
	"to_miner",
	"opener",
	"lease_fee",
	"leased",
};

const char *mvt_tag_str(enum mvt_tag tag)
{
	return mvt_tags[tag];
}

enum mvt_tag *new_tag_arr(const tal_t *ctx, enum mvt_tag tag)
{
	enum mvt_tag *tags = tal_arr(ctx, enum mvt_tag, 1);
	tags[0] = tag;
	return tags;
}

struct channel_coin_mvt *new_channel_coin_mvt(const tal_t *ctx,
					      const struct channel_id *cid,
					      struct sha256 payment_hash,
					      u64 *part_id,
					      struct amount_msat amount,
					      enum mvt_tag *tags STEALS,
					      bool is_credit,
					      struct amount_msat fees)
{
	struct channel_coin_mvt *mvt = tal(ctx, struct channel_coin_mvt);

	mvt->chan_id = *cid;
	mvt->payment_hash = tal_dup(mvt, struct sha256, &payment_hash);
	mvt->part_id = part_id;
	mvt->tags = tal_steal(mvt, tags);

	if (is_credit) {
		mvt->credit = amount;
		mvt->debit = AMOUNT_MSAT(0);
	} else {
		mvt->debit = amount;
		mvt->credit = AMOUNT_MSAT(0);
	}

	mvt->fees = fees;

	return mvt;
}

static struct chain_coin_mvt *new_chain_coin_mvt(const tal_t *ctx,
						 const char *account_name,
						 const struct bitcoin_txid *tx_txid,
						 const struct bitcoin_outpoint *outpoint,
						 const struct sha256 *payment_hash TAKES,
						 u32 blockheight,
						 enum mvt_tag *tags STEALS,
						 struct amount_msat amount,
						 bool is_credit,
						 struct amount_sat output_val)
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
	mvt->payment_hash = tal_dup_or_null(mvt, struct sha256, payment_hash);
	mvt->blockheight = blockheight;

	mvt->tags = tal_steal(mvt, tags);

	if (is_credit) {
		mvt->credit = amount;
		mvt->debit = AMOUNT_MSAT(0);
	} else {
		mvt->debit = amount;
		mvt->credit = AMOUNT_MSAT(0);
	}
	mvt->output_val = output_val;

	return mvt;
}

static struct chain_coin_mvt *new_chain_coin_mvt_sat(const tal_t *ctx,
						     const char *account_name,
						     const struct bitcoin_txid *tx_txid,
						     const struct bitcoin_outpoint *outpoint,
						     const struct sha256 *payment_hash TAKES,
						     u32 blockheight,
						     enum mvt_tag *tags,
						     struct amount_sat amt_sat,
						     bool is_credit)
{
	struct amount_msat amt_msat;
	bool ok;
	ok = amount_sat_to_msat(&amt_msat, amt_sat);
	assert(ok);

	return new_chain_coin_mvt(ctx, account_name, tx_txid,
				  outpoint, payment_hash,
				  blockheight, tags, amt_msat, is_credit,
				  /* All amounts that are sat are
				   * on-chain output values */
				  amt_sat);
}

struct chain_coin_mvt *new_onchaind_withdraw(const tal_t *ctx,
					     const struct bitcoin_outpoint *outpoint,
					     const struct bitcoin_txid *spend_txid,
					     u32 blockheight,
					     struct amount_sat amount,
					     enum mvt_tag tag)
{
	return new_chain_coin_mvt_sat(ctx, NULL, spend_txid,
				      outpoint, NULL,
				      blockheight, new_tag_arr(ctx, tag),
				      amount, false);
}

struct chain_coin_mvt *new_onchaind_deposit(const tal_t *ctx,
					    const struct bitcoin_outpoint *outpoint,
					    u32 blockheight,
					    struct amount_sat amount,
					    enum mvt_tag tag)
{
	return new_chain_coin_mvt_sat(ctx, NULL, NULL,
				      outpoint, NULL,
				      blockheight, new_tag_arr(ctx, tag),
				      amount, true);
}

struct chain_coin_mvt *new_coin_channel_close(const tal_t *ctx,
					      const struct bitcoin_txid *txid,
					      const struct bitcoin_outpoint *out,
					      u32 blockheight,
					      const struct amount_msat amount,
					      const struct amount_sat output_val)
{
	return new_chain_coin_mvt(ctx, NULL, txid,
				  out, NULL, blockheight,
				  new_tag_arr(ctx, CHANNEL_CLOSE),
				  amount, false,
				  output_val);
}

struct chain_coin_mvt *new_coin_channel_open(const tal_t *ctx,
					     const struct channel_id *chan_id,
					     const struct bitcoin_outpoint *out,
					     u32 blockheight,
					     const struct amount_msat amount,
					     const struct amount_sat output_val,
					     bool is_opener,
					     bool is_leased)
{
	struct chain_coin_mvt *mvt;

	mvt = new_chain_coin_mvt(ctx, NULL, NULL, out, NULL, blockheight,
				 new_tag_arr(ctx, CHANNEL_OPEN), amount,
				 true, output_val);
	mvt->account_name = type_to_string(mvt, struct channel_id, chan_id);

	/* If we're the opener, add to the tag list */
	if (is_opener)
		tal_arr_expand(&mvt->tags, OPENER);

	if (is_leased)
		tal_arr_expand(&mvt->tags, LEASED);

	return mvt;
}

struct chain_coin_mvt *new_onchain_htlc_deposit(const tal_t *ctx,
						const struct bitcoin_outpoint *outpoint,
						u32 blockheight,
						struct amount_sat amount,
						struct sha256 *payment_hash)
{
	return new_chain_coin_mvt_sat(ctx, NULL, NULL,
				      outpoint, payment_hash,
				      blockheight,
				      new_tag_arr(ctx, HTLC_FULFILL),
				      amount, true);
}


struct chain_coin_mvt *new_onchain_htlc_withdraw(const tal_t *ctx,
						 const struct bitcoin_outpoint *outpoint,
						 u32 blockheight,
						 struct amount_sat amount,
						 struct sha256 *payment_hash)
{
	/* An onchain htlc fulfillment to peer is a *deposit* of
	 * that output into their (external) account */
	return new_chain_coin_mvt_sat(ctx, EXTERNAL, NULL,
				      outpoint, payment_hash,
				      blockheight,
				      new_tag_arr(ctx, HTLC_FULFILL),
				      amount, false);
}

struct chain_coin_mvt *new_coin_external_spend(const tal_t *ctx,
					       const struct bitcoin_outpoint *outpoint,
					       const struct bitcoin_txid *txid,
					       u32 blockheight,
					       struct amount_sat amount,
					       enum mvt_tag tag)
{
	return new_chain_coin_mvt(ctx, EXTERNAL, txid,
				  outpoint, NULL, blockheight,
				  new_tag_arr(ctx, tag),
				  AMOUNT_MSAT(0), true, amount);
}

struct chain_coin_mvt *new_coin_external_deposit(const tal_t *ctx,
						 const struct bitcoin_outpoint *outpoint,
						 u32 blockheight,
						 struct amount_sat amount,
						 enum mvt_tag tag)
{
	return new_chain_coin_mvt(ctx, EXTERNAL, NULL,
				  outpoint, NULL,
				  blockheight,
				  new_tag_arr(ctx, tag),
				  AMOUNT_MSAT(0), true, amount);
}

struct chain_coin_mvt *new_coin_wallet_deposit(const tal_t *ctx,
					       const struct bitcoin_outpoint *outpoint,
					       u32 blockheight,
					       struct amount_sat amount,
					       enum mvt_tag tag)
{
	return new_chain_coin_mvt_sat(ctx, WALLET, NULL,
				      outpoint, NULL,
				      blockheight, new_tag_arr(ctx, tag),
				      amount, true);
}

struct chain_coin_mvt *new_coin_wallet_withdraw(const tal_t *ctx,
						const struct bitcoin_txid *spend_txid,
						const struct bitcoin_outpoint *outpoint,
						u32 blockheight,
						struct amount_sat amount,
						enum mvt_tag tag)
{
	return new_chain_coin_mvt_sat(ctx, WALLET, spend_txid,
				      outpoint, NULL,
				      blockheight, new_tag_arr(ctx, tag),
				      amount, false);
}

struct chain_coin_mvt *new_coin_penalty_sat(const tal_t *ctx,
					    const char *account_name,
					    const struct bitcoin_txid *txid,
					    const struct bitcoin_outpoint *outpoint,
					    u32 blockheight,
					    struct amount_sat amount)
{
	return new_chain_coin_mvt_sat(ctx, account_name,
				      txid, outpoint, NULL,
				      blockheight,
				      new_tag_arr(ctx, PENALTY),
				      amount, false);
}

struct channel_coin_mvt *new_coin_channel_push(const tal_t *ctx,
					       const struct channel_id *cid,
					       struct amount_msat amount,
					       enum mvt_tag tag,
					       bool is_credit)
{
	struct sha256 empty_hash;
	/* Use a 0'd out payment hash */
	memset(&empty_hash, 0, sizeof(empty_hash));

	return new_channel_coin_mvt(ctx, cid, empty_hash,
				    NULL, amount,
				    new_tag_arr(ctx, tag), is_credit,
				    AMOUNT_MSAT(0));
}

struct coin_mvt *finalize_chain_mvt(const tal_t *ctx,
				    const struct chain_coin_mvt *chain_mvt,
				    const char *bip173_name,
				    u32 timestamp,
				    struct node_id *node_id)
{
	struct coin_mvt *mvt = tal(ctx, struct coin_mvt);

	mvt->account_id = tal_strndup(mvt, chain_mvt->account_name,
				      strlen(chain_mvt->account_name));
	mvt->bip173_name = tal_strndup(mvt, bip173_name, strlen(bip173_name));
	mvt->type = CHAIN_MVT;

	mvt->id.tx_txid = chain_mvt->tx_txid;
	mvt->id.outpoint = chain_mvt->outpoint;
	mvt->id.payment_hash = chain_mvt->payment_hash;
	mvt->tags = tal_steal(mvt, chain_mvt->tags);
	mvt->credit = chain_mvt->credit;
	mvt->debit = chain_mvt->debit;

	mvt->output_val = tal(mvt, struct amount_sat);
	*mvt->output_val = chain_mvt->output_val;
	mvt->fees = NULL;

	mvt->timestamp = timestamp;
	mvt->blockheight = chain_mvt->blockheight;
	mvt->version = COIN_MVT_VERSION;
	mvt->node_id = node_id;

	return mvt;
}

struct coin_mvt *finalize_channel_mvt(const tal_t *ctx,
				      const struct channel_coin_mvt *chan_mvt,
				      const char *bip173_name,
				      u32 timestamp, struct node_id *node_id)
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
	mvt->tags = tal_steal(mvt, chan_mvt->tags);
	mvt->credit = chan_mvt->credit;
	mvt->debit = chan_mvt->debit;
	mvt->output_val = NULL;
	mvt->fees = tal(mvt, struct amount_msat);
	*mvt->fees = chan_mvt->fees;
	mvt->timestamp = timestamp;
	/* channel movements don't have a blockheight */
	mvt->blockheight = 0;
	mvt->version = COIN_MVT_VERSION;
	mvt->node_id = node_id;

	return mvt;
}

void towire_chain_coin_mvt(u8 **pptr, const struct chain_coin_mvt *mvt)
{
	if (mvt->account_name) {
		towire_bool(pptr, true);
		towire_wirestring(pptr, mvt->account_name);
	} else
		towire_bool(pptr, false);

	towire_bitcoin_outpoint(pptr, mvt->outpoint);

	if (mvt->tx_txid) {
		towire_bool(pptr, true);
		towire_bitcoin_txid(pptr, cast_const(struct bitcoin_txid *, mvt->tx_txid));

	} else
		towire_bool(pptr, false);
	if (mvt->payment_hash) {
		towire_bool(pptr, true);
		towire_sha256(pptr, mvt->payment_hash);
	} else
		towire_bool(pptr, false);
	towire_u32(pptr, mvt->blockheight);

	towire_u32(pptr, tal_count(mvt->tags));
	for (size_t i = 0; i < tal_count(mvt->tags); i++)
		towire_u8(pptr, mvt->tags[i]);

	towire_amount_msat(pptr, mvt->credit);
	towire_amount_msat(pptr, mvt->debit);
	towire_amount_sat(pptr, mvt->output_val);
}

void fromwire_chain_coin_mvt(const u8 **cursor, size_t *max, struct chain_coin_mvt *mvt)
{
	if (fromwire_bool(cursor, max)) {
		mvt->account_name = fromwire_wirestring(mvt, cursor, max);
	} else
		mvt->account_name = NULL;

	/* Read into non-const version */
	struct bitcoin_outpoint *outpoint
		= tal(mvt, struct bitcoin_outpoint);
	fromwire_bitcoin_outpoint(cursor, max, outpoint);
	mvt->outpoint = outpoint;

	if (fromwire_bool(cursor, max)) {
		mvt->tx_txid = tal(mvt, struct bitcoin_txid);
		fromwire_bitcoin_txid(cursor, max,
				      cast_const(struct bitcoin_txid *, mvt->tx_txid));
	} else
		mvt->tx_txid = NULL;

	if (fromwire_bool(cursor, max)) {
		mvt->payment_hash = tal(mvt, struct sha256);
		fromwire_sha256(cursor, max, mvt->payment_hash);
	} else
		mvt->payment_hash = NULL;
	mvt->blockheight = fromwire_u32(cursor, max);

	u32 tags_len = fromwire_u32(cursor, max);
	mvt->tags = tal_arr(mvt, enum mvt_tag, tags_len);
	for (size_t i = 0; i < tags_len; i++)
		mvt->tags[i] = fromwire_u8(cursor, max);

	mvt->credit = fromwire_amount_msat(cursor, max);
	mvt->debit = fromwire_amount_msat(cursor, max);
	mvt->output_val = fromwire_amount_sat(cursor, max);
}
