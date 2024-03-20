#include "config.h"
#include <assert.h>
#include <bitcoin/tx.h>
#include <ccan/ccan/cast/cast.h>
#include <ccan/tal/str/str.h>
#include <common/coin_mvt.h>
#include <common/node_id.h>
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
	"stealable",
	"channel_proposed",
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
					      const struct sha256 *payment_hash TAKES,
					      u64 *part_id TAKES,
					      struct amount_msat amount,
					      const enum mvt_tag *tags TAKES,
					      bool is_credit,
					      struct amount_msat fees)
{
	struct channel_coin_mvt *mvt = tal(ctx, struct channel_coin_mvt);

	mvt->chan_id = *cid;
	mvt->payment_hash = tal_dup_or_null(mvt, struct sha256, payment_hash);
	mvt->part_id = tal_dup_or_null(mvt, u64, part_id);
	mvt->tags = tal_dup_talarr(mvt, enum mvt_tag, tags);

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
						 const char *account_name TAKES,
						 const struct bitcoin_txid *tx_txid,
						 const struct bitcoin_outpoint *outpoint,
						 const struct sha256 *payment_hash TAKES,
						 u32 blockheight,
						 enum mvt_tag *tags,
						 struct amount_msat amount,
						 bool is_credit,
						 struct amount_sat output_val,
						 u32 out_count)
{
	struct chain_coin_mvt *mvt = tal(ctx, struct chain_coin_mvt);

	mvt->account_name = tal_strdup_or_null(mvt, account_name);
	mvt->tx_txid = tx_txid;
	mvt->outpoint = outpoint;
	mvt->originating_acct = NULL;

	/* Most chain event's don't have a peer (only channel_opens) */
	mvt->peer_id = NULL;

	/* for htlc's that are filled onchain, we also have a
	 * preimage, NULL otherwise */
	mvt->payment_hash = tal_dup_or_null(mvt, struct sha256, payment_hash);
	mvt->blockheight = blockheight;

	mvt->tags = tal_dup_talarr(mvt, enum mvt_tag, tags);

	if (is_credit) {
		mvt->credit = amount;
		mvt->debit = AMOUNT_MSAT(0);
	} else {
		mvt->debit = amount;
		mvt->credit = AMOUNT_MSAT(0);
	}

	mvt->output_val = output_val;
	mvt->output_count = out_count;

	return mvt;
}

static struct chain_coin_mvt *new_chain_coin_mvt_sat(const tal_t *ctx,
						     const char *account_name,
						     const struct bitcoin_txid *tx_txid,
						     const struct bitcoin_outpoint *outpoint,
						     const struct sha256 *payment_hash TAKES,
						     u32 blockheight,
						     enum mvt_tag *tags TAKES,
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
				  amt_sat, 0);
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
				      blockheight,
				      take(new_tag_arr(NULL, tag)),
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
				      blockheight,
				      take(new_tag_arr(NULL, tag)),
				      amount, true);
}

struct chain_coin_mvt *new_coin_channel_close(const tal_t *ctx,
					      const struct bitcoin_txid *txid,
					      const struct bitcoin_outpoint *out,
					      u32 blockheight,
					      const struct amount_msat amount,
					      const struct amount_sat output_val,
					      u32 output_count)
{
	return new_chain_coin_mvt(ctx, NULL, txid,
				  out, NULL, blockheight,
				  take(new_tag_arr(NULL, CHANNEL_CLOSE)),
				  amount, false,
				  output_val,
				  output_count);
}

struct chain_coin_mvt *new_coin_channel_open_proposed(const tal_t *ctx,
						      const struct channel_id *chan_id,
						      const struct bitcoin_outpoint *out,
						      const struct node_id *peer_id,
						      const struct amount_msat amount,
						      const struct amount_sat output_val,
						      bool is_opener,
						      bool is_leased)
{
	struct chain_coin_mvt *mvt;

	mvt = new_chain_coin_mvt(ctx, NULL, NULL, out, NULL, 0,
				 take(new_tag_arr(NULL, CHANNEL_PROPOSED)),
				 amount, true, output_val, 0);
	mvt->account_name = fmt_channel_id(mvt, chan_id);
	mvt->peer_id = tal_dup(mvt, struct node_id, peer_id);

	/* If we're the opener, add to the tag list */
	if (is_opener)
		tal_arr_expand(&mvt->tags, OPENER);

	if (is_leased)
		tal_arr_expand(&mvt->tags, LEASED);

	return mvt;
}

struct chain_coin_mvt *new_coin_channel_open(const tal_t *ctx,
					     const struct channel_id *chan_id,
					     const struct bitcoin_outpoint *out,
					     const struct node_id *peer_id,
					     u32 blockheight,
					     const struct amount_msat amount,
					     const struct amount_sat output_val,
					     bool is_opener,
					     bool is_leased)
{
	struct chain_coin_mvt *mvt;

	mvt = new_chain_coin_mvt(ctx, NULL, NULL, out, NULL, blockheight,
				 take(new_tag_arr(NULL, CHANNEL_OPEN)), amount,
				 true, output_val, 0);
	mvt->account_name = fmt_channel_id(mvt, chan_id);
	mvt->peer_id = tal_dup(mvt, struct node_id, peer_id);

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
						const struct sha256 *payment_hash)
{
	return new_chain_coin_mvt_sat(ctx, NULL, NULL,
				      outpoint, payment_hash,
				      blockheight,
				      take(new_tag_arr(NULL, HTLC_FULFILL)),
				      amount, true);
}


struct chain_coin_mvt *new_onchain_htlc_withdraw(const tal_t *ctx,
						 const struct bitcoin_outpoint *outpoint,
						 u32 blockheight,
						 struct amount_sat amount,
						 const struct sha256 *payment_hash)
{
	/* An onchain htlc fulfillment to peer is a *deposit* of
	 * that output into their (external) account */
	return new_chain_coin_mvt_sat(ctx, EXTERNAL, NULL,
				      outpoint, payment_hash,
				      blockheight,
				      take(new_tag_arr(NULL, HTLC_FULFILL)),
				      amount, true);
}

struct chain_coin_mvt *new_coin_external_spend_tags(const tal_t *ctx,
						    const struct bitcoin_outpoint *outpoint,
						    const struct bitcoin_txid *txid,
						    u32 blockheight,
						    struct amount_sat amount,
						    enum mvt_tag *tags TAKES)
{
	return new_chain_coin_mvt(ctx, EXTERNAL, txid,
				  outpoint, NULL, blockheight,
				  take(tags),
				  AMOUNT_MSAT(0), true, amount, 0);
}

struct chain_coin_mvt *new_coin_external_spend(const tal_t *ctx,
					       const struct bitcoin_outpoint *outpoint,
					       const struct bitcoin_txid *txid,
					       u32 blockheight,
					       struct amount_sat amount,
					       enum mvt_tag tag)
{
	return new_coin_external_spend_tags(ctx, outpoint,
					    txid, blockheight, amount,
					    new_tag_arr(NULL, tag));
}

struct chain_coin_mvt *new_coin_external_deposit_tags(const tal_t *ctx,
						 const struct bitcoin_outpoint *outpoint,
						 u32 blockheight,
						 struct amount_sat amount,
						 enum mvt_tag *tags TAKES)
{
	return new_chain_coin_mvt_sat(ctx, EXTERNAL, NULL, outpoint, NULL,
				      blockheight, take(tags),
				      amount, true);
}


struct chain_coin_mvt *new_coin_external_deposit(const tal_t *ctx,
						 const struct bitcoin_outpoint *outpoint,
						 u32 blockheight,
						 struct amount_sat amount,
						 enum mvt_tag tag)
{
	return new_chain_coin_mvt_sat(ctx, EXTERNAL, NULL, outpoint, NULL,
				      blockheight, take(new_tag_arr(NULL, tag)),
				      amount, true);
}

bool chain_mvt_is_external(const struct chain_coin_mvt *mvt)
{
	return streq(mvt->account_name, EXTERNAL);
}

struct chain_coin_mvt *new_coin_wallet_deposit(const tal_t *ctx,
					       const struct bitcoin_outpoint *outpoint,
					       u32 blockheight,
					       struct amount_sat amount,
					       enum mvt_tag tag)
{
	return new_chain_coin_mvt_sat(ctx, WALLET, NULL,
				      outpoint, NULL,
				      blockheight, take(new_tag_arr(NULL, tag)),
				      amount, true);
}

struct chain_coin_mvt *new_coin_wallet_deposit_tagged(const tal_t *ctx,
						      const struct bitcoin_outpoint *outpoint,
						      u32 blockheight,
						      struct amount_sat amount,
						      enum mvt_tag *tags TAKES)
{
	return new_chain_coin_mvt_sat(ctx, WALLET, NULL,
				      outpoint, NULL,
				      blockheight,
				      take(tags),
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
				      blockheight, take(new_tag_arr(NULL, tag)),
				      amount, false);
}

struct channel_coin_mvt *new_coin_channel_push(const tal_t *ctx,
					       const struct channel_id *cid,
					       struct amount_msat amount,
					       enum mvt_tag tag,
					       bool is_credit)
{
	return new_channel_coin_mvt(ctx, cid, NULL,
				    NULL, amount,
				    take(new_tag_arr(NULL, tag)), is_credit,
				    AMOUNT_MSAT(0));
}

struct coin_mvt *finalize_chain_mvt(const tal_t *ctx,
				    const struct chain_coin_mvt *chain_mvt,
				    const char *hrp_name TAKES,
				    u32 timestamp,
				    struct node_id *node_id)
{
	struct coin_mvt *mvt = tal(ctx, struct coin_mvt);

	mvt->account_id = tal_strdup(mvt, chain_mvt->account_name);
	mvt->originating_acct =
		tal_strdup_or_null(mvt, chain_mvt->originating_acct);
	mvt->hrp_name = tal_strdup(mvt, hrp_name);
	mvt->type = CHAIN_MVT;

	mvt->id.tx_txid = chain_mvt->tx_txid;
	mvt->id.outpoint = chain_mvt->outpoint;
	mvt->id.payment_hash = chain_mvt->payment_hash;
	mvt->tags = tal_steal(mvt, chain_mvt->tags);
	mvt->credit = chain_mvt->credit;
	mvt->debit = chain_mvt->debit;

	mvt->output_val = tal(mvt, struct amount_sat);
	*mvt->output_val = chain_mvt->output_val;
	mvt->output_count = chain_mvt->output_count;
	mvt->fees = NULL;

	mvt->timestamp = timestamp;
	mvt->blockheight = chain_mvt->blockheight;
	mvt->version = COIN_MVT_VERSION;
	mvt->node_id = node_id;
	mvt->peer_id = chain_mvt->peer_id;

	return mvt;
}

struct coin_mvt *finalize_channel_mvt(const tal_t *ctx,
				      const struct channel_coin_mvt *chan_mvt,
				      const char *hrp_name TAKES,
				      u32 timestamp,
				      const struct node_id *node_id TAKES)
{
	struct coin_mvt *mvt = tal(ctx, struct coin_mvt);

	mvt->account_id = fmt_channel_id(mvt, &chan_mvt->chan_id);
	/* channel moves don't have external events! */
	mvt->originating_acct = NULL;
	mvt->hrp_name = tal_strdup(mvt, hrp_name);
	mvt->type = CHANNEL_MVT;
	mvt->id.payment_hash = chan_mvt->payment_hash;
	mvt->id.part_id = chan_mvt->part_id;
	mvt->id.tx_txid = NULL;
	mvt->id.outpoint = NULL;
	mvt->tags = tal_steal(mvt, chan_mvt->tags);
	mvt->credit = chan_mvt->credit;
	mvt->debit = chan_mvt->debit;
	mvt->output_val = NULL;
	mvt->output_count = 0;
	mvt->fees = tal(mvt, struct amount_msat);
	*mvt->fees = chan_mvt->fees;
	mvt->timestamp = timestamp;
	mvt->version = COIN_MVT_VERSION;
	mvt->node_id = tal_dup(mvt, struct node_id, node_id);
	mvt->peer_id = NULL;

	return mvt;
}

void towire_chain_coin_mvt(u8 **pptr, const struct chain_coin_mvt *mvt)
{
	if (mvt->account_name) {
		towire_bool(pptr, true);
		towire_wirestring(pptr, mvt->account_name);
	} else
		towire_bool(pptr, false);

	if (mvt->originating_acct) {
		towire_bool(pptr, true);
		towire_wirestring(pptr, mvt->originating_acct);
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
	towire_u32(pptr, mvt->output_count);

	if (mvt->peer_id) {
		towire_bool(pptr, true);
		towire_node_id(pptr, mvt->peer_id);
	} else
		towire_bool(pptr, false);
}

void fromwire_chain_coin_mvt(const u8 **cursor, size_t *max, struct chain_coin_mvt *mvt)
{
	if (fromwire_bool(cursor, max)) {
		mvt->account_name = fromwire_wirestring(mvt, cursor, max);
	} else
		mvt->account_name = NULL;

	if (fromwire_bool(cursor, max)) {
		mvt->originating_acct = fromwire_wirestring(mvt, cursor, max);
	} else
		mvt->originating_acct = NULL;

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
	mvt->output_count = fromwire_u32(cursor, max);

	if (fromwire_bool(cursor, max)) {
		struct node_id peer_id;
		fromwire_node_id(cursor, max, &peer_id);
		mvt->peer_id = tal_dup(mvt, struct node_id, &peer_id);
	} else
		mvt->peer_id = NULL;
}
