#include "config.h"
#include <assert.h>
#include <bitcoin/tx.h>
#include <ccan/ccan/cast/cast.h>
#include <ccan/tal/str/str.h>
#include <common/coin_mvt.h>
#include <common/node_id.h>
#include <wire/wire.h>

#define EXTERNAL "external"

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
	"splice",
};

static bool mvt_tag_is_primary(enum mvt_tag tag)
{
	switch (tag) {
	case MVT_DEPOSIT:
		return true;
	case MVT_WITHDRAWAL:
		return true;
	case MVT_PENALTY:
		return true;
	case MVT_INVOICE:
		return true;
	case MVT_ROUTED:
		return true;
	case MVT_PUSHED:
		return true;
	case MVT_CHANNEL_OPEN:
		return true;
	case MVT_CHANNEL_CLOSE:
		return true;
	case MVT_CHANNEL_TO_US:
		return true;
	case MVT_HTLC_TIMEOUT:
		return true;
	case MVT_HTLC_FULFILL:
		return true;
	case MVT_HTLC_TX:
		return true;
	case MVT_TO_WALLET:
		return true;
	case MVT_ANCHOR:
		return true;
	case MVT_TO_THEM:
		return true;
	case MVT_PENALIZED:
		return true;
	case MVT_STOLEN:
		return true;
	case MVT_TO_MINER:
		return true;
	case MVT_OPENER:
		return false;
	case MVT_LEASE_FEE:
		return true;
	case MVT_LEASED:
		return false;
	case MVT_STEALABLE:
		return false;
	case MVT_CHANNEL_PROPOSED:
		return true;
	case MVT_SPLICE:
		return false;
	}
	abort();
}

const char *mvt_tag_str(enum mvt_tag tag)
{
	return mvt_tags[tag];
}

enum mvt_tag *new_tag_arr(const tal_t *ctx, enum mvt_tag tag)
{
	enum mvt_tag *tags = tal_arr(ctx, enum mvt_tag, 1);
	assert(mvt_tag_is_primary(tag));
	tags[0] = tag;
	return tags;
}

static void check_tags(const enum mvt_tag *tags)
{
	assert(tal_count(tags) > 0);
	assert(mvt_tag_is_primary(tags[0]));
	for (size_t i = 1; i < tal_count(tags); i++)
		assert(!mvt_tag_is_primary(tags[i]));
}

void set_mvt_account_id(struct mvt_account_id *acct_id,
			const struct channel *channel,
			const char *account_name TAKES)
{
	if (channel) {
		assert(account_name == NULL);
		acct_id->channel = channel;
		acct_id->alt_account = NULL;
	} else {
		assert(account_name != NULL);
		acct_id->channel = NULL;
		acct_id->alt_account = tal_strdup(acct_id, account_name);
	}
}

struct mvt_account_id *new_mvt_account_id(const tal_t *ctx,
					  const struct channel *channel,
					  const char *account_name TAKES)
{
	struct mvt_account_id *acct = tal(ctx, struct mvt_account_id);
	set_mvt_account_id(acct, channel, account_name);
	return acct;
}

struct channel_coin_mvt *new_channel_coin_mvt(const tal_t *ctx,
					      const struct channel *channel,
					      const struct sha256 *payment_hash TAKES,
					      const u64 *part_id,
					      const u64 *group_id,
					      enum coin_mvt_dir direction,
					      struct amount_msat amount,
					      const enum mvt_tag *tags TAKES,
					      struct amount_msat fees)
{
	struct channel_coin_mvt *mvt = tal(ctx, struct channel_coin_mvt);

	set_mvt_account_id(&mvt->account, channel, NULL);
	mvt->payment_hash = tal_dup_or_null(mvt, struct sha256, payment_hash);
	if (!part_id) {
		assert(!group_id);
		mvt->part_and_group = NULL;
	} else {
		/* Temporary for non-const */
		struct channel_coin_mvt_id *pg;
		mvt->part_and_group = pg = tal(mvt, struct channel_coin_mvt_id);
		pg->part_id = *part_id;
		pg->group_id = *group_id;
	}

	check_tags(tags);
	mvt->tags = tal_dup_talarr(mvt, enum mvt_tag, tags);

	mvt->fees = fees;
	switch (direction) {
	case COIN_CREDIT:
		mvt->credit = amount;
		mvt->debit = AMOUNT_MSAT(0);
		return mvt;
	case COIN_DEBIT:
		mvt->debit = amount;
		mvt->credit = AMOUNT_MSAT(0);
		return mvt;
	}

	abort();
}

static struct chain_coin_mvt *new_chain_coin_mvt(const tal_t *ctx,
						 const struct channel *channel,
						 const char *account_name TAKES,
						 const struct bitcoin_txid *tx_txid,
						 const struct bitcoin_outpoint *outpoint,
						 const struct sha256 *payment_hash TAKES,
						 u32 blockheight,
						 enum mvt_tag *tags,
						 enum coin_mvt_dir direction,
						 struct amount_msat amount,
						 struct amount_sat output_val,
						 u32 out_count)
{
	struct chain_coin_mvt *mvt = tal(ctx, struct chain_coin_mvt);

	set_mvt_account_id(&mvt->account, channel, account_name);
	mvt->tx_txid = tx_txid;
	mvt->outpoint = outpoint;
	mvt->originating_acct = NULL;

	/* Most chain event's don't have a peer (only channel_opens) */
	mvt->peer_id = NULL;

	/* for htlc's that are filled onchain, we also have a
	 * preimage, NULL otherwise */
	mvt->payment_hash = tal_dup_or_null(mvt, struct sha256, payment_hash);
	mvt->blockheight = blockheight;

	check_tags(tags);
	mvt->tags = tal_dup_talarr(mvt, enum mvt_tag, tags);

	mvt->output_val = output_val;
	mvt->output_count = out_count;

	switch (direction) {
	case COIN_CREDIT:
		mvt->credit = amount;
		mvt->debit = AMOUNT_MSAT(0);
		return mvt;
	case COIN_DEBIT:
		mvt->debit = amount;
		mvt->credit = AMOUNT_MSAT(0);
		return mvt;
	}
	abort();
}

static struct chain_coin_mvt *new_chain_coin_mvt_sat(const tal_t *ctx,
						     const struct channel *channel,
						     const char *account_name TAKES,
						     const struct bitcoin_txid *tx_txid,
						     const struct bitcoin_outpoint *outpoint,
						     const struct sha256 *payment_hash TAKES,
						     u32 blockheight,
						     enum mvt_tag *tags TAKES,
						     enum coin_mvt_dir direction,
						     struct amount_sat amt_sat)
{
	struct amount_msat amt_msat;
	bool ok;
	ok = amount_sat_to_msat(&amt_msat, amt_sat);
	assert(ok);

	return new_chain_coin_mvt(ctx, channel, account_name, tx_txid,
				  outpoint, payment_hash,
				  blockheight, tags, direction, amt_msat,
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
	return new_chain_coin_mvt_sat(ctx, NULL, "", spend_txid,
				      outpoint, NULL,
				      blockheight,
				      take(new_tag_arr(NULL, tag)),
				      COIN_DEBIT, amount);
}

struct chain_coin_mvt *new_onchaind_deposit(const tal_t *ctx,
					    const struct bitcoin_outpoint *outpoint,
					    u32 blockheight,
					    struct amount_sat amount,
					    enum mvt_tag tag)
{
	return new_chain_coin_mvt_sat(ctx, NULL, "", NULL,
				      outpoint, NULL,
				      blockheight,
				      take(new_tag_arr(NULL, tag)),
				      COIN_CREDIT, amount);
}

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
{
	struct chain_coin_mvt *mvt;
	enum mvt_tag *tags = new_tag_arr(NULL, MVT_CHANNEL_CLOSE);

	if (is_splice)
		tal_arr_expand(&tags, MVT_SPLICE);

	mvt = new_chain_coin_mvt(ctx, channel, alt_account, txid,
				 out, NULL, blockheight,
				 take(tags),
				 COIN_DEBIT, amount,
				 output_val,
				 output_count);
	return mvt;
}

struct chain_coin_mvt *new_coin_channel_open_proposed(const tal_t *ctx,
						      const struct channel *channel,
						      const struct bitcoin_outpoint *out,
						      const struct node_id *peer_id,
						      const struct amount_msat amount,
						      const struct amount_sat output_val,
						      bool is_opener,
						      bool is_leased)
{
	struct chain_coin_mvt *mvt;

	mvt = new_chain_coin_mvt(ctx, channel, NULL, NULL, out, NULL, 0,
				 take(new_tag_arr(NULL, MVT_CHANNEL_PROPOSED)),
				 COIN_CREDIT, amount, output_val, 0);
	mvt->peer_id = tal_dup(mvt, struct node_id, peer_id);

	/* If we're the opener, add to the tag list */
	if (is_opener)
		tal_arr_expand(&mvt->tags, MVT_OPENER);

	if (is_leased)
		tal_arr_expand(&mvt->tags, MVT_LEASED);

	return mvt;
}

struct chain_coin_mvt *new_coin_channel_open(const tal_t *ctx,
					     const struct channel *channel,
					     const struct bitcoin_outpoint *out,
					     const struct node_id *peer_id,
					     u32 blockheight,
					     const struct amount_msat amount,
					     const struct amount_sat output_val,
					     bool is_opener,
					     bool is_leased)
{
	struct chain_coin_mvt *mvt;

	mvt = new_chain_coin_mvt(ctx, channel, NULL, NULL, out, NULL, blockheight,
				 take(new_tag_arr(NULL, MVT_CHANNEL_OPEN)),
				 COIN_CREDIT, amount,
				 output_val, 0);
	mvt->peer_id = tal_dup(mvt, struct node_id, peer_id);

	/* If we're the opener, add to the tag list */
	if (is_opener)
		tal_arr_expand(&mvt->tags, MVT_OPENER);

	if (is_leased)
		tal_arr_expand(&mvt->tags, MVT_LEASED);

	return mvt;
}

struct chain_coin_mvt *new_onchain_htlc_deposit(const tal_t *ctx,
						const struct bitcoin_outpoint *outpoint,
						u32 blockheight,
						struct amount_sat amount,
						const struct sha256 *payment_hash)
{
	return new_chain_coin_mvt_sat(ctx, NULL, "", NULL,
				      outpoint, payment_hash,
				      blockheight,
				      take(new_tag_arr(NULL, MVT_HTLC_FULFILL)),
				      COIN_CREDIT, amount);
}


struct chain_coin_mvt *new_onchain_htlc_withdraw(const tal_t *ctx,
						 const struct bitcoin_outpoint *outpoint,
						 u32 blockheight,
						 struct amount_sat amount,
						 const struct sha256 *payment_hash)
{
	/* An onchain htlc fulfillment to peer is a *deposit* of
	 * that output into their (external) account */
	return new_chain_coin_mvt_sat(ctx, NULL, EXTERNAL, NULL,
				      outpoint, payment_hash,
				      blockheight,
				      take(new_tag_arr(NULL, MVT_HTLC_FULFILL)),
				      COIN_CREDIT, amount);
}

struct chain_coin_mvt *new_coin_external_spend_tags(const tal_t *ctx,
						    const struct bitcoin_outpoint *outpoint,
						    const struct bitcoin_txid *txid,
						    u32 blockheight,
						    struct amount_sat amount,
						    enum mvt_tag *tags TAKES)
{
	return new_chain_coin_mvt(ctx, NULL, EXTERNAL, txid,
				  outpoint, NULL, blockheight,
				  take(tags),
				  COIN_CREDIT, AMOUNT_MSAT(0), amount, 0);
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
	return new_chain_coin_mvt_sat(ctx, NULL, EXTERNAL, NULL, outpoint, NULL,
				      blockheight, take(tags),
				      COIN_CREDIT, amount);
}


struct chain_coin_mvt *new_coin_external_deposit(const tal_t *ctx,
						 const struct bitcoin_outpoint *outpoint,
						 u32 blockheight,
						 struct amount_sat amount,
						 enum mvt_tag tag)
{
	return new_chain_coin_mvt_sat(ctx, NULL, EXTERNAL, NULL, outpoint, NULL,
				      blockheight, take(new_tag_arr(NULL, tag)),
				      COIN_CREDIT, amount);
}

bool chain_mvt_is_external(const struct chain_coin_mvt *mvt)
{
	return mvt->account.alt_account && streq(mvt->account.alt_account, EXTERNAL);
}

struct chain_coin_mvt *new_coin_wallet_deposit(const tal_t *ctx,
					       const struct bitcoin_outpoint *outpoint,
					       u32 blockheight,
					       struct amount_sat amount,
					       enum mvt_tag tag)
{
	return new_chain_coin_mvt_sat(ctx, NULL, WALLET, NULL,
				      outpoint, NULL,
				      blockheight, take(new_tag_arr(NULL, tag)),
				      COIN_CREDIT, amount);
}

struct chain_coin_mvt *new_coin_wallet_deposit_tagged(const tal_t *ctx,
						      const struct bitcoin_outpoint *outpoint,
						      u32 blockheight,
						      struct amount_sat amount,
						      enum mvt_tag *tags TAKES)
{
	return new_chain_coin_mvt_sat(ctx, NULL, WALLET, NULL,
				      outpoint, NULL,
				      blockheight,
				      take(tags),
				      COIN_CREDIT, amount);
}

struct chain_coin_mvt *new_coin_wallet_withdraw(const tal_t *ctx,
						const struct bitcoin_txid *spend_txid,
						const struct bitcoin_outpoint *outpoint,
						u32 blockheight,
						struct amount_sat amount,
						enum mvt_tag tag)
{
	return new_chain_coin_mvt_sat(ctx, NULL, WALLET, spend_txid,
				      outpoint, NULL,
				      blockheight, take(new_tag_arr(NULL, tag)),
				      COIN_DEBIT, amount);
}

struct channel_coin_mvt *new_coin_channel_push(const tal_t *ctx,
					       const struct channel *channel,
					       enum coin_mvt_dir direction,
					       struct amount_msat amount,
					       enum mvt_tag tag)
{
	return new_channel_coin_mvt(ctx, channel, NULL,
				    NULL, NULL, direction, amount,
				    take(new_tag_arr(NULL, tag)),
				    AMOUNT_MSAT(0));
}

const char **mvt_tag_strs(const tal_t *ctx, const enum mvt_tag *tags)
{
	const char **strs = tal_arr(ctx, const char *, 0);
	for (size_t i = 0; i < tal_count(tags); i++)
		tal_arr_expand(&strs, mvt_tag_str(tags[i]));
	return strs;
}
/* This is used solely by onchaind.  It always uses alt_account, with "" meaning
 * the channel itself. */
void towire_chain_coin_mvt(u8 **pptr, const struct chain_coin_mvt *mvt)
{
	towire_wirestring(pptr, mvt->account.alt_account);
	assert(!mvt->originating_acct);

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
	set_mvt_account_id(&mvt->account, NULL, take(fromwire_wirestring(NULL, cursor, max)));
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
		struct sha256 *ph;
		mvt->payment_hash = ph = tal(mvt, struct sha256);
		fromwire_sha256(cursor, max, ph);
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
