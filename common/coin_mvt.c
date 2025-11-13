#include "config.h"
#include <assert.h>
#include <ccan/bitops/bitops.h>
#include <ccan/ccan/cast/cast.h>
#include <ccan/tal/str/str.h>
#include <common/clock_time.h>
#include <common/coin_mvt.h>
#include <common/node_id.h>
#include <common/utils.h>
#include <wire/wire.h>

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
	"penalty_adj",
	"journal_entry",
	"foreign",
	"ignored",
};

#define PRIMARY_TAG_BITS ((1ULL << MVT_DEPOSIT) |	\
			  (1ULL << MVT_WITHDRAWAL) |	\
			  (1ULL << MVT_PENALTY) |	\
			  (1ULL << MVT_INVOICE) |	\
			  (1ULL << MVT_ROUTED) |	\
			  (1ULL << MVT_PUSHED) |	\
			  (1ULL << MVT_CHANNEL_OPEN) |	\
			  (1ULL << MVT_CHANNEL_CLOSE) |	\
			  (1ULL << MVT_CHANNEL_TO_US) |	\
			  (1ULL << MVT_HTLC_TIMEOUT) |	\
			  (1ULL << MVT_HTLC_FULFILL) |	\
			  (1ULL << MVT_HTLC_TX) |	\
			  (1ULL << MVT_TO_WALLET) |	\
			  (1ULL << MVT_ANCHOR) |	\
			  (1ULL << MVT_TO_THEM) |	\
			  (1ULL << MVT_PENALIZED) |	\
			  (1ULL << MVT_STOLEN) |	\
			  (1ULL << MVT_TO_MINER) |	\
			  (1ULL << MVT_LEASE_FEE) |	\
			  (1ULL << MVT_PENALTY_ADJ) |	\
			  (1ULL << MVT_JOURNAL) |	\
			  (1ULL << MVT_CHANNEL_PROPOSED) | \
			  (1ULL << MVT_IGNORED))

static enum mvt_tag mvt_tag_in_db(enum mvt_tag mvt_tag)
{
	switch (mvt_tag) {
	case MVT_DEPOSIT:
		BUILD_ASSERT(MVT_DEPOSIT == 0);
		return mvt_tag;
	case MVT_WITHDRAWAL:
		BUILD_ASSERT(MVT_WITHDRAWAL == 1);
		return mvt_tag;
	case MVT_PENALTY:
		BUILD_ASSERT(MVT_PENALTY == 2);
		return mvt_tag;
	case MVT_INVOICE:
		BUILD_ASSERT(MVT_INVOICE == 3);
		return mvt_tag;
	case MVT_ROUTED:
		BUILD_ASSERT(MVT_ROUTED == 4);
		return mvt_tag;
	case MVT_PUSHED:
		BUILD_ASSERT(MVT_PUSHED == 5);
		return mvt_tag;
	case MVT_CHANNEL_OPEN:
		BUILD_ASSERT(MVT_CHANNEL_OPEN == 6);
		return mvt_tag;
	case MVT_CHANNEL_CLOSE:
		BUILD_ASSERT(MVT_CHANNEL_CLOSE == 7);
		return mvt_tag;
	case MVT_CHANNEL_TO_US:
		BUILD_ASSERT(MVT_CHANNEL_TO_US == 8);
		return mvt_tag;
	case MVT_HTLC_TIMEOUT:
		BUILD_ASSERT(MVT_HTLC_TIMEOUT == 9);
		return mvt_tag;
	case MVT_HTLC_FULFILL:
		BUILD_ASSERT(MVT_HTLC_FULFILL == 10);
		return mvt_tag;
	case MVT_HTLC_TX:
		BUILD_ASSERT(MVT_HTLC_TX == 11);
		return mvt_tag;
	case MVT_TO_WALLET:
		BUILD_ASSERT(MVT_TO_WALLET == 12);
		return mvt_tag;
	case MVT_ANCHOR:
		BUILD_ASSERT(MVT_ANCHOR == 13);
		return mvt_tag;
	case MVT_TO_THEM:
		BUILD_ASSERT(MVT_TO_THEM == 14);
		return mvt_tag;
	case MVT_PENALIZED:
		BUILD_ASSERT(MVT_PENALIZED == 15);
		return mvt_tag;
	case MVT_STOLEN:
		BUILD_ASSERT(MVT_STOLEN == 16);
		return mvt_tag;
	case MVT_TO_MINER:
		BUILD_ASSERT(MVT_TO_MINER == 17);
		return mvt_tag;
	case MVT_OPENER:
		BUILD_ASSERT(MVT_OPENER == 18);
		return mvt_tag;
	case MVT_LEASE_FEE:
		BUILD_ASSERT(MVT_LEASE_FEE == 19);
		return mvt_tag;
	case MVT_LEASED:
		BUILD_ASSERT(MVT_LEASED == 20);
		return mvt_tag;
	case MVT_STEALABLE:
		BUILD_ASSERT(MVT_STEALABLE == 21);
		return mvt_tag;
	case MVT_CHANNEL_PROPOSED:
		BUILD_ASSERT(MVT_CHANNEL_PROPOSED == 22);
		return mvt_tag;
	case MVT_SPLICE:
		BUILD_ASSERT(MVT_SPLICE == 23);
		return mvt_tag;
	case MVT_PENALTY_ADJ:
		BUILD_ASSERT(MVT_PENALTY_ADJ == 24);
		return mvt_tag;
	case MVT_JOURNAL:
		BUILD_ASSERT(MVT_JOURNAL == 25);
		return mvt_tag;
	case MVT_FOREIGN:
		BUILD_ASSERT(MVT_FOREIGN == 26);
		return mvt_tag;
	case MVT_IGNORED:
		BUILD_ASSERT(MVT_IGNORED == 27);
		return mvt_tag;
	}
	abort();
}

/* This puts the coin movements in order */
u64 coinmvt_current_time(void)
{
	return clock_time_progresses().ts.tv_sec;
}

const char *mvt_tag_str(enum mvt_tag tag)
{
	assert((unsigned)tag < NUM_MVT_TAGS);
	return mvt_tags[tag];
}

void mvt_tag_set(struct mvt_tags *tags, enum mvt_tag tag)
{
	u64 bitnum = mvt_tag_in_db(tag);
	assert(bitnum < NUM_MVT_TAGS);
	/* Not already set! */
	assert((tags->bits & (1ULL << bitnum)) == 0);
	tags->bits |= (1ULL << bitnum);
}

bool mvt_tags_valid(struct mvt_tags tags)
{
	u64 primaries = (tags.bits & PRIMARY_TAG_BITS);
	/* Must have exactly one primary. */
	if (!primaries)
		return false;
	if ((primaries & (primaries - 1)) != 0)
		return false;
	return tags.bits < (1ULL << NUM_MVT_TAGS);
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

enum mvt_tag primary_mvt_tag(struct mvt_tags tags)
{
	u64 primary = (tags.bits & PRIMARY_TAG_BITS);

	assert(mvt_tags_valid(tags));
	return bitops_ffs64(primary) - 1;
}

struct mvt_account_id *new_mvt_account_id(const tal_t *ctx,
					  const struct channel *channel,
					  const char *account_name TAKES)
{
	struct mvt_account_id *acct = tal(ctx, struct mvt_account_id);
	set_mvt_account_id(acct, channel, account_name);
	return acct;
}

struct channel_coin_mvt *new_channel_coin_mvt_general(const tal_t *ctx,
						      const struct channel *channel,
						      const struct channel_id *cid,
						      u64 timestamp,
						      const struct sha256 *payment_hash TAKES,
						      const u64 *part_id,
						      const u64 *group_id,
						      enum coin_mvt_dir direction,
						      struct amount_msat amount,
						      struct mvt_tags tags,
						      struct amount_msat fees)
{
	struct channel_coin_mvt *mvt = tal(ctx, struct channel_coin_mvt);

	assert(mvt_tags_valid(tags));
	set_mvt_account_id(&mvt->account, channel, cid ? take(fmt_channel_id(NULL, cid)) : NULL);
	mvt->timestamp = timestamp;
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

	mvt->tags = tags;
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

struct channel_coin_mvt *new_channel_coin_mvt(const tal_t *ctx,
					      const struct channel *channel,
					      u64 timestamp,
					      const struct sha256 *payment_hash TAKES,
					      const u64 *part_id,
					      const u64 *group_id,
					      enum coin_mvt_dir direction,
					      struct amount_msat amount,
					      struct mvt_tags tags,
					      struct amount_msat fees)
{
	return new_channel_coin_mvt_general(ctx, channel, NULL, timestamp, payment_hash,
					    part_id, group_id, direction, amount, tags, fees);
}

static struct chain_coin_mvt *new_chain_coin_mvt(const tal_t *ctx,
						 const struct channel *channel,
						 const char *account_name TAKES,
						 u64 timestamp,
						 const struct bitcoin_txid *spending_txid,
						 const struct bitcoin_outpoint *outpoint,
						 const struct sha256 *payment_hash TAKES,
						 u32 blockheight,
						 struct mvt_tags tags,
						 enum coin_mvt_dir direction,
						 struct amount_msat amount,
						 struct amount_sat output_val,
						 u32 out_count)
{
	struct chain_coin_mvt *mvt = tal(ctx, struct chain_coin_mvt);

	assert(mvt_tags_valid(tags));
	set_mvt_account_id(&mvt->account, channel, account_name);
	mvt->timestamp = timestamp;
	mvt->spending_txid = spending_txid;
	mvt->outpoint = *outpoint;
	mvt->originating_acct = NULL;

	/* Most chain event's don't have a peer (only channel_opens) */
	mvt->peer_id = NULL;

	/* for htlc's that are filled onchain, we also have a
	 * preimage, NULL otherwise */
	mvt->payment_hash = tal_dup_or_null(mvt, struct sha256, payment_hash);
	mvt->blockheight = blockheight;

	mvt->tags = tags;
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
						     struct mvt_tags tags,
						     enum coin_mvt_dir direction,
						     struct amount_sat amt_sat)
{
	struct amount_msat amt_msat;
	bool ok;
	ok = amount_sat_to_msat(&amt_msat, amt_sat);
	assert(ok);

	return new_chain_coin_mvt(ctx, channel, account_name,
				  coinmvt_current_time(), tx_txid,
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
					     struct mvt_tags tags)
{
	return new_chain_coin_mvt_sat(ctx, NULL, "", spend_txid,
				      outpoint, NULL,
				      blockheight,
				      tags,
				      COIN_DEBIT, amount);
}

struct chain_coin_mvt *new_onchaind_deposit(const tal_t *ctx,
					    const struct bitcoin_outpoint *outpoint,
					    u32 blockheight,
					    struct amount_sat amount,
					    struct mvt_tags tags)
{
	return new_chain_coin_mvt_sat(ctx, NULL, "", NULL,
				      outpoint, NULL,
				      blockheight,
				      tags,
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
	struct mvt_tags tags;

	if (is_splice)
		tags = mk_mvt_tags(MVT_CHANNEL_CLOSE, MVT_SPLICE);
	else
		tags = mk_mvt_tags(MVT_CHANNEL_CLOSE);

	mvt = new_chain_coin_mvt(ctx, channel, alt_account,
				 coinmvt_current_time(), txid,
				 out, NULL, blockheight,
				 tags,
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
	struct mvt_tags tags = tag_to_mvt_tags(MVT_CHANNEL_PROPOSED);

	/* If we're the opener, add to the tag list */
	if (is_opener)
		mvt_tag_set(&tags, MVT_OPENER);

	if (is_leased)
		mvt_tag_set(&tags, MVT_LEASED);

	mvt = new_chain_coin_mvt(ctx, channel, NULL, coinmvt_current_time(),
				 NULL, out, NULL, 0,
				 tags,
				 COIN_CREDIT, amount, output_val, 0);
	mvt->peer_id = tal_dup(mvt, struct node_id, peer_id);

	return mvt;
}

struct chain_coin_mvt *new_coin_channel_open_general(const tal_t *ctx,
						     const struct channel *channel,
						     const struct channel_id *cid,
						     u64 timestamp,
						     const struct bitcoin_outpoint *out,
						     const struct node_id *peer_id,
						     u32 blockheight,
						     const struct amount_msat amount,
						     const struct amount_sat output_val,
						     bool is_opener,
						     bool is_leased)
{
	struct chain_coin_mvt *mvt;
	struct mvt_tags tags = tag_to_mvt_tags(MVT_CHANNEL_OPEN);

	/* If we're the opener, add to the tag list */
	if (is_opener)
		mvt_tag_set(&tags, MVT_OPENER);

	if (is_leased)
		mvt_tag_set(&tags, MVT_LEASED);

	mvt = new_chain_coin_mvt(ctx, channel, cid ? take(fmt_channel_id(NULL, cid)) : NULL,
				 timestamp,
				 NULL, out, NULL, blockheight,
				 tags,
				 COIN_CREDIT, amount,
				 output_val, 0);
	mvt->peer_id = tal_dup(mvt, struct node_id, peer_id);

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
	return new_coin_channel_open_general(ctx, channel, NULL,
					     coinmvt_current_time(),
					     out, peer_id, blockheight,
					     amount, output_val, is_opener, is_leased);
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
				      tag_to_mvt_tags(MVT_HTLC_FULFILL),
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
	return new_chain_coin_mvt_sat(ctx, NULL, ACCOUNT_NAME_EXTERNAL, NULL,
				      outpoint, payment_hash,
				      blockheight,
				      tag_to_mvt_tags(MVT_HTLC_FULFILL),
				      COIN_CREDIT, amount);
}

struct chain_coin_mvt *new_coin_external_spend(const tal_t *ctx,
					       const struct bitcoin_outpoint *outpoint,
					       const struct bitcoin_txid *txid,
					       u32 blockheight,
					       struct amount_sat amount,
					       struct mvt_tags tags)
{
	return new_chain_coin_mvt(ctx, NULL, ACCOUNT_NAME_EXTERNAL,
				  coinmvt_current_time(), txid,
				  outpoint, NULL, blockheight,
				  tags,
				  COIN_CREDIT, AMOUNT_MSAT(0), amount, 0);
}

struct chain_coin_mvt *new_coin_external_deposit(const tal_t *ctx,
						 const struct bitcoin_outpoint *outpoint,
						 u32 blockheight,
						 struct amount_sat amount,
						 struct mvt_tags tags)
{
	return new_chain_coin_mvt_sat(ctx, NULL, ACCOUNT_NAME_EXTERNAL, NULL, outpoint, NULL,
				      blockheight, tags,
				      COIN_CREDIT, amount);
}

bool chain_mvt_is_external(const struct chain_coin_mvt *mvt)
{
	return mvt->account.alt_account && is_external_account(mvt->account.alt_account);
}

struct chain_coin_mvt *new_coin_wallet_deposit(const tal_t *ctx,
					       const struct bitcoin_outpoint *outpoint,
					       u32 blockheight,
					       struct amount_sat amount,
					       struct mvt_tags tags)
{
	return new_chain_coin_mvt_sat(ctx, NULL, ACCOUNT_NAME_WALLET, NULL,
				      outpoint, NULL,
				      blockheight, tags,
				      COIN_CREDIT, amount);
}

struct chain_coin_mvt *new_coin_wallet_withdraw(const tal_t *ctx,
						const struct bitcoin_txid *spend_txid,
						const struct bitcoin_outpoint *outpoint,
						u32 blockheight,
						struct amount_sat amount,
						struct mvt_tags tags)
{
	return new_chain_coin_mvt_sat(ctx, NULL, ACCOUNT_NAME_WALLET, spend_txid,
				      outpoint, NULL,
				      blockheight, tags,
				      COIN_DEBIT, amount);
}

struct channel_coin_mvt *new_coin_channel_push_general(const tal_t *ctx,
						       const struct channel *channel,
						       const struct channel_id *cid,
						       u64 timestamp,
						       enum coin_mvt_dir direction,
						       struct amount_msat amount,
						       struct mvt_tags tags)
{
	return new_channel_coin_mvt_general(ctx, channel, cid, timestamp, NULL,
				    NULL, NULL, direction, amount,
				    tags,
				    AMOUNT_MSAT(0));
}

struct channel_coin_mvt *new_coin_channel_push(const tal_t *ctx,
					       const struct channel *channel,
					       enum coin_mvt_dir direction,
					       struct amount_msat amount,
					       struct mvt_tags tags)
{
	return new_coin_channel_push_general(ctx, channel, NULL,
					     coinmvt_current_time(),
					     direction, amount, tags);
}

struct chain_coin_mvt *new_foreign_deposit(const tal_t *ctx,
					   const struct bitcoin_outpoint *outpoint,
					   u32 blockheight,
					   struct amount_sat amount,
					   const char *account,
					   u64 timestamp)
{
	struct chain_coin_mvt *e;

	e = new_chain_coin_mvt_sat(ctx, NULL, account, NULL, outpoint, NULL,
				   blockheight,
				   mk_mvt_tags(MVT_DEPOSIT, MVT_FOREIGN),
				   COIN_CREDIT,
				   amount);
	e->timestamp = timestamp;
	return e;
}

struct chain_coin_mvt *new_foreign_withdrawal(const tal_t *ctx,
					      const struct bitcoin_outpoint *outpoint,
					      const struct bitcoin_txid *spend_txid,
					      struct amount_sat amount,
					      u32 blockheight,
					      const char *account,
					      u64 timestamp)
{
	struct chain_coin_mvt *e;

	e = new_chain_coin_mvt_sat(ctx, NULL, account, spend_txid, outpoint, NULL,
				   blockheight,
				   mk_mvt_tags(MVT_WITHDRAWAL, MVT_FOREIGN),
				   COIN_DEBIT,
				   amount);
	e->timestamp = timestamp;
	return e;
}

const char **mvt_tag_strs(const tal_t *ctx, struct mvt_tags tags)
{
	const char **strs = tal_arr(ctx, const char *, 1);

	/* There must be exactly one primary */
	assert(mvt_tags_valid(tags));

	/* We put the *primary* tag first */
	for (size_t i = 0; i < NUM_MVT_TAGS; i++) {
		u64 bit = (u64)1 << i;
		if ((bit & tags.bits) == 0)
			continue;
		if (bit & PRIMARY_TAG_BITS)
			strs[0] = mvt_tag_str(i);
		else
			tal_arr_expand(&strs, mvt_tag_str(i));
	}
	return strs;
}

/* Parse a single mvt tag.  Returns false or populates *tag */
bool mvt_tag_parse(const char *buf, size_t len, enum mvt_tag *tag)
{
	for (size_t i = 0; i < NUM_MVT_TAGS; i++) {
		const char *name = mvt_tag_str(i);
		if (strlen(name) == len && memcmp(buf, name, len) == 0) {
			*tag = i;
			return true;
		}
	}

	return false;
}

/* This is used solely by onchaind.  It always uses alt_account, with "" meaning
 * the channel itself. */
void towire_chain_coin_mvt(u8 **pptr, const struct chain_coin_mvt *mvt)
{
	towire_wirestring(pptr, mvt->account.alt_account);
	assert(!mvt->originating_acct);

	towire_bitcoin_outpoint(pptr, &mvt->outpoint);

	if (mvt->spending_txid) {
		towire_bool(pptr, true);
		towire_bitcoin_txid(pptr, cast_const(struct bitcoin_txid *, mvt->spending_txid));

	} else
		towire_bool(pptr, false);
	if (mvt->payment_hash) {
		towire_bool(pptr, true);
		towire_sha256(pptr, mvt->payment_hash);
	} else
		towire_bool(pptr, false);
	towire_u32(pptr, mvt->blockheight);

	towire_u64(pptr, mvt->tags.bits);
	towire_amount_msat(pptr, mvt->credit);
	towire_amount_msat(pptr, mvt->debit);
	towire_amount_sat(pptr, mvt->output_val);
	towire_u32(pptr, mvt->output_count);

	if (mvt->peer_id) {
		towire_bool(pptr, true);
		towire_node_id(pptr, mvt->peer_id);
	} else
		towire_bool(pptr, false);
	towire_u64(pptr, mvt->timestamp);
}

void fromwire_chain_coin_mvt(const u8 **cursor, size_t *max, struct chain_coin_mvt *mvt)
{
	set_mvt_account_id(&mvt->account, NULL, take(fromwire_wirestring(NULL, cursor, max)));
	mvt->originating_acct = NULL;

	fromwire_bitcoin_outpoint(cursor, max, &mvt->outpoint);

	if (fromwire_bool(cursor, max)) {
		/* We need non-const temporary */
		struct bitcoin_txid *txid;
		mvt->spending_txid = txid = tal(mvt, struct bitcoin_txid);
		fromwire_bitcoin_txid(cursor, max, txid);
	} else
		mvt->spending_txid = NULL;

	if (fromwire_bool(cursor, max)) {
		struct sha256 *ph;
		mvt->payment_hash = ph = tal(mvt, struct sha256);
		fromwire_sha256(cursor, max, ph);
	} else
		mvt->payment_hash = NULL;
	mvt->blockheight = fromwire_u32(cursor, max);

	mvt->tags.bits = fromwire_u64(cursor, max);
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
	mvt->timestamp = fromwire_u64(cursor, max);

	/* Align onchaind's timestamps with ours if we're deterministic */
	if (clock_time_overridden())
		mvt->timestamp = coinmvt_current_time();
}

struct mvt_tags mk_mvt_tags_(enum mvt_tag tag, ...)
{
	va_list ap;
	struct mvt_tags ret = { 0 };

	mvt_tag_set(&ret, tag);
	va_start(ap, tag);
	while ((tag = va_arg(ap, enum mvt_tag)) != 999)
		mvt_tag_set(&ret, mvt_tag_in_db(tag));
	va_end(ap);
	return ret;
}
