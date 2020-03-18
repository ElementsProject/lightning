#include <ccan/ccan/cast/cast.h>
#include <ccan/tal/str/str.h>
#include <common/coin_mvt.h>
#include <common/type_to_string.h>

static const char *mvt_types[] = { "chain_mvt", "channel_mvt" };
const char *mvt_type_str(enum mvt_type type)
{
	return mvt_types[type];
}

static const char *mvt_tags[] = {
	"deposit",
	"withdrawal",
	"chain_fees",
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

static const char *mvt_units[] = { "btc", };
const char *mvt_unit_str(enum mvt_unit_type unit)
{
	return mvt_units[unit];
}

static u64 mvt_count = 0;

struct channel_coin_mvt *new_channel_coin_mvt(const tal_t *ctx,
					      struct bitcoin_txid *funding_txid,
					      u32 funding_outnum,
					      struct sha256 payment_hash,
					      u32 part_id,
					      struct amount_msat amount,
					      enum mvt_tag tag,
					      bool is_credit,
					      enum mvt_unit_type unit)
{
	struct channel_coin_mvt *mvt = tal(ctx, struct channel_coin_mvt);

	derive_channel_id(&mvt->chan_id, funding_txid, funding_outnum);
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

	mvt->unit = unit;

	return mvt;
}

struct chain_coin_mvt *new_chain_coin_mvt(const tal_t *ctx,
					  const char *account_name,
					  const struct bitcoin_txid *tx_txid,
					  const struct bitcoin_txid *output_txid,
					  u32 vout,
					  struct sha256 *payment_hash,
					  enum mvt_tag tag,
					  struct amount_msat amount,
					  bool is_credit,
					  enum mvt_unit_type unit)
{
	struct chain_coin_mvt *mvt = tal(ctx, struct chain_coin_mvt);

	if (account_name)
		mvt->account_name = tal_strndup(mvt, account_name,
						strlen(account_name));
	else
		mvt->account_name = NULL;

	mvt->tx_txid = tx_txid;
	mvt->output_txid = output_txid;
	mvt->vout = vout;

	/* for htlc's that are filled onchain, we also have a
	 * preimage, NULL otherwise */
	mvt->payment_hash = payment_hash;

	mvt->tag = tag;
	if (is_credit) {
		mvt->credit = amount;
		mvt->debit = AMOUNT_MSAT(0);
	} else {
		mvt->debit = amount;
		mvt->credit = AMOUNT_MSAT(0);
	}
	mvt->unit = unit;

	return mvt;
}

struct chain_coin_mvt *new_chain_coin_mvt_sat(const tal_t *ctx,
					      const char *account_name,
					      const struct bitcoin_txid *tx_txid,
					      const struct bitcoin_txid *output_txid,
					      u32 vout,
					      struct sha256 *payment_hash,
					      enum mvt_tag tag,
					      struct amount_sat amt_sat,
					      bool is_credit,
					      enum mvt_unit_type unit)
{
	struct amount_msat amt_msat;
	if (!amount_sat_to_msat(&amt_msat, amt_sat))
		return NULL;

	return new_chain_coin_mvt(ctx, account_name, tx_txid,
				  output_txid, vout, payment_hash,
				  tag, amt_msat, is_credit,
				  unit);
}

struct coin_mvt *finalize_chain_mvt(const tal_t *ctx,
				    const struct chain_coin_mvt *chain_mvt,
				    u32 timestamp,
				    u32 blockheight,
				    struct node_id *node_id)
{
	struct coin_mvt *mvt = tal(ctx, struct coin_mvt);

	mvt->account_id = tal_strndup(mvt, chain_mvt->account_name,
				      strlen(chain_mvt->account_name));
	mvt->type = CHAIN_MVT;

	mvt->id.tx_txid = chain_mvt->tx_txid;
	mvt->id.output_txid = chain_mvt->output_txid;
	mvt->id.vout = chain_mvt->vout;
	mvt->id.payment_hash = chain_mvt->payment_hash;
	mvt->tag = chain_mvt->tag;
	mvt->credit = chain_mvt->credit;
	mvt->debit = chain_mvt->debit;
	mvt->unit = chain_mvt->unit;
	mvt->timestamp = timestamp;
	mvt->blockheight = blockheight;
	mvt->version = COIN_MVT_VERSION;
	mvt->node_id = node_id;
	mvt->counter = mvt_count++;

	return mvt;
}

struct coin_mvt *finalize_channel_mvt(const tal_t *ctx,
				      const struct channel_coin_mvt *chan_mvt,
				      u32 timestamp, u32 blockheight,
				      struct node_id *node_id)
{
	struct coin_mvt *mvt = tal(ctx, struct coin_mvt);

	mvt->account_id = type_to_string(mvt, struct channel_id,
					 &chan_mvt->chan_id);
	mvt->type = CHANNEL_MVT;
	mvt->id.payment_hash = chan_mvt->payment_hash;
	mvt->id.part_id = chan_mvt->part_id;
	mvt->id.tx_txid = NULL;
	mvt->id.output_txid = NULL;
	mvt->id.vout = 0;
	mvt->tag = chan_mvt->tag;
	mvt->credit = chan_mvt->credit;
	mvt->debit = chan_mvt->debit;
	mvt->unit = chan_mvt->unit;
	mvt->timestamp = timestamp;
	mvt->blockheight = blockheight;
	mvt->version = COIN_MVT_VERSION;
	mvt->node_id = node_id;
	mvt->counter = mvt_count++;

	return mvt;
}
