#include "txfilter.h"

#include <bitcoin/script.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/mem/mem.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/utils.h>
#include <wallet/wallet.h>

struct txfilter {
	const u8 **scriptpubkeys;
};

struct outpointfilter_entry {
	struct bitcoin_txid txid;
	u32 outnum;
};

static size_t outpoint_hash(const struct outpointfilter_entry *out)
{
	struct siphash24_ctx ctx;
	siphash24_init(&ctx, siphash_seed());
	siphash24_update(&ctx, &out->txid, sizeof(out->txid));
	siphash24_u32(&ctx, out->outnum);
	return siphash24_done(&ctx);
}

static bool outpoint_eq(const struct outpointfilter_entry *o1,
			const struct outpointfilter_entry *o2)
{
	return bitcoin_txid_eq(&o1->txid, &o2->txid) && o1->outnum == o2->outnum;
}

static const struct outpointfilter_entry *outpoint_keyof(const struct outpointfilter_entry *out)
{
	return out;
}

HTABLE_DEFINE_TYPE(struct outpointfilter_entry, outpoint_keyof, outpoint_hash, outpoint_eq,
		   outpointset);

struct outpointfilter {
	struct outpointset *set;
};

struct txfilter *txfilter_new(const tal_t *ctx)
{
	struct txfilter *filter = tal(ctx, struct txfilter);
	filter->scriptpubkeys = tal_arr(filter, const u8 *, 0);
	return filter;
}

void txfilter_add_scriptpubkey(struct txfilter *filter, const u8 *script TAKES)
{
	size_t count = tal_count(filter->scriptpubkeys);
	tal_resize(&filter->scriptpubkeys, count + 1);
	filter->scriptpubkeys[count] = tal_dup_arr(filter, u8, script, tal_count(script), 0);
}

void txfilter_add_derkey(struct txfilter *filter,
			 const u8 derkey[PUBKEY_DER_LEN])
{
	u8 *skp, *p2sh;

	skp = scriptpubkey_p2wpkh_derkey(tmpctx, derkey);
	p2sh = scriptpubkey_p2sh(tmpctx, skp);

	txfilter_add_scriptpubkey(filter, take(skp));
	txfilter_add_scriptpubkey(filter, take(p2sh));
}


bool txfilter_match(const struct txfilter *filter, const struct bitcoin_tx *tx)
{
	for (size_t i = 0; i < tal_count(tx->output); i++) {
		u8 *oscript = tx->output[i].script;

		for (size_t j = 0; j < tal_count(filter->scriptpubkeys); j++) {
			if (scripteq(oscript, filter->scriptpubkeys[j]))
				return true;
		}
	}
	return false;
}

void outpointfilter_add(struct outpointfilter *of, const struct bitcoin_txid *txid, const u32 outnum)
{
	struct outpointfilter_entry *op;
	if (outpointfilter_matches(of, txid, outnum))
		return;
	/* Have to mark the entries as notleak since they'll not be
	 * pointed to by anything other than the htable */
	op = notleak(tal(of->set, struct outpointfilter_entry));
	op->txid = *txid;
	op->outnum = outnum;
	outpointset_add(of->set, op);
}

bool outpointfilter_matches(struct outpointfilter *of, const struct bitcoin_txid *txid, const u32 outnum)
{
	struct outpointfilter_entry op;
	op.txid = *txid;
	op.outnum = outnum;
	return outpointset_get(of->set, &op) != NULL;
}

void outpointfilter_remove(struct outpointfilter *of, const struct bitcoin_txid *txid, const u32 outnum)
{
	struct outpointfilter_entry op;
	op.txid = *txid;
	op.outnum = outnum;
	outpointset_del(of->set, &op);
}

struct outpointfilter *outpointfilter_new(tal_t *ctx)
{
	struct outpointfilter *opf = tal(ctx, struct outpointfilter);
	opf->set = tal(opf, struct outpointset);
	outpointset_init(opf->set);
	return opf;
}
