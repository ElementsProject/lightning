#include "config.h"
#include <bitcoin/script.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/mem/mem.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <wallet/txfilter.h>
#include <wallet/wallet.h>

static size_t scriptpubkey_hash(const u8 *out)
{
	struct siphash24_ctx ctx;
	siphash24_init(&ctx, siphash_seed());
	siphash24_update(&ctx, out, tal_bytelen(out));
	return siphash24_done(&ctx);
}

static const u8 *scriptpubkey_keyof(const u8 *out)
{
	return out;
}

static bool scriptpubkey_eq(const u8 *a, const u8 *b)
{
	return tal_arr_eq(a, b);
}

/* FIXME: Should we disallow dups here? */
HTABLE_DEFINE_DUPS_TYPE(u8, scriptpubkey_keyof, scriptpubkey_hash, scriptpubkey_eq, scriptpubkeyset);

struct txfilter {
	struct scriptpubkeyset scriptpubkeyset;
};

static size_t outpoint_hash(const struct bitcoin_outpoint *out)
{
	struct siphash24_ctx ctx;
	siphash24_init(&ctx, siphash_seed());
	siphash24_update(&ctx, &out->txid, sizeof(out->txid));
	siphash24_u32(&ctx, out->n);
	return siphash24_done(&ctx);
}

static const struct bitcoin_outpoint *outpoint_keyof(const struct bitcoin_outpoint *out)
{
	return out;
}

HTABLE_DEFINE_NODUPS_TYPE(struct bitcoin_outpoint, outpoint_keyof, outpoint_hash, bitcoin_outpoint_eq,
			  outpointset);

struct outpointfilter {
	struct outpointset *set;
};

struct txfilter *txfilter_new(const tal_t *ctx)
{
	struct txfilter *filter = tal(ctx, struct txfilter);
	scriptpubkeyset_init(&filter->scriptpubkeyset);
	return filter;
}

void txfilter_add_scriptpubkey(struct txfilter *filter, const u8 *script TAKES)
{
	scriptpubkeyset_add(
	    &filter->scriptpubkeyset,
	    notleak(tal_dup_talarr(filter, u8, script)));
}

void txfilter_add_derkey(struct txfilter *filter,
			 const u8 derkey[PUBKEY_CMPR_LEN])
{
	u8 *skp, *p2sh, *p2tr;

	skp = scriptpubkey_p2wpkh_derkey(tmpctx, derkey);
	p2sh = scriptpubkey_p2sh(tmpctx, skp);
	p2tr = scriptpubkey_p2tr_derkey(tmpctx, derkey);

	txfilter_add_scriptpubkey(filter, take(skp));
	txfilter_add_scriptpubkey(filter, take(p2sh));
	txfilter_add_scriptpubkey(filter, take(p2tr));
}


bool txfilter_match(const struct txfilter *filter, const struct bitcoin_tx *tx)
{
	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		const struct wally_tx_output *txout = &tx->wtx->outputs[i];
		if (txfilter_scriptpubkey_matches(filter, txout->script))
			return true;
	}
	return false;
}

bool txfilter_scriptpubkey_matches(const struct txfilter *filter, const u8 *scriptPubKey)
{
	if (!scriptPubKey)
		return false;
	return scriptpubkeyset_exists(&filter->scriptpubkeyset, scriptPubKey);
}

void outpointfilter_add(struct outpointfilter *of,
			const struct bitcoin_outpoint *outpoint)
{
	if (outpointfilter_matches(of, outpoint))
		return;
	outpointset_add(of->set, tal_dup(of->set,
					 struct bitcoin_outpoint,
					 outpoint));
}

bool outpointfilter_matches(struct outpointfilter *of,
			    const struct bitcoin_outpoint *outpoint)
{
	return outpointset_get(of->set, outpoint) != NULL;
}

void outpointfilter_remove(struct outpointfilter *of,
			   const struct bitcoin_outpoint *outpoint)
{
	struct bitcoin_outpoint *o = outpointset_get(of->set, outpoint);
	if (o) {
		outpointset_del(of->set, o);
		tal_free(o);
	}
}

struct outpointfilter *outpointfilter_new(tal_t *ctx)
{
	struct outpointfilter *opf = tal(ctx, struct outpointfilter);
	opf->set = tal(opf, struct outpointset);
	outpointset_init(opf->set);
	return opf;
}

void memleak_scan_outpointfilter(struct htable *memtable, const struct outpointfilter *opf)
{
	memleak_scan_htable(memtable, &opf->set->raw);
}
