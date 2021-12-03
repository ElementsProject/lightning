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

static int scriptpubkey_eq(const u8 *a, const u8 *b)
{
	return memeq(a, tal_bytelen(a), b, tal_bytelen(b));
}

HTABLE_DEFINE_TYPE(u8, scriptpubkey_keyof, scriptpubkey_hash, scriptpubkey_eq, scriptpubkeyset);

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

HTABLE_DEFINE_TYPE(struct bitcoin_outpoint, outpoint_keyof, outpoint_hash, bitcoin_outpoint_eq,
		   outpointset);

struct outpointfilter {
	struct outpointset *set;
};

static void destroy_txfilter(struct txfilter *filter)
{
	scriptpubkeyset_clear(&filter->scriptpubkeyset);
}

struct txfilter *txfilter_new(const tal_t *ctx)
{
	struct txfilter *filter = tal(ctx, struct txfilter);
	scriptpubkeyset_init(&filter->scriptpubkeyset);
	tal_add_destructor(filter, destroy_txfilter);
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
	u8 *skp, *p2sh;

	skp = scriptpubkey_p2wpkh_derkey(tmpctx, derkey);
	p2sh = scriptpubkey_p2sh(tmpctx, skp);

	txfilter_add_scriptpubkey(filter, take(skp));
	txfilter_add_scriptpubkey(filter, take(p2sh));
}


bool txfilter_match(const struct txfilter *filter, const struct bitcoin_tx *tx)
{
	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		const u8 *oscript = bitcoin_tx_output_get_script(tmpctx, tx, i);

		if (!oscript)
			continue;

		if (scriptpubkeyset_get(&filter->scriptpubkeyset, oscript))
			return true;
	}
	return false;
}

void outpointfilter_add(struct outpointfilter *of,
			const struct bitcoin_outpoint *outpoint)
{
	if (outpointfilter_matches(of, outpoint))
		return;
	/* Have to mark the entries as notleak since they'll not be
	 * pointed to by anything other than the htable */
	outpointset_add(of->set, notleak(tal_dup(of->set,
						 struct bitcoin_outpoint,
						 outpoint)));
}

bool outpointfilter_matches(struct outpointfilter *of,
			    const struct bitcoin_outpoint *outpoint)
{
	return outpointset_get(of->set, outpoint) != NULL;
}

void outpointfilter_remove(struct outpointfilter *of,
			   const struct bitcoin_outpoint *outpoint)
{
	outpointset_del(of->set, outpoint);
}

static void destroy_outpointfilter(struct outpointfilter *opf)
{
	outpointset_clear(opf->set);
}

struct outpointfilter *outpointfilter_new(tal_t *ctx)
{
	struct outpointfilter *opf = tal(ctx, struct outpointfilter);
	opf->set = tal(opf, struct outpointset);
	outpointset_init(opf->set);
	tal_add_destructor(opf, destroy_outpointfilter);
	return opf;
}
