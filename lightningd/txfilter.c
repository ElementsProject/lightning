#include "txfilter.h"

#include <bitcoin/script.h>
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <common/utils.h>

struct txfilter {
	u8 **scriptpubkeys;
};



struct txfilter *txfilter_new(const tal_t *ctx)
{
	struct txfilter *filter = tal(ctx, struct txfilter);
	filter->scriptpubkeys = tal_arr(filter, u8*, 0);
	return filter;
}

static void txfilter_add_scriptpubkey(struct txfilter *filter, u8 *script)
{
	size_t count = tal_count(filter->scriptpubkeys);
	tal_resize(&filter->scriptpubkeys, count + 1);
	filter->scriptpubkeys[count] = tal_dup_arr(filter, u8, script, tal_len(script), 0);
}

void txfilter_add_derkey(struct txfilter *filter, u8 derkey[33])
{
	tal_t *tmpctx = tal_tmpctx(filter);
	u8 *skp, *p2sh;

	skp = scriptpubkey_p2wpkh_derkey(tmpctx, derkey);
	p2sh = scriptpubkey_p2sh(tmpctx, skp);

	txfilter_add_scriptpubkey(filter, take(skp));
	txfilter_add_scriptpubkey(filter, take(p2sh));

	tal_free(tmpctx);
}


bool txfilter_match(const struct txfilter *filter, const struct bitcoin_tx *tx)
{
	u8 *oscript;
	for (size_t i = 0; i < tal_count(tx->output); i++) {
		oscript = tx->output[i].script;

		for (size_t j = 0; j < tal_count(filter->scriptpubkeys); j++) {
			if (scripteq(oscript, filter->scriptpubkeys[j]))
				return true;
		}
	}
	return false;
}
