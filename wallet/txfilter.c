#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/utils.h>
#include <wallet/txfilter.h>

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
	opf->set = new_htable(opf, outpointset);
	return opf;
}
