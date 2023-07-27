#include "config.h"
#include <assert.h>
#include <bitcoin/psbt.h>
#include <channeld/inflight.h>
#include <wire/wire.h>

struct inflight *fromwire_inflight(const tal_t *ctx, const u8 **cursor, size_t *max)
{
	struct inflight *inflight = tal(ctx, struct inflight);

	fromwire_bitcoin_outpoint(cursor, max, &inflight->outpoint);
	inflight->amnt = fromwire_amount_sat(cursor, max);
	inflight->psbt = fromwire_wally_psbt(inflight, cursor, max);
	inflight->splice_amnt = fromwire_s64(cursor, max);
	inflight->last_tx = fromwire_bitcoin_tx(inflight, cursor, max);
	fromwire_bitcoin_signature(cursor, max, &inflight->last_sig);
	inflight->i_am_initiator = fromwire_bool(cursor, max);

	return inflight;
}

void towire_inflight(u8 **pptr, const struct inflight *inflight)
{
	towire_bitcoin_outpoint(pptr, &inflight->outpoint);
	towire_amount_sat(pptr, inflight->amnt);
	towire_wally_psbt(pptr, inflight->psbt);
	towire_s64(pptr, inflight->splice_amnt);
	towire_bitcoin_tx(pptr, inflight->last_tx);
	towire_bitcoin_signature(pptr, &inflight->last_sig);
	towire_bool(pptr, inflight->i_am_initiator);
}

void copy_inflight(struct inflight *dest, struct inflight *src)
{
	dest->outpoint = src->outpoint;
	dest->amnt = src->amnt;
	dest->psbt = src->psbt ? clone_psbt(dest, src->psbt): NULL;
	dest->splice_amnt = src->splice_amnt;
	dest->last_tx = src->last_tx ? clone_bitcoin_tx(dest, src->last_tx) : NULL;
	dest->last_sig = src->last_sig;
	dest->i_am_initiator = src->i_am_initiator;
}
