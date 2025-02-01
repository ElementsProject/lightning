#include "config.h"
#include <assert.h>
#include <bitcoin/psbt.h>
#include <bitcoin/short_channel_id.h>
#include <channeld/inflight.h>
#include <wire/wire.h>

struct inflight *fromwire_inflight(const tal_t *ctx, const u8 **cursor, size_t *max)
{
	struct inflight *inflight = tal(ctx, struct inflight);

	fromwire_bitcoin_outpoint(cursor, max, &inflight->outpoint);
	fromwire_pubkey(cursor, max, &inflight->remote_funding);
	inflight->amnt = fromwire_amount_sat(cursor, max);
	inflight->remote_tx_sigs = fromwire_bool(cursor, max);
	inflight->psbt = fromwire_wally_psbt(inflight, cursor, max);
	inflight->splice_amnt = fromwire_s64(cursor, max);
	int has_tx = fromwire_u8(cursor, max);
	if(has_tx) {
		inflight->last_tx = fromwire_bitcoin_tx(inflight, cursor, max);
		fromwire_bitcoin_signature(cursor, max, &inflight->last_sig);
	}
	else {
		inflight->last_tx = NULL;
		memset(&inflight->last_sig, 0, sizeof(inflight->last_sig));
	}
	inflight->i_am_initiator = fromwire_bool(cursor, max);
	inflight->force_sign_first = fromwire_bool(cursor, max);
	int has_locked_scid = fromwire_u8(cursor, max);
	if (has_locked_scid) {
		inflight->locked_scid = tal(inflight, struct short_channel_id);
		*inflight->locked_scid = fromwire_short_channel_id(cursor, max);
	}
	else {
		inflight->locked_scid = NULL;
	}

	return inflight;
}

void towire_inflight(u8 **pptr, const struct inflight *inflight)
{
	towire_bitcoin_outpoint(pptr, &inflight->outpoint);
	towire_pubkey(pptr, &inflight->remote_funding);
	towire_amount_sat(pptr, inflight->amnt);
	towire_bool(pptr, inflight->remote_tx_sigs);
	towire_wally_psbt(pptr, inflight->psbt);
	towire_s64(pptr, inflight->splice_amnt);
	towire_u8(pptr, inflight->last_tx ? 1 : 0);
	if(inflight->last_tx) {
		towire_bitcoin_tx(pptr, inflight->last_tx);
		towire_bitcoin_signature(pptr, &inflight->last_sig);
	}
	towire_bool(pptr, inflight->i_am_initiator);
	towire_bool(pptr, inflight->force_sign_first);
	towire_u8(pptr, inflight->locked_scid ? 1 : 0);
	if (inflight->locked_scid)
		towire_short_channel_id(pptr, *inflight->locked_scid);
}
