#ifndef LIGHTNING_CHANNELD_INFLIGHT_H
#define LIGHTNING_CHANNELD_INFLIGHT_H

#include "config.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/tx.h>
#include <common/amount.h>

struct inflight {
	struct bitcoin_outpoint outpoint;
	struct pubkey remote_funding;
	struct amount_sat amnt;
	bool remote_tx_sigs;
	struct wally_psbt *psbt;
	s64 splice_amnt;
	struct bitcoin_tx *last_tx;
	/* last_sig is assumed valid if last_tx is set */
	struct bitcoin_signature last_sig;
	bool i_am_initiator;
	bool force_sign_first;
	bool is_locked;
};

struct inflight *fromwire_inflight(const tal_t *ctx, const u8 **cursor, size_t *max);
void towire_inflight(u8 **pptr, const struct inflight *inflight);

#endif /* LIGHTNING_CHANNELD_INFLIGHT_H */
