#include "config.h"
#include <ccan/tal/tal.h>
#include <channeld/splice.h>

struct splice_state *splice_state_new(const tal_t *ctx)
{
	struct splice_state *splice_state = tal(ctx, struct splice_state);

	splice_state->committed_count = 0;
	splice_state->revoked_count = 0;
	splice_state->count = 0;
	splice_state->locked_ready[LOCAL] = false;
	splice_state->locked_ready[REMOTE] = false;
	splice_state->await_commitment_succcess = false;
	splice_state->inflights = NULL;

	return splice_state;
}

struct splice *splice_new(const tal_t *ctx)
{
	struct splice *splice = tal(ctx, struct splice);

	splice->opener_relative = 0;
	splice->accepter_relative = 0;
	splice->feerate_per_kw = 0;
	splice->force_feerate = false;
	splice->force_sign_first = false;
	splice->mode = false;
	splice->tx_add_input_count = 0;
	splice->tx_add_output_count = 0;
	splice->current_psbt = NULL;
	splice->received_tx_complete = false;
	splice->sent_tx_complete = false;

	return splice;
}
