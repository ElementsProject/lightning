#include "config.h"
#include <ccan/tal/tal.h>
#include <channeld/splice.h>

void init_splice_state(struct splice_state *splice_state)
{
	splice_state->committed_count = 0;
	splice_state->revoked_count = 0;
	splice_state->count = 0;
	splice_state->locked_ready[LOCAL] = false;
	splice_state->locked_ready[REMOTE] = false;
	splice_state->await_commitment_succcess = false;
	splice_state->inflights = NULL;
}

void init_splice(struct splice *splice)
{
	splice->current_psbt = NULL;
	reset_splice(splice);
}

void reset_splice(struct splice *splice)
{
	splice->opener_funding = AMOUNT_SAT(0);
	splice->accepter_funding = AMOUNT_SAT(0);
	splice->feerate_per_kw = 0;
	splice->force_feerate = false;
	splice->force_sign_first = false;
	splice->mode = false;
	splice->tx_add_input_count = 0;
	splice->tx_add_output_count = 0;
	splice->current_psbt = tal_free(splice->current_psbt);
	splice->received_tx_complete = false;
	splice->sent_tx_complete = false;
}
