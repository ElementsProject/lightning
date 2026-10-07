#include "config.h"
#include <channeld/channeld_wiregen.h>
#include <channeld/splice.h>

bool splice_record_commitment(struct inflight *inflight,
			      struct commitsig *commit)
{
	if (!commit)
		return false;

	if (inflight->last_tx != commit->tx)
		inflight->last_tx = tal_free(inflight->last_tx);
	inflight->last_tx = tal_steal(inflight, commit->tx);
	inflight->last_sig = commit->commit_signature;
	return true;
}

struct splice_state *splice_state_new(const tal_t *ctx)
{
	struct splice_state *splice_state = tal(ctx, struct splice_state);

	splice_state->count = 0;
	splice_state->locked_ready[LOCAL] = false;
	splice_state->locked_ready[REMOTE] = false;
	splice_state->inflights = NULL;
	splice_state->remote_locked_txid = NULL;

	return splice_state;
}

struct splicing *splicing_new(const tal_t *ctx)
{
	struct splicing *splicing = tal(ctx, struct splicing);

	splicing->opener_relative = 0;
	splicing->accepter_relative = 0;
	splicing->feerate_per_kw = 0;
	splicing->force_feerate = false;
	splicing->force_sign_first = false;
	splicing->mode = false;
	splicing->tx_add_input_count = 0;
	splicing->tx_add_output_count = 0;
	splicing->current_psbt = NULL;
	splicing->received_tx_complete = false;
	splicing->sent_tx_complete = false;
	splicing->tx_sig_msg = NULL;
	splicing->inws = NULL;
	splicing->their_sig = NULL;

	return splicing;
}
