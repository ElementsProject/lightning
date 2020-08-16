#include "permute_tx.h"
#include <stdbool.h>
#include <string.h>
#include <wally_psbt.h>

static bool input_better(const struct wally_tx_input *a,
			 const struct wally_tx_input *b)
{
	int cmp;

	cmp = memcmp(a->txhash, b->txhash, sizeof(a->txhash));
	if (cmp != 0)
		return cmp < 0;
	if (a->index != b->index)
		return a->index < b->index;

	/* These shouldn't happen, but let's get a canonical order anyway. */
	if (a->script_len != b->script_len)
		return a->script_len < b->script_len;

	cmp = memcmp(a->script, b->script, a->script_len);
	if (cmp != 0)
		return cmp < 0;
	return a->sequence < b->sequence;
}

static size_t find_best_in(struct wally_tx_input *inputs, size_t num)
{
	size_t i, best = 0;

	for (i = 1; i < num; i++) {
		if (input_better(&inputs[i], &inputs[best]))
			best = i;
	}
	return best;
}

static void swap_wally_inputs(struct wally_tx_input *inputs,
			      struct wally_tx_input *psbt_global_ins,
			      struct wally_psbt_input *psbt_ins,
			      const void **map,
                              size_t i1, size_t i2)
{
	struct wally_tx_input tmpinput;
	struct wally_psbt_input tmppsbtin;
	const void *tmp;

	if (i1 == i2)
		return;

	tmpinput = inputs[i1];
	inputs[i1] = inputs[i2];
	inputs[i2] = tmpinput;

	/* For the PSBT, we swap the psbt inputs and
	 * the global tx's inputs */
	tmpinput = psbt_global_ins[i1];
	psbt_global_ins[i1] = psbt_global_ins[i2];
	psbt_global_ins[i2] = tmpinput;

	tmppsbtin = psbt_ins[i1];
	psbt_ins[i1] = psbt_ins[i2];
	psbt_ins[i2] = tmppsbtin;

	if (map) {
		tmp = map[i1];
		map[i1] = map[i2];
		map[i2] = tmp;
	}
}

void permute_inputs(struct bitcoin_tx *tx, const void **map)
{
	size_t i, best_pos;
	struct wally_tx_input *inputs = tx->wtx->inputs;
	size_t num_inputs = tx->wtx->num_inputs;

	/* We can't permute nothing! */
	if (num_inputs == 0)
		return;

	/* Now do a dumb sort (num_inputs is small). */
	for (i = 0; i < num_inputs-1; i++) {
		best_pos = i + find_best_in(inputs + i, num_inputs - i);
		/* Swap best into first place. */
		swap_wally_inputs(tx->wtx->inputs,
				  tx->psbt->tx->inputs,
				  tx->psbt->inputs,
				  map, i, best_pos);
	}
}

static void swap_wally_outputs(struct wally_tx_output *outputs,
			       struct wally_tx_output *psbt_global_outs,
			       struct wally_psbt_output *psbt_outs,
			       const void **map, u32 *cltvs,
			       size_t i1, size_t i2)
{
	struct wally_tx_output tmpoutput;
	struct wally_psbt_output tmppsbtout;

	if (i1 == i2)
		return;

	tmpoutput = outputs[i1];
	outputs[i1] = outputs[i2];
	outputs[i2] = tmpoutput;

	/* For the PSBT, we swap the psbt outputs and
	 * the global tx's outputs */
	tmpoutput = psbt_global_outs[i1];
	psbt_global_outs[i1] = psbt_global_outs[i2];
	psbt_global_outs[i2] = tmpoutput;

	tmppsbtout = psbt_outs[i1];
	psbt_outs[i1] = psbt_outs[i2];
	psbt_outs[i2] = tmppsbtout;

	if (map) {
		const void *tmp = map[i1];
		map[i1] = map[i2];
		map[i2] = tmp;
	}

	if (cltvs) {
		u32 tmp = cltvs[i1];
		cltvs[i1] = cltvs[i2];
		cltvs[i2] = tmp;
	}
}

static bool output_better(const struct wally_tx_output *a, u32 cltv_a,
			  const struct wally_tx_output *b, u32 cltv_b)
{
	size_t len, lena, lenb;
	int ret;

	if (a->satoshi != b->satoshi)
		return a->satoshi < b->satoshi;

	/* Lexicographical sort. */
	lena = a->script_len;
	lenb = b->script_len;
	if (lena < lenb)
		len = lena;
	else
		len = lenb;

	ret = memcmp(a->script, b->script, len);
	if (ret != 0)
		return ret < 0;

	if (lena != lenb)
		return lena < lenb;

	return cltv_a < cltv_b;
}

static u32 cltv_of(const u32 *cltvs, size_t idx)
{
	if (!cltvs)
		return 0;
	return cltvs[idx];
}

static size_t find_best_out(struct wally_tx_output *outputs, const u32 *cltvs,
			    size_t num)
{
	size_t i, best = 0;

	for (i = 1; i < num; i++) {
		if (output_better(&outputs[i], cltv_of(cltvs, i),
				  &outputs[best], cltv_of(cltvs, best)))
			best = i;
	}
	return best;
}

void permute_outputs(struct bitcoin_tx *tx, u32 *cltvs, const void **map)
{
	size_t i, best_pos;
	struct wally_tx_output *outputs = tx->wtx->outputs;
	size_t num_outputs = tx->wtx->num_outputs;

	/* We can't permute nothing! */
	if (num_outputs == 0)
		return;

	/* Now do a dumb sort (num_outputs is small). */
	for (i = 0; i < num_outputs - 1; i++) {
		best_pos =
		    i + find_best_out(outputs + i, cltvs ? cltvs + i : NULL,
				      num_outputs - i);

		/* Swap best into first place. */
		swap_wally_outputs(tx->wtx->outputs,
				   tx->psbt->tx->outputs,
				   tx->psbt->outputs,
				   map, cltvs, i, best_pos);
	}
}
