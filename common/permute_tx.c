#include "config.h"
#include <common/permute_tx.h>
#include <wally_psbt.h>

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
