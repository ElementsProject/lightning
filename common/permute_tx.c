#include "permute_tx.h"
#include <stdbool.h>
#include <string.h>

static bool input_better(const struct bitcoin_tx_input *a,
			 const struct bitcoin_tx_input *b)
{
	int cmp;

	cmp = memcmp(&a->txid, &b->txid, sizeof(a->txid));
	if (cmp != 0)
		return cmp < 0;
	if (a->index != b->index)
		return a->index < b->index;

	/* These shouldn't happen, but let's get a canonical order anyway. */
	if (tal_len(a->script) != tal_len(b->script))
		return tal_len(a->script) < tal_len(b->script);
	cmp = memcmp(a->script, b->script, tal_len(a->script));
	if (cmp != 0)
		return cmp < 0;
	return a->sequence_number < b->sequence_number;
}

static size_t find_best_in(struct bitcoin_tx_input *inputs, size_t num)
{
	size_t i, best = 0;

	for (i = 1; i < num; i++) {
		if (input_better(&inputs[i], &inputs[best]))
			best = i;
	}
	return best;
}

static void swap_inputs(struct bitcoin_tx_input *inputs,
			const void **map,
			size_t i1, size_t i2)
{
	struct bitcoin_tx_input tmpinput;
	const void *tmp;

	tmpinput = inputs[i1];
	inputs[i1] = inputs[i2];
	inputs[i2] = tmpinput;

	if (map) {
		tmp = map[i1];
		map[i1] = map[i2];
		map[i2] = tmp;
	}
}

void permute_inputs(struct bitcoin_tx_input *inputs, size_t num_inputs,
		    const void **map)
{
	size_t i;

	/* Now do a dumb sort (num_inputs is small). */
	for (i = 0; i < num_inputs; i++) {
		/* Swap best into first place. */
		swap_inputs(inputs, map,
			    i, i + find_best_in(inputs + i, num_inputs - i));
	}
}

static void swap_outputs(struct bitcoin_tx_output *outputs,
			 const void **map,
			 size_t i1, size_t i2)
{
	struct bitcoin_tx_output tmpoutput;
	const void *tmp;

	tmpoutput = outputs[i1];
	outputs[i1] = outputs[i2];
	outputs[i2] = tmpoutput;

	if (map) {
		tmp = map[i1];
		map[i1] = map[i2];
		map[i2] = tmp;
	}
}

static bool output_better(const struct bitcoin_tx_output *a,
			  const struct bitcoin_tx_output *b)
{
	size_t len;
	int ret;

	if (a->amount != b->amount)
		return a->amount < b->amount;

	/* Lexographic sort. */
	if (tal_len(a->script) < tal_len(b->script))
		len = tal_len(a->script);
	else
		len = tal_len(b->script);

	ret = memcmp(a->script, b->script, len);
	if (ret != 0)
		return ret < 0;

	return tal_len(a->script) < tal_len(b->script);
}

static size_t find_best_out(struct bitcoin_tx_output *outputs, size_t num)
{
	size_t i, best = 0;

	for (i = 1; i < num; i++) {
		if (output_better(&outputs[i], &outputs[best]))
			best = i;
	}
	return best;
}

void permute_outputs(struct bitcoin_tx_output *outputs, size_t num_outputs,
		     const void **map)
{
	size_t i;

	/* Now do a dumb sort (num_outputs is small). */
	for (i = 0; i < num_outputs; i++) {
		/* Swap best into first place. */
		swap_outputs(outputs, map,
			     i, i + find_best_out(outputs + i, num_outputs - i));
	}
}
