#include "permute_tx.h"
#include <stdbool.h>
#include <string.h>

static void init_map(int *map, size_t len)
{
	size_t i;

	if (!map)
		return;

	for (i = 0; i < len; i++)
		map[i] = i;
}

/* This map says where things ended up, eg. 0 might be in slot 3.  we
 * want to change it so map[0] = 3. */
static void invert_map(int *map, size_t len)
{
	if (map) {
		int i, newmap[len];

		memset(newmap, 0, sizeof(newmap));
		for (i = 0; i < len; i++) {
			newmap[map[i]] = i;
		}
		memcpy(map, newmap, sizeof(newmap));
	}
}

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
	if (a->script_length != b->script_length)
		return a->script_length < b->script_length;
	cmp = memcmp(a->script, b->script, a->script_length);
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

static void swap_inputs(struct bitcoin_tx_input *inputs, int *map,
			size_t i1, size_t i2)
{
	struct bitcoin_tx_input tmpinput;
	size_t tmpidx;

	tmpinput = inputs[i1];
	inputs[i1] = inputs[i2];
	inputs[i2] = tmpinput;

	if (map) {
		tmpidx = map[i1];
		map[i1] = map[i2];
		map[i2] = tmpidx;
	}
}

void permute_inputs(struct bitcoin_tx_input *inputs,
		    size_t num_inputs,
		    int *map)
{
	size_t i;

	init_map(map, num_inputs);

	/* Now do a dumb sort (num_inputs is small). */
	for (i = 0; i < num_inputs; i++) {
		/* Swap best into first place. */
		swap_inputs(inputs, map,
			    i, i + find_best_in(inputs + i, num_inputs - i));
	}

	invert_map(map, num_inputs);
}

static void swap_outputs(struct bitcoin_tx_output *outputs, int *map,
			size_t i1, size_t i2)
{
	struct bitcoin_tx_output tmpoutput;
	size_t tmpidx;

	tmpoutput = outputs[i1];
	outputs[i1] = outputs[i2];
	outputs[i2] = tmpoutput;

	if (map) {
		tmpidx = map[i1];
		map[i1] = map[i2];
		map[i2] = tmpidx;
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
	if (a->script_length < b->script_length)
		len = a->script_length;
	else
		len = b->script_length;

	ret = memcmp(a->script, b->script, len);
	if (ret != 0)
		return ret < 0;

	return a->script_length < b->script_length;
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

void permute_outputs(struct bitcoin_tx_output *outputs,
		     size_t num_outputs,
		     int *map)
{
	size_t i;

	init_map(map, num_outputs);

	/* Now do a dumb sort (num_outputs is small). */
	for (i = 0; i < num_outputs; i++) {
		/* Swap best into first place. */
		swap_outputs(outputs, map,
			     i, i + find_best_out(outputs + i, num_outputs - i));
	}

	invert_map(map, num_outputs);
}
