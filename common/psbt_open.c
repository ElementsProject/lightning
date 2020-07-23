#include <assert.h>
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <common/psbt_open.h>
#include <common/utils.h>
#include <wally_psbt.h>
#include <wally_transaction.h>

static void swap_wally_inputs(struct wally_psbt *psbt,
                              size_t i1, size_t i2)
{
	struct wally_tx_input *inputs = psbt->tx->inputs;
	struct wally_psbt_input *psbt_ins = psbt->inputs;
	struct wally_tx_input tmpinput;
	struct wally_psbt_input tmppsbtin;

	if (i1 == i2)
		return;

	tmpinput = inputs[i1];
	inputs[i1] = inputs[i2];
	inputs[i2] = tmpinput;

	tmppsbtin = psbt_ins[i1];
	psbt_ins[i1] = psbt_ins[i2];
	psbt_ins[i2] = tmppsbtin;
}

static void swap_wally_outputs(struct wally_psbt *psbt,
                               size_t i1, size_t i2)
{
	struct wally_tx_output *outputs = psbt->tx->outputs;
	struct wally_psbt_output *psbt_ins = psbt->outputs;
	struct wally_tx_output tmpoutput;
	struct wally_psbt_output tmppsbtin;

	if (i1 == i2)
		return;

	tmpoutput = outputs[i1];
	outputs[i1] = outputs[i2];
	outputs[i2] = tmpoutput;

	tmppsbtin = psbt_ins[i1];
	psbt_ins[i1] = psbt_ins[i2];
	psbt_ins[i2] = tmppsbtin;
}

bool psbt_get_serial_id(struct wally_unknowns_map *map, u16 *serial_id)
{
	u8 *key = psbt_make_key(tmpctx, PSBT_TYPE_SERIAL_ID, NULL);
	size_t value_len;
	void *result = psbt_get_unknown(map, key, &value_len);
	if (!result)
		return false;
	assert(value_len == sizeof(*serial_id));
	memcpy(serial_id, result, value_len);
	return true;
}

static int compare_inputs(struct wally_psbt *psbt,
			  size_t left, size_t right)
{
	u16 serial_left, serial_right;
	bool ok;

	ok = psbt_get_serial_id(psbt->inputs[left].unknowns, &serial_left);
	assert(ok);
	ok = psbt_get_serial_id(psbt->inputs[right].unknowns,
				&serial_right);
	assert(ok);
	if (serial_left < serial_right)
		return -1;
	if (serial_left == serial_right)
		return 0;
	return 1;
}

static bool compare_outputs(struct wally_psbt *psbt,
			    size_t left, size_t right)
{
	u16 serial_left, serial_right;
	bool ok;

	ok = psbt_get_serial_id(psbt->outputs[left].unknowns, &serial_left);
	assert(ok);
	ok = psbt_get_serial_id(psbt->outputs[right].unknowns,
				&serial_right);
	assert(ok);
	if (serial_left < serial_right)
		return -1;
	if (serial_left == serial_right)
		return 0;
	return 1;
}

void sort_inputs(struct wally_psbt *psbt, size_t first, size_t last);
void sort_inputs(struct wally_psbt *psbt, size_t first, size_t last)
{
	size_t i, j, pivot;

	if (first >= last)
		return;

	pivot = (last + first) / 2;
	i = first;
	j = last;

	while (i < j) {
		while (compare_inputs(psbt, i, pivot) < 1 && i < last)
			i++;
		while (compare_inputs(psbt, j, pivot) == 1)
			j--;
		if (i < j)
			swap_wally_inputs(psbt, i, j);
	}

	swap_wally_inputs(psbt, pivot, j);
	sort_inputs(psbt, first, j - 1);
	sort_inputs(psbt, j + 1, last);
}

void sort_outputs(struct wally_psbt *psbt, size_t first, size_t last);
void sort_outputs(struct wally_psbt *psbt, size_t first, size_t last)
{
	size_t i, j, pivot;

	if (first >= last)
		return;

	pivot = (last + first) / 2;
	i = first;
	j = last;

	while (i < j) {
		while (compare_outputs(psbt, i, pivot) < 1 && i < last)
			i++;
		while (compare_outputs(psbt, j, pivot) == 1)
			j--;
		if (i < j)
			swap_wally_outputs(psbt, i, j);
	}

	swap_wally_outputs(psbt, pivot, j);
	sort_outputs(psbt, first, j - 1);
	sort_outputs(psbt, j + 1, last);
}

void psbt_sort_by_serial_id(struct wally_psbt *psbt)
{
	sort_inputs(psbt, 0, psbt->num_inputs);
	sort_outputs(psbt, 0, psbt->num_outputs);
}

static int compare_input_at(struct wally_psbt *psbt_a,
			    struct wally_psbt *psbt_b,
			    size_t index_a,
			    size_t index_b)
{
	u16 serial_left, serial_right;
	bool ok;

	ok = psbt_get_serial_id(psbt_a->inputs[index_a].unknowns,
				&serial_left);
	assert(ok);
	ok = psbt_get_serial_id(psbt_b->inputs[index_b].unknowns,
				&serial_right);
	assert(ok);
	if (serial_left < serial_right)
		return -1;
	if (serial_left == serial_right)
		return 0;
	return 1;
}

static int compare_output_at(struct wally_psbt *psbt_a,
			    struct wally_psbt *psbt_b,
			    size_t index_a,
			    size_t index_b)
{
	u16 serial_left, serial_right;
	bool ok;

	ok = psbt_get_serial_id(psbt_a->outputs[index_a].unknowns,
				&serial_left);
	assert(ok);
	ok = psbt_get_serial_id(psbt_b->outputs[index_b].unknowns,
				&serial_right);
	assert(ok);
	if (serial_left < serial_right)
		return -1;
	if (serial_left == serial_right)
		return 0;
	return 1;
}

/* this requires having a serial_id entry on everything */
bool psbt_has_diff(const tal_t *ctx,
		   struct wally_psbt *orig,
		   struct wally_psbt *new,
		   struct input_set ***added_ins,
		   struct input_set ***rm_ins,
		   struct output_set ***added_outs,
		   struct output_set ***rm_outs)
{
	int result;

	psbt_sort_by_serial_id(orig);
	psbt_sort_by_serial_id(new);

	*added_ins = tal_arr(ctx, struct input_set *, 0);
	*rm_ins = tal_arr(ctx, struct input_set *, 0);
	*added_outs = tal_arr(ctx, struct output_set *, 0);
	*rm_outs = tal_arr(ctx, struct output_set *, 0);

	/* Find the input diff */
	for (size_t i = 0, j = 0; i < orig->num_inputs || j < new->num_inputs;) {
		struct input_set *in = tal(ctx, struct input_set);
		if (i >= orig->num_inputs) {
			in->in = tal_dup(*added_ins,
					 struct wally_psbt_input,
					 &new->inputs[j]);
			in->tx_in = tal_dup(*added_ins,
					    struct wally_tx_input,
					    &new->tx->inputs[j]);
			tal_arr_expand(added_ins, in);
			j++;
			continue;
		}
		if (j >= new->num_inputs) {
			in->in = tal_dup(*rm_ins,
					 struct wally_psbt_input,
					 &orig->inputs[i]);
			in->tx_in = tal_dup(*rm_ins,
					    struct wally_tx_input,
					    &orig->tx->inputs[i]);
			tal_arr_expand(rm_ins, in);
			i++;
			continue;
		}

		result = compare_input_at(orig, new, i, j);
		if (result == 1) {
			in->in = tal_dup(*rm_ins,
					 struct wally_psbt_input,
					 &orig->inputs[i]);
			in->tx_in = tal_dup(*rm_ins,
					    struct wally_tx_input,
					    &orig->tx->inputs[i]);
			tal_arr_expand(rm_ins, in);
			i++;
			continue;
		}

		if (result == -1) {
			in->in = tal_dup(*added_ins,
					 struct wally_psbt_input,
					 &new->inputs[j]);
			in->tx_in = tal_dup(*added_ins,
					    struct wally_tx_input,
					    &new->tx->inputs[j]);
			tal_arr_expand(added_ins, in);
			j++;
			continue;
		}

		i++;
		j++;
	}

	/* Find the output diff */
	for (size_t i = 0, j = 0; i < orig->num_outputs || j < new->num_outputs;) {
		struct output_set *out = tal(ctx, struct output_set);
		if (i >= orig->num_outputs) {
			out->out = tal_dup(*added_outs,
					 struct wally_psbt_output,
					 &new->outputs[j]);
			out->tx_out = tal_dup(*added_outs,
					    struct wally_tx_output,
					    &new->tx->outputs[j]);
			tal_arr_expand(added_outs, out);
			j++;
			continue;
		}
		if (j >= new->num_outputs) {
			out->out = tal_dup(*rm_outs,
					 struct wally_psbt_output,
					 &orig->outputs[i]);
			out->tx_out = tal_dup(*rm_outs,
					    struct wally_tx_output,
					    &orig->tx->outputs[i]);
			tal_arr_expand(rm_outs, out);
			i++;
			continue;
		}

		result = compare_output_at(orig, new, i, j);
		if (result == 1) {
			out->out = tal_dup(*rm_outs,
					 struct wally_psbt_output,
					 &orig->outputs[i]);
			out->tx_out = tal_dup(*rm_outs,
					    struct wally_tx_output,
					    &orig->tx->outputs[i]);
			tal_arr_expand(rm_outs, out);
			i++;
			continue;
		}

		if (result == -1) {
			out->out = tal_dup(*added_outs,
					 struct wally_psbt_output,
					 &new->outputs[j]);
			out->tx_out = tal_dup(*added_outs,
					    struct wally_tx_output,
					    &new->tx->outputs[j]);
			tal_arr_expand(added_outs, out);
			j++;
			continue;
		}

		i++;
		j++;
	}

	return tal_count(*added_ins) != 0 ||
		tal_count(*rm_ins) != 0 ||
		tal_count(*added_outs) != 0 ||
		tal_count(*rm_outs) != 0;
}

void psbt_input_add_serial_id(struct wally_psbt_input *input,
			      u16 serial_id)
{
	u8 *key = psbt_make_key(input, PSBT_TYPE_SERIAL_ID, NULL);
	psbt_input_add_unknown(input, key, &serial_id, sizeof(serial_id));
}


void psbt_output_add_serial_id(struct wally_psbt_output *output,
			       u16 serial_id)
{
	u8 *key = psbt_make_key(output, PSBT_TYPE_SERIAL_ID, NULL);
	psbt_output_add_unknown(output, key, &serial_id, sizeof(serial_id));
}

bool psbt_has_serial_input(struct wally_psbt *psbt, u16 serial_id)
{
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		u16 in_serial;
		if (!psbt_get_serial_id(psbt->inputs[i].unknowns, &in_serial))
			continue;
		if (in_serial == serial_id)
			return true;
	}
	return false;
}

bool psbt_has_serial_output(struct wally_psbt *psbt, u16 serial_id)
{
	for (size_t i = 0; i < psbt->num_outputs; i++) {
		u16 out_serial;
		if (!psbt_get_serial_id(psbt->outputs[i].unknowns, &out_serial))
			continue;
		if (out_serial == serial_id)
			return true;
	}
	return false;
}

void psbt_input_add_max_witness_len(struct wally_psbt_input *input,
				    u16 max_witness_len)
{
	u8 *key = psbt_make_key(input, PSBT_TYPE_MAX_WITNESS_LEN, NULL);
	psbt_input_add_unknown(input, key, &max_witness_len, sizeof(max_witness_len));
}


bool psbt_input_get_max_witness_len(struct wally_psbt_input *input,
				    u16 *max_witness_len)
{
	u8 *key = psbt_make_key(tmpctx, PSBT_TYPE_MAX_WITNESS_LEN, NULL);
	size_t value_len;
	void *result = psbt_get_unknown(input->unknowns, key, &value_len);
	if (!result)
		return false;
	assert(value_len == sizeof(*max_witness_len));
	memcpy(max_witness_len, result, value_len);
	return true;
}

bool psbt_has_required_fields(struct wally_psbt *psbt)
{
	u16 max_witness, serial_id;
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct wally_psbt_input *input = &psbt->inputs[i];

		if (!psbt_get_serial_id(input->unknowns, &serial_id))
			return false;

		/* Inputs had also better have their max_witness_lens filled in! */
		if (!psbt_input_get_max_witness_len(input, &max_witness))
			return false;

		/* Required because we send the full tx over the wire now */
		if (!input->non_witness_utxo)
			return false;

		/* If is P2SH, redeemscript must be present */
		size_t outnum = psbt->tx->inputs[i].index;
		const u8 *outscript =
			wally_tx_output_get_script(tmpctx,
				&input->non_witness_utxo->outputs[outnum]);
		if (is_p2sh(outscript, NULL) && input->redeem_script_len == 0)
			return false;

	}

	for (size_t i = 0; i < psbt->num_outputs; i++) {
		if (!psbt_get_serial_id(psbt->outputs[i].unknowns, &serial_id))
			return false;
	}

	return true;
}
