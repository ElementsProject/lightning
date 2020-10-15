#include "common/psbt_open.h"
#include <assert.h>
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/asort/asort.h>
#include <ccan/ccan/endian/endian.h>
#include <ccan/ccan/mem/mem.h>
#include <common/channel_id.h>
#include <common/pseudorand.h>
#include <common/utils.h>
#include <wire/peer_wire.h>

bool psbt_get_serial_id(const struct wally_map *map, u16 *serial_id)
{
	size_t value_len;
	beint16_t bev;
	void *result = psbt_get_lightning(map, PSBT_TYPE_SERIAL_ID, &value_len);
	if (!result)
		return false;

	if (value_len != sizeof(bev))
		return false;

	memcpy(&bev, result, value_len);
	*serial_id = be16_to_cpu(bev);
	return true;
}

static int compare_serials(const struct wally_map *map_a,
			   const struct wally_map *map_b)
{
	u16 serial_left, serial_right;
	bool ok;

	ok = psbt_get_serial_id(map_a, &serial_left);
	assert(ok);
	ok = psbt_get_serial_id(map_b, &serial_right);
	assert(ok);
	if (serial_left > serial_right)
		return 1;
	if (serial_left < serial_right)
		return -1;
	return 0;
}

static int compare_inputs_at(const struct input_set *a,
			     const struct input_set *b,
			     void *unused UNUSED)
{
	return compare_serials(&a->input.unknowns,
			       &b->input.unknowns);
}

static int compare_outputs_at(const struct output_set *a,
			      const struct output_set *b,
			      void *unused UNUSED)
{
	return compare_serials(&a->output.unknowns,
			       &b->output.unknowns);
}

static const u8 *linearize_input(const tal_t *ctx,
				 const struct wally_psbt_input *in,
				 const struct wally_tx_input *tx_in)
{
	struct wally_psbt *psbt = create_psbt(NULL, 1, 0, 0);
	size_t byte_len;

	tal_wally_start();
	if (wally_tx_add_input(psbt->tx, tx_in) != WALLY_OK)
		abort();
	tal_wally_end(psbt->tx);

	psbt->inputs[0] = *in;
	psbt->num_inputs++;


	/* Sort the inputs, so serializing them is ok */
	wally_map_sort(&psbt->inputs[0].unknowns, 0);

	/* signatures, keypaths, etc - we dont care if they change */
	psbt->inputs[0].final_witness = NULL;
	psbt->inputs[0].final_scriptsig_len = 0;
	psbt->inputs[0].witness_script_len = 0;
	psbt->inputs[0].redeem_script_len = 0;
	psbt->inputs[0].keypaths.num_items = 0;
	psbt->inputs[0].signatures.num_items = 0;


	const u8 *bytes = psbt_get_bytes(ctx, psbt, &byte_len);

	/* Hide the inputs we added, so it doesn't get freed */
	psbt->num_inputs--;
	tal_free(psbt);
	return bytes;
}

static const u8 *linearize_output(const tal_t *ctx,
				  const struct wally_psbt_output *out,
				  const struct wally_tx_output *tx_out)
{
	struct wally_psbt *psbt = create_psbt(NULL, 1, 1, 0);
	size_t byte_len;
	struct bitcoin_txid txid;

	/* Add a 'fake' input so this will linearize the tx */
	memset(&txid, 0, sizeof(txid));
	psbt_append_input(psbt, &txid, 0, 0, NULL, NULL, NULL);

	tal_wally_start();
	if (wally_tx_add_output(psbt->tx, tx_out) != WALLY_OK)
		abort();
	tal_wally_end(psbt->tx);

	psbt->outputs[0] = *out;
	psbt->num_outputs++;
	/* Sort the outputs, so serializing them is ok */
	wally_map_sort(&psbt->outputs[0].unknowns, 0);

	/* We don't care if the keypaths change */
	psbt->outputs[0].keypaths.num_items = 0;
	/* And you can add scripts, no problem */
	psbt->outputs[0].witness_script_len = 0;
	psbt->outputs[0].redeem_script_len = 0;

	const u8 *bytes = psbt_get_bytes(ctx, psbt, &byte_len);

	/* Hide the outputs we added, so it doesn't get freed */
	psbt->num_outputs--;
	tal_free(psbt);
	return bytes;
}

static bool input_identical(const struct wally_psbt *a,
			    size_t a_index,
			    const struct wally_psbt *b,
			    size_t b_index)
{
	const u8 *a_in = linearize_input(tmpctx,
					 &a->inputs[a_index],
					 &a->tx->inputs[a_index]);
	const u8 *b_in = linearize_input(tmpctx,
					 &b->inputs[b_index],
					 &b->tx->inputs[b_index]);

	return memeq(a_in, tal_bytelen(a_in),
		     b_in, tal_bytelen(b_in));
}

static bool output_identical(const struct wally_psbt *a,
			     size_t a_index,
			     const struct wally_psbt *b,
			     size_t b_index)
{
	const u8 *a_out = linearize_output(tmpctx,
					   &a->outputs[a_index],
					   &a->tx->outputs[a_index]);
	const u8 *b_out = linearize_output(tmpctx,
					   &b->outputs[b_index],
					   &b->tx->outputs[b_index]);
	return memeq(a_out, tal_bytelen(a_out),
		     b_out, tal_bytelen(b_out));
}

static void sort_inputs(struct wally_psbt *psbt)
{
	/* Build an input map */
	struct input_set *set = tal_arr(NULL,
					struct input_set,
					psbt->num_inputs);

	for (size_t i = 0; i < tal_count(set); i++) {
		set[i].tx_input = psbt->tx->inputs[i];
		set[i].input = psbt->inputs[i];
	}

	asort(set, tal_count(set),
	      compare_inputs_at, NULL);

	/* Put PSBT parts into place */
	for (size_t i = 0; i < tal_count(set); i++) {
		psbt->inputs[i] = set[i].input;
		psbt->tx->inputs[i] = set[i].tx_input;
	}

	tal_free(set);
}

static void sort_outputs(struct wally_psbt *psbt)
{
	/* Build an output map */
	struct output_set *set = tal_arr(NULL,
					 struct output_set,
					 psbt->num_outputs);
	for (size_t i = 0; i < tal_count(set); i++) {
		set[i].tx_output = psbt->tx->outputs[i];
		set[i].output = psbt->outputs[i];
	}

	asort(set, tal_count(set),
	      compare_outputs_at, NULL);

	/* Put PSBT parts into place */
	for (size_t i = 0; i < tal_count(set); i++) {
		psbt->outputs[i] = set[i].output;
		psbt->tx->outputs[i] = set[i].tx_output;
	}

	tal_free(set);
}

void psbt_sort_by_serial_id(struct wally_psbt *psbt)
{
	sort_inputs(psbt);
	sort_outputs(psbt);
}

#define ADD(type, add_to, from, index)				\
	do {							\
		struct type##_set a;				\
		a.type = from->type##s[index];			\
		a.tx_##type = from->tx->type##s[index]; 	\
		tal_arr_expand(&add_to, a);			\
	} while (0)

static struct psbt_changeset *new_changeset(const tal_t *ctx)
{
	struct psbt_changeset *set = tal(ctx, struct psbt_changeset);

	set->added_ins = tal_arr(set, struct input_set, 0);
	set->rm_ins = tal_arr(set, struct input_set, 0);
	set->added_outs = tal_arr(set, struct output_set, 0);
	set->rm_outs = tal_arr(set, struct output_set, 0);

	return set;
}

/* this requires having a serial_id entry on everything */
/* YOU MUST KEEP orig + new AROUND TO USE THE RESULTING SETS */
struct psbt_changeset *psbt_get_changeset(const tal_t *ctx,
					  struct wally_psbt *orig,
					  struct wally_psbt *new)
{
	int result;
	size_t i = 0, j = 0;
	struct psbt_changeset *set;

	psbt_sort_by_serial_id(orig);
	psbt_sort_by_serial_id(new);

	set = new_changeset(ctx);

	/* Find the input diff */
	while (i < orig->num_inputs || j < new->num_inputs) {
		if (i >= orig->num_inputs) {
			ADD(input, set->added_ins, new, j);
			j++;
			continue;
		}
		if (j >= new->num_inputs) {
			ADD(input, set->rm_ins, orig, i);
			i++;
			continue;
		}

		result = compare_serials(&orig->inputs[i].unknowns,
					 &new->inputs[j].unknowns);
		if (result == -1) {
			ADD(input, set->rm_ins, orig, i);
			i++;
			continue;
		}
		if (result == 1) {
			ADD(input, set->added_ins, new, j);
			j++;
			continue;
		}

		if (!input_identical(orig, i, new, j)) {
			ADD(input, set->rm_ins, orig, i);
			ADD(input, set->added_ins, new, j);
		}
		i++;
		j++;
	}
	/* Find the output diff */
	i = 0;
	j = 0;
	while (i < orig->num_outputs || j < new->num_outputs) {
		if (i >= orig->num_outputs) {
			ADD(output, set->added_outs, new, j);
			j++;
			continue;
		}
		if (j >= new->num_outputs) {
			ADD(output, set->rm_outs, orig, i);
			i++;
			continue;
		}

		result = compare_serials(&orig->outputs[i].unknowns,
					 &new->outputs[j].unknowns);
		if (result == -1) {
			ADD(output, set->rm_outs, orig, i);
			i++;
			continue;
		}
		if (result == 1) {
			ADD(output, set->added_outs, new, j);
			j++;
			continue;
		}
		if (!output_identical(orig, i, new, j)) {
			ADD(output, set->rm_outs, orig, i);
			ADD(output, set->added_outs, new, j);
		}
		i++;
		j++;
	}

	return set;
}

u8 *psbt_changeset_get_next(const tal_t *ctx, struct channel_id *cid,
			    struct psbt_changeset *set)
{
	u16 serial_id;
	u8 *msg;

	if (tal_count(set->added_ins) != 0) {
		const struct input_set *in = &set->added_ins[0];
		u8 *script;

		if (!psbt_get_serial_id(&in->input.unknowns, &serial_id))
			abort();

		const u8 *prevtx = linearize_wtx(ctx,
						 in->input.utxo);

		if (in->input.redeem_script_len)
			script = tal_dup_arr(ctx, u8,
					     in->input.redeem_script,
					     in->input.redeem_script_len, 0);
		else
			script = NULL;

		msg = towire_tx_add_input(ctx, cid, serial_id,
					  prevtx, in->tx_input.index,
					  in->tx_input.sequence,
					  script,
					  NULL);

		tal_arr_remove(&set->added_ins, 0);
		return msg;
	}
	if (tal_count(set->rm_ins) != 0) {
		if (!psbt_get_serial_id(&set->rm_ins[0].input.unknowns,
					&serial_id))
			abort();

		msg = towire_tx_remove_input(ctx, cid, serial_id);

		tal_arr_remove(&set->rm_ins, 0);
		return msg;
	}
	if (tal_count(set->added_outs) != 0) {
		struct amount_sat sats;
		struct amount_asset asset_amt;

		const struct output_set *out = &set->added_outs[0];
		if (!psbt_get_serial_id(&out->output.unknowns, &serial_id))
			abort();

		asset_amt = wally_tx_output_get_amount(&out->tx_output);
		sats = amount_asset_to_sat(&asset_amt);
		const u8 *script = wally_tx_output_get_script(ctx,
							      &out->tx_output);

		msg = towire_tx_add_output(ctx, cid, serial_id,
					   sats.satoshis, /* Raw: wire interface */
					   script);

		tal_arr_remove(&set->added_outs, 0);
		return msg;
	}
	if (tal_count(set->rm_outs) != 0) {
		if (!psbt_get_serial_id(&set->rm_outs[0].output.unknowns,
					&serial_id))
			abort();

		msg = towire_tx_remove_output(ctx, cid, serial_id);

		/* Is this a kosher way to move the list forward? */
		tal_arr_remove(&set->rm_outs, 0);
		return msg;
	}
	return NULL;
}

void psbt_input_set_serial_id(const tal_t *ctx,
			      struct wally_psbt_input *input,
			      u16 serial_id)
{
	u8 *key = psbt_make_key(tmpctx, PSBT_TYPE_SERIAL_ID, NULL);
	beint16_t bev = cpu_to_be16(serial_id);

	psbt_input_set_unknown(ctx, input, key, &bev, sizeof(bev));
}


void psbt_output_set_serial_id(const tal_t *ctx,
			       struct wally_psbt_output *output,
			       u16 serial_id)
{
	u8 *key = psbt_make_key(tmpctx, PSBT_TYPE_SERIAL_ID, NULL);
	beint16_t bev = cpu_to_be16(serial_id);
	psbt_output_set_unknown(ctx, output, key, &bev, sizeof(bev));
}

int psbt_find_serial_input(struct wally_psbt *psbt, u16 serial_id)
{
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		u16 in_serial;
		if (!psbt_get_serial_id(&psbt->inputs[i].unknowns, &in_serial))
			continue;
		if (in_serial == serial_id)
			return i;
	}
	return -1;
}

int psbt_find_serial_output(struct wally_psbt *psbt, u16 serial_id)
{
	for (size_t i = 0; i < psbt->num_outputs; i++) {
		u16 out_serial;
		if (!psbt_get_serial_id(&psbt->outputs[i].unknowns, &out_serial))
			continue;
		if (out_serial == serial_id)
			return i;
	}
	return -1;
}

static u16 get_random_serial(enum tx_role role)
{
	return pseudorand(1 << 15) << 1 | role;
}

u16 psbt_new_input_serial(struct wally_psbt *psbt, enum tx_role role)
{
	u16 serial_id;

	while ((serial_id = get_random_serial(role)) &&
		psbt_find_serial_input(psbt, serial_id) != -1) {
		/* keep going; */
	}

	return serial_id;
}

u16 psbt_new_output_serial(struct wally_psbt *psbt, enum tx_role role)
{
	u16 serial_id;

	while ((serial_id = get_random_serial(role)) &&
		psbt_find_serial_output(psbt, serial_id) != -1) {
		/* keep going; */
	}

	return serial_id;
}

bool psbt_has_required_fields(struct wally_psbt *psbt)
{
	u16 serial_id;
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct wally_psbt_input *input = &psbt->inputs[i];

		if (!psbt_get_serial_id(&input->unknowns, &serial_id))
			return false;

		/* Required because we send the full tx over the wire now */
		if (!input->utxo)
			return false;

		/* If is P2SH, redeemscript must be present */
		assert(psbt->tx->inputs[i].index < input->utxo->num_outputs);
		const u8 *outscript =
			wally_tx_output_get_script(tmpctx,
				&input->utxo->outputs[psbt->tx->inputs[i].index]);
		if (is_p2sh(outscript, NULL) && input->redeem_script_len == 0)
			return false;

	}

	for (size_t i = 0; i < psbt->num_outputs; i++) {
		if (!psbt_get_serial_id(&psbt->outputs[i].unknowns, &serial_id))
			return false;
	}

	return true;
}

void psbt_input_set_final_witness_stack(struct wally_psbt_input *in,
					const struct witness_element **elements)
{
	wally_tx_witness_stack_init_alloc(tal_count(elements),
					  &in->final_witness);

	for (size_t i = 0; i < tal_count(elements); i++)
		wally_tx_witness_stack_add(in->final_witness,
					   elements[i]->witness,
					   tal_bytelen(elements[i]->witness));
}

const struct witness_stack **
psbt_to_witness_stacks(const tal_t *ctx,
		       const struct wally_psbt *psbt,
		       enum tx_role side_to_stack)
{
	size_t stack_index;
	u16 serial_id;
	const struct witness_stack **stacks
		= tal_arr(ctx, const struct witness_stack *, psbt->num_inputs);

	stack_index = 0;
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		if (!psbt_get_serial_id(&psbt->inputs[i].unknowns,
					&serial_id))
			/* FIXME: throw an error ? */
			return NULL;

		/* BOLT-78de9a79b491ae9fb84b1fdb4546bacf642dce87 #2:
		 * - if is the `initiator`:
		 *   - MUST send even `serial_id`s
		 */
		if (serial_id % 2 == side_to_stack) {
			struct wally_tx_witness_stack *wtx_s =
				psbt->inputs[i].final_witness;
			struct witness_stack *stack =
				tal(stacks, struct witness_stack);
			/* Convert the wally_tx_witness_stack to
			 * a witness_stack entry */
			stack->witness_element =
				tal_arr(stack, struct witness_element *,
					wtx_s->num_items);
			for (size_t j = 0; j < tal_count(stack->witness_element); j++) {
				stack->witness_element[j] = tal(stack,
								struct witness_element);
				stack->witness_element[j]->witness =
					tal_dup_arr(stack, u8,
						    wtx_s->items[j].witness,
						    wtx_s->items[j].witness_len,
						    0);

			}

			stacks[stack_index++] = stack;
		}

	}

	if (stack_index == 0)
		return tal_free(stacks);

	tal_resize(&stacks, stack_index);
	return stacks;
}

bool psbt_side_finalized(const struct wally_psbt *psbt, enum tx_role role)
{
	u16 serial_id;
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		if (!psbt_get_serial_id(&psbt->inputs[i].unknowns,
					&serial_id)) {
			return false;
		}
		if (serial_id % 2 == role) {
			if (!psbt->inputs[i].final_witness ||
					psbt->inputs[i].final_witness->num_items == 0)
				return false;
		}
	}
	return true;
}

/* Adds serials to inputs + outputs that don't have one yet */
void psbt_add_serials(struct wally_psbt *psbt, enum tx_role role)
{
	u16 serial_id;
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		/* Skip ones that already have a serial id */
		if (psbt_get_serial_id(&psbt->inputs[i].unknowns, &serial_id))
			continue;

		serial_id = psbt_new_input_serial(psbt, role);
		psbt_input_set_serial_id(psbt, &psbt->inputs[i], serial_id);
	}
	for (size_t i = 0; i < psbt->num_outputs; i++) {
		/* Skip ones that already have a serial id */
		if (psbt_get_serial_id(&psbt->outputs[i].unknowns, &serial_id))
			continue;

		serial_id = psbt_new_output_serial(psbt, role);
		psbt_output_set_serial_id(psbt, &psbt->outputs[i], serial_id);
	}
}
