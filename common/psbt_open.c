#include "common/psbt_open.h"
#include <assert.h>
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/asort/asort.h>
#include <ccan/ccan/endian/endian.h>
#include <ccan/ccan/mem/mem.h>
#include <common/pseudorand.h>
#include <common/utils.h>

bool psbt_get_serial_id(const struct wally_map *map, u64 *serial_id)
{
	size_t value_len;
	beint64_t bev;
	void *result = psbt_get_lightning(map, PSBT_TYPE_SERIAL_ID, &value_len);
	if (!result)
		return false;

	if (value_len != sizeof(bev))
		return false;

	memcpy(&bev, result, value_len);
	*serial_id = be64_to_cpu(bev);
	return true;
}

static int compare_serials(const struct wally_map *map_a,
			   const struct wally_map *map_b)
{
	u64 serial_left, serial_right;
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
		a.idx = index;					\
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


void psbt_input_set_serial_id(const tal_t *ctx,
			      struct wally_psbt_input *input,
			      u64 serial_id)
{
	u8 *key = psbt_make_key(tmpctx, PSBT_TYPE_SERIAL_ID, NULL);
	beint64_t bev = cpu_to_be64(serial_id);

	psbt_input_set_unknown(ctx, input, key, &bev, sizeof(bev));
}


void psbt_output_set_serial_id(const tal_t *ctx,
			       struct wally_psbt_output *output,
			       u64 serial_id)
{
	u8 *key = psbt_make_key(tmpctx, PSBT_TYPE_SERIAL_ID, NULL);
	beint64_t bev = cpu_to_be64(serial_id);
	psbt_output_set_unknown(ctx, output, key, &bev, sizeof(bev));
}

int psbt_find_serial_input(struct wally_psbt *psbt, u64 serial_id)
{
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		u64 in_serial;
		if (!psbt_get_serial_id(&psbt->inputs[i].unknowns, &in_serial))
			continue;
		if (in_serial == serial_id)
			return i;
	}
	return -1;
}

int psbt_find_serial_output(struct wally_psbt *psbt, u64 serial_id)
{
	for (size_t i = 0; i < psbt->num_outputs; i++) {
		u64 out_serial;
		if (!psbt_get_serial_id(&psbt->outputs[i].unknowns, &out_serial))
			continue;
		if (out_serial == serial_id)
			return i;
	}
	return -1;
}

static u64 get_random_serial(enum tx_role role)
{
	return pseudorand_u64() << 1 | role;
}

u64 psbt_new_input_serial(struct wally_psbt *psbt, enum tx_role role)
{
	u64 serial_id;

	while ((serial_id = get_random_serial(role)) &&
		psbt_find_serial_input(psbt, serial_id) != -1) {
		/* keep going; */
	}

	return serial_id;
}

u64 psbt_new_output_serial(struct wally_psbt *psbt, enum tx_role role)
{
	u64 serial_id;

	while ((serial_id = get_random_serial(role)) &&
		psbt_find_serial_output(psbt, serial_id) != -1) {
		/* keep going; */
	}

	return serial_id;
}

bool psbt_has_required_fields(struct wally_psbt *psbt)
{
	u64 serial_id;
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

bool psbt_side_finalized(const struct wally_psbt *psbt, enum tx_role role)
{
	u64 serial_id;
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
	u64 serial_id;
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

void psbt_input_mark_ours(const tal_t *ctx,
			  struct wally_psbt_input *input)
{
	u8 *key = psbt_make_key(tmpctx, PSBT_TYPE_INPUT_MARKER, NULL);
	beint16_t bev = cpu_to_be16(1);

	psbt_input_set_unknown(ctx, input, key, &bev, sizeof(bev));
}

bool psbt_input_is_ours(const struct wally_psbt_input *input)
{
	size_t unused;
	void *result = psbt_get_lightning(&input->unknowns,
					  PSBT_TYPE_INPUT_MARKER, &unused);
	return !(!result);
}
