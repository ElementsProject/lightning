#include "config.h"
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/asort/asort.h>
#include <ccan/ccan/endian/endian.h>
#include <ccan/ccan/mem/mem.h>
#include <common/channel_id.h>
#include <common/psbt_open.h>
#include <common/pseudorand.h>
#include <common/utils.h>

#define MAX_CHANNEL_IDS 4096

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
				 const struct wally_psbt_input *in)
{
	struct wally_psbt *psbt = create_psbt(NULL, 1, 0, 0);
	size_t byte_len;

	psbt->inputs[0] = *in;
	psbt->num_inputs++;


	/* Sort the inputs, so serializing them is ok */
	wally_map_sort(&psbt->inputs[0].unknowns, 0);

	/* signatures, keypaths, etc - we dont care if they change */
	wally_psbt_input_set_final_witness(&psbt->inputs[0], NULL);
	wally_psbt_input_set_final_scriptsig(&psbt->inputs[0], NULL, 0);
	wally_psbt_input_set_witness_script(&psbt->inputs[0], NULL, 0);
	wally_psbt_input_set_redeem_script(&psbt->inputs[0], NULL, 0);
	wally_psbt_input_set_taproot_signature(&psbt->inputs[0], NULL, 0);
	psbt->inputs[0].taproot_leaf_hashes.num_items = 0;
	psbt->inputs[0].taproot_leaf_paths.num_items = 0;
	psbt->inputs[0].keypaths.num_items = 0;
	psbt->inputs[0].signatures.num_items = 0;
	psbt->inputs[0].utxo = NULL;
	psbt->inputs[0].witness_utxo = NULL;

	const u8 *bytes = psbt_get_bytes(ctx, psbt, &byte_len);

	/* Hide the inputs we added, so it doesn't get freed */
	psbt->num_inputs--;
	tal_free(psbt);
	return bytes;
}

static const u8 *linearize_output(const tal_t *ctx,
				  const struct wally_psbt_output *out)
{
	struct wally_psbt *psbt = create_psbt(NULL, 1, 1, 0);
	size_t byte_len;
	struct bitcoin_outpoint outpoint;

	/* Add a 'fake' non-zero input so libwally will agree to linearize the tx */
	memset(&outpoint, 1, sizeof(outpoint));
	psbt_append_input(psbt, &outpoint, 0, NULL, NULL, NULL);

	psbt->outputs[0] = *out;
	psbt->num_outputs++;
	/* Sort the outputs, so serializing them is ok */
	wally_map_sort(&psbt->outputs[0].unknowns, 0);

	/* We don't care if the keypaths change */
	psbt->outputs[0].keypaths.num_items = 0;
	psbt->outputs[0].taproot_leaf_hashes.num_items = 0;
	psbt->outputs[0].taproot_leaf_paths.num_items = 0;
	/* And you can add scripts, no problem */
	wally_psbt_output_set_witness_script(&psbt->outputs[0], NULL, 0);
	wally_psbt_output_set_redeem_script(&psbt->outputs[0], NULL, 0);

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
					 &a->inputs[a_index]);
	const u8 *b_in = linearize_input(tmpctx,
					 &b->inputs[b_index]);

	return tal_arr_eq(a_in, b_in);
}

static bool output_identical(const struct wally_psbt *a,
			     size_t a_index,
			     const struct wally_psbt *b,
			     size_t b_index)
{
	const u8 *a_out = linearize_output(tmpctx,
					   &a->outputs[a_index]);
	const u8 *b_out = linearize_output(tmpctx,
					   &b->outputs[b_index]);
	return tal_arr_eq(a_out, b_out);
}

static void sort_inputs(struct wally_psbt *psbt)
{
	/* Build an input map */
	struct input_set *set = tal_arr(NULL,
					struct input_set,
					psbt->num_inputs);

	for (size_t i = 0; i < tal_count(set); i++) {
		set[i].input = psbt->inputs[i];
	}

	asort(set, tal_count(set),
	      compare_inputs_at, NULL);

	/* Put PSBT parts into place */
	for (size_t i = 0; i < tal_count(set); i++) {
		psbt->inputs[i] = set[i].input;
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
		set[i].output = psbt->outputs[i];
	}

	asort(set, tal_count(set),
	      compare_outputs_at, NULL);

	/* Put PSBT parts into place */
	for (size_t i = 0; i < tal_count(set); i++) {
		psbt->outputs[i] = set[i].output;
	}

	tal_free(set);
}

void psbt_sort_by_serial_id(struct wally_psbt *psbt)
{
	sort_inputs(psbt);
	sort_outputs(psbt);
}

bool psbt_get_channel_ids(const tal_t *ctx,
			  const struct wally_psbt *psbt,
			  struct channel_id **channel_ids)
{
	size_t value_len;
	void *res = psbt_get_lightning(&psbt->unknowns, PSBT_TYPE_CHANNELIDS,
				       &value_len);
	if (!res)
		return false;

	/* Max channel id limit */
	if (value_len > MAX_CHANNEL_IDS * 32)
		return false;

	/* Must be a multiple of 32 */
	if (value_len % 32)
		return false;

	*channel_ids = tal_arr(ctx, struct channel_id, value_len / 32);
	for (size_t i = 0; i < value_len / 32; i++)
		memcpy((*channel_ids)[i].id, res + i * 32, 32);

	return true;
}

void psbt_set_channel_ids(struct wally_psbt *psbt,
			  struct channel_id *channel_ids)
{
	BUILD_ASSERT(sizeof(channel_ids[0].id) == 32);
	int data_size = tal_count(channel_ids) * 32;
	u8 *data = tal_arr(tmpctx, u8, data_size);

	for (size_t i = 0; i < tal_count(channel_ids); i++)
		memcpy(data + i * 32, channel_ids[i].id, 32);

	psbt_set_lightning(psbt,
			   &psbt->unknowns,
			   PSBT_TYPE_CHANNELIDS,
			   data,
			   data_size);
}

/* psbt_set_channel_ids - Stores the channel_ids in the PSBT
 *
 * @psbt - the psbt to put the channel_ids into
 * @channel_ids - the channel ids to put in
 */
void psbt_set_channel_ids(struct wally_psbt *psbt,
			  struct channel_id *channel_ids);

#define ADD(type, add_to, from, index)				\
	do {							\
		struct type##_set a;				\
		a.type = from->type##s[index];			\
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
		const struct wally_map_item *redeem_script;
		const struct wally_tx_output *txout;
		struct wally_psbt_input *input = &psbt->inputs[i];

		if (!psbt_get_serial_id(&input->unknowns, &serial_id))
			return false;

		/* Required because we send the full tx over the wire now */
		if (!input->utxo)
			return false;

		assert(input->index < input->utxo->num_outputs);
		txout = &input->utxo->outputs[input->index];
		if (!is_p2sh(txout->script, txout->script_len, NULL))
			continue;
		/* P2SH: redeemscript must be present */
		const u32 key = 0x04; /* PSBT_IN_REDEEM_SCRIPT */
		redeem_script = wally_map_get_integer(&input->psbt_fields, key);
		if (!redeem_script || !redeem_script->value_len)
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

bool psbt_has_our_input(const struct wally_psbt *psbt)
{
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		if (psbt_input_is_ours(&psbt->inputs[i]))
			return true;
	}

	return false;
}

void psbt_output_mark_as_external(const tal_t *ctx,
				  struct wally_psbt_output *output)
{
	u8 *key = psbt_make_key(tmpctx, PSBT_TYPE_OUTPUT_EXTERNAL, NULL);
	beint16_t bev = cpu_to_be16(1);

	psbt_output_set_unknown(ctx, output, key, &bev, sizeof(bev));
}

bool psbt_output_to_external(const struct wally_psbt_output *output)
{
	size_t unused;
	void *result = psbt_get_lightning(&output->unknowns,
					  PSBT_TYPE_OUTPUT_EXTERNAL, &unused);
	return !(!result);
}

/* FIXME: both PSBT should be const */
bool psbt_contribs_changed(struct wally_psbt *orig,
			   struct wally_psbt *new)
{
	struct psbt_changeset *cs;
	bool ok;

	assert(orig->version == 2 && new->version == 2);

	cs = psbt_get_changeset(NULL, orig, new);

	ok = tal_count(cs->added_ins) > 0 ||
	    tal_count(cs->rm_ins) > 0 ||
	    tal_count(cs->added_outs) > 0 ||
	    tal_count(cs->rm_outs) > 0;
	tal_free(cs);
	return ok;
}
