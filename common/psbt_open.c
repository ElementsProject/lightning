#include "config.h"
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/ccan/endian/endian.h>
#include <ccan/ccan/mem/mem.h>
#include <common/psbt_open.h>
#include <common/pseudorand.h>
#include <common/utils.h>
#include <wally_psbt_members.h>

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

static const u8 *get_redeem_script(const tal_t *ctx,
				   const struct wally_psbt *psbt,
				   size_t index)
{
	return psbt_get_script(ctx, psbt, index,
			       wally_psbt_get_input_redeem_script_len,
			       wally_psbt_get_input_redeem_script);
}

/* FIXME: wally_psbt_add_tx_input_at doesn't update the
 * psbt fields for v0 PSBTs :( */
static void psbt_input_outpoint(const struct wally_psbt *psbt,
				size_t index,
				struct bitcoin_outpoint *outp)
{
	if (psbt->version == WALLY_PSBT_VERSION_0) {
		BUILD_ASSERT(sizeof(psbt->tx->inputs[index].txhash)
			     == sizeof(outp->txid));
		memcpy(&outp->txid, psbt->tx->inputs[index].txhash,
		       sizeof(outp->txid));
		outp->n = psbt->tx->inputs[index].index;
	} else {
		BUILD_ASSERT(sizeof(psbt->inputs[index].txhash)
			     == sizeof(outp->txid));
		assert(psbt->version == WALLY_PSBT_VERSION_2);
		memcpy(&outp->txid, psbt->inputs[index].txhash,
		       sizeof(outp->txid));
		outp->n = psbt->inputs[index].index;
	}
}

static u32 psbt_input_sequence(const struct wally_psbt *psbt,
			       size_t index)
{
	if (psbt->version == WALLY_PSBT_VERSION_0) {
		return psbt->tx->inputs[index].sequence;
	} else {
		assert(psbt->version == WALLY_PSBT_VERSION_2);
		return psbt->inputs[index].sequence;
	}
}

/*
 * tx_add_input contains:
 *  msgdata,tx_add_input,serial_id,u64,
 *  msgdata,tx_add_input,prevtx_len,u16,
 *  msgdata,tx_add_input,prevtx,byte,prevtx_len
 *  msgdata,tx_add_input,prevtx_vout,u32,
 *  msgdata,tx_add_input,sequence,u32,
 *  msgdata,tx_add_input,script_sig_len,u16,
 *  msgdata,tx_add_input,script_sig,byte,script_sig_len
 *
 * So, if we compare serial_id, prev txid, prev_vout,
 * sequence and script_sig, that's everything.
 *
 * We already checked: serial_id is identical, but we
 * do it here for completeness.
 */
static bool input_identical(const struct wally_psbt *a,
			    size_t a_index,
			    const struct wally_psbt *b,
			    size_t b_index)
{
	const struct wally_psbt_input *api = &a->inputs[a_index];
	const struct wally_psbt_input *bpi = &b->inputs[b_index];
	u64 serial_a, serial_b;
	const u8 *a_redeem_script, *b_redeem_script;
	struct bitcoin_outpoint out_a, out_b;

	psbt_input_outpoint(a, a_index, &out_a);
	psbt_input_outpoint(b, b_index, &out_b);
	if (!bitcoin_outpoint_eq(&out_a, &out_b))
		return false;

	if (psbt_input_sequence(a, a_index) != psbt_input_sequence(b, b_index))
		return false;

	/* If A doesn't have redeem script, B must not either! */
	a_redeem_script = get_redeem_script(tmpctx, a, a_index);
	b_redeem_script = get_redeem_script(tmpctx, b, b_index);
	if (!memeq(a_redeem_script, tal_bytelen(a_redeem_script),
		   b_redeem_script, tal_bytelen(b_redeem_script)))
		return false;

	if (!psbt_get_serial_id(&api->unknowns, &serial_a))
		return !psbt_get_serial_id(&bpi->unknowns, &serial_b);
	if (!psbt_get_serial_id(&bpi->unknowns, &serial_b))
		return false;
	if (serial_a != serial_b)
		return false;

	return true;
}

/* FIXME: wally only uses these fields for v2, v0 must look at
 * the internal ->tx instead. */
static const u8 *psbt_output_script(const struct wally_psbt *psbt,
				   size_t index)
{
	if (psbt->version == WALLY_PSBT_VERSION_0)
		return psbt->tx->outputs[index].script;

	assert(psbt->version == WALLY_PSBT_VERSION_2);
	return psbt->outputs[index].script;
}

static size_t psbt_output_scriptlen(const struct wally_psbt *psbt,
				   size_t index)
{
	if (psbt->version == WALLY_PSBT_VERSION_0)
		return psbt->tx->outputs[index].script_len;

	assert(psbt->version == WALLY_PSBT_VERSION_2);
	return psbt->outputs[index].script_len;
}

static bool psbt_output_amount(const struct wally_psbt *psbt,
			       size_t index,
			       struct amount_sat *sat)
{
	if (psbt->version == WALLY_PSBT_VERSION_0) {
		*sat = amount_sat(psbt->tx->outputs[index].satoshi);
		return true;
	}

	assert(psbt->version == WALLY_PSBT_VERSION_2);
	if (!psbt->outputs[index].has_amount)
		return false;

	*sat = amount_sat(psbt->outputs[index].amount);
	return true;
}

/*
 * tx_add_output contains:
 *
 *  msgdata,tx_add_output,channel_id,channel_id,
 *  msgdata,tx_add_output,serial_id,u64,
 *  msgdata,tx_add_output,sats,u64,
 *  msgdata,tx_add_output,scriptlen,u16,
 *  msgdata,tx_add_output,script,byte,scriptlen
 */
static bool output_identical(const struct wally_psbt *a,
			     size_t a_index,
			     const struct wally_psbt *b,
			     size_t b_index)
{
	const struct wally_psbt_output *apo = &a->outputs[a_index];
	const struct wally_psbt_output *bpo = &b->outputs[b_index];
	u64 serial_a, serial_b;
	struct amount_sat amount_a, amount_b;

	if (!psbt_get_serial_id(&apo->unknowns, &serial_a))
		return !psbt_get_serial_id(&bpo->unknowns, &serial_b);
	if (!psbt_get_serial_id(&bpo->unknowns, &serial_b))
		return false;
	if (serial_a != serial_b)
		return false;

	if (!memeq(psbt_output_script(a, a_index),
		   psbt_output_scriptlen(a, a_index),
		   psbt_output_script(b, b_index),
		   psbt_output_scriptlen(b, b_index)))
		return false;

	/* FIXME: Not sure we should ever *not* have an amount here? */
	if (!psbt_output_amount(a, a_index, &amount_a))
		return !psbt_output_amount(b, b_index, &amount_b);

	if (!psbt_output_amount(b, b_index, &amount_b))
		return false;

	return amount_sat_eq(amount_a, amount_b);
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
		size_t redeem_script_len;
		if (is_p2sh(outscript, NULL) &&
		    (wally_psbt_get_input_redeem_script_len(psbt, i, &redeem_script_len) != WALLY_OK ||
		     redeem_script_len == 0))
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

bool psbt_contribs_changed(struct wally_psbt *orig,
			   struct wally_psbt *new)
{
	struct psbt_changeset *cs;
	bool ok;
	cs = psbt_get_changeset(NULL, orig, new);

	ok = tal_count(cs->added_ins) > 0 ||
	    tal_count(cs->rm_ins) > 0 ||
	    tal_count(cs->added_outs) > 0 ||
	    tal_count(cs->rm_outs) > 0;

	tal_free(cs);
	return ok;
}
