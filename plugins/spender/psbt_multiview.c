#include "config.h"
#include <assert.h>
#include <bitcoin/psbt.h>
#include <bitcoin/tx.h>
#include <common/amount.h>
#include <common/psbt_open.h>
#include <common/utils.h>
#include <plugins/spender/psbt_multiview.h>

static bool serial_in_list(const u64 *serials, u64 serial)
{
	for (size_t i = 0; i < tal_count(serials); i++)
		if (serials[i] == serial)
			return true;
	return false;
}

bool psbt_multiview_merge(const tal_t *ctx,
			  struct wally_psbt *old_node_psbt,
			  struct wally_psbt *new_node_psbt,
			  const u64 *preserve_in_serials,
			  const u64 *preserve_out_serials,
			  bool *parent_changed,
			  struct wally_psbt **parent_psbt)
{
	struct psbt_changeset *changes;
	struct wally_psbt *clone, *new_node_copy;
	bool changed = false;

	/* Clone the parent, so we don't make any changes to it
	 * until we've succesfully done everything */

	/* Only failure is alloc, should we even check? */
	tal_wally_start();
	if (wally_psbt_clone_alloc(*parent_psbt, 0, &clone) != WALLY_OK)
		abort();
	tal_wally_end_onto(ctx, clone, struct wally_psbt);

	/* This makes it such that we can reparent/steal added
	 * inputs/outputs without impacting the 'original'. We
	 * could avoid this if there was a 'wally_psbt_input_clone_into'
	 * function, or the like */
	tal_wally_start();
	if (wally_psbt_clone_alloc(new_node_psbt, 0, &new_node_copy)
			!= WALLY_OK)
		abort();
	/* copy is cleaned up below, but we need parts we steal from it
	 * owned by the clone.  */
	tal_wally_end(clone);

	changes = psbt_get_changeset(NULL, old_node_psbt,
				     new_node_copy);
	/* Inputs */
	for (size_t i = 0; i < tal_count(changes->added_ins); i++) {
		u64 serial, parent_serial;
		int s_idx;
		const struct wally_psbt_input *in =
			&changes->added_ins[i].input;
		size_t idx = clone->num_inputs;

		if (!psbt_get_serial_id(&in->unknowns, &serial))
			goto fail;

		if (serial % 2 == TX_INITIATOR) {
			/* Daemon-minted entries we've been told to
			 * preserve (e.g. a splice's old-funding input)
			 * go on the parent verbatim; any other input
			 * of ours is already there */
			if (serial_in_list(preserve_in_serials, serial))
				parent_serial = serial;
			else
				continue;
		} else
			parent_serial = serial - 1;

		/* Check that serial does not exist on parent already */
		s_idx = psbt_find_serial_input(clone, parent_serial);
		if (s_idx != -1)
			goto fail;

		const struct wally_psbt_input *input = &changes->added_ins[i].input;
		struct bitcoin_outpoint outpoint;
		wally_psbt_input_get_outpoint(input, &outpoint);
		psbt_append_input(clone,
					&outpoint,
                    input->sequence,
                    NULL /* scriptSig */,
                    NULL /* input_wscript */,
                    NULL /* redeemscript */);

		/* Move the input over */
		clone->inputs[idx] = *in;

		/* Update the added serial on the clone to the correct
		 * position */
		psbt_input_set_serial_id(clone, &clone->inputs[idx],
					 parent_serial);
		changed = true;
	}

	for (size_t i = 0; i < tal_count(changes->rm_ins); i++) {
		u64 serial;
		int s_idx;
		const struct wally_psbt_input *in =
			&changes->rm_ins[i].input;

		if (!psbt_get_serial_id(&in->unknowns, &serial))
			goto fail;

		/* If it's ours, that's a whoops */
		if (serial % 2 == TX_INITIATOR)
			goto fail;

		/* Check that serial exists on parent already */
		s_idx = psbt_find_serial_input(clone, serial - 1);
		if (s_idx == -1)
			goto fail;

		/* Remove input */
		if (wally_psbt_remove_input(clone, s_idx) != WALLY_OK)
			goto fail;
		changed = true;
	}

	/* Outputs */
	for (size_t i = 0; i < tal_count(changes->added_outs); i++) {
		u64 serial, parent_serial;
		const struct wally_psbt_output *out =
			&changes->added_outs[i].output;
		int s_idx;
		size_t idx = clone->num_outputs;

		if (!psbt_get_serial_id(&out->unknowns, &serial))
			goto fail;

		if (serial % 2 == TX_INITIATOR) {
			/* If it's a funding output (or similar
			 * daemon-minted entry), we add it */
			if (serial_in_list(preserve_out_serials, serial)) {
				parent_serial = serial;
			} else
				continue;
		} else
			parent_serial = serial - 1;

		/* Check that serial does not exist on parent already */
		s_idx = psbt_find_serial_output(clone, parent_serial);
		if (s_idx != -1)
			goto fail;

		const struct wally_psbt_output *output = &changes->added_outs[i].output;
		psbt_append_output(clone, output->script, amount_sat(output->amount));

		/* Move output over */
		clone->outputs[idx] = *out;

		/* Update the added serial on the clone to the correct
		 * position */
		psbt_output_set_serial_id(clone, &clone->outputs[idx],
					  parent_serial);
		changed = true;
	}

	for (size_t i = 0; i < tal_count(changes->rm_outs); i++) {
		u64 serial;
		int s_idx;
		const struct wally_psbt_output *out =
			&changes->rm_outs[i].output;

		if (!psbt_get_serial_id(&out->unknowns, &serial))
			goto fail;

		/* If it's ours, that's a whoops */
		if (serial % 2 == TX_INITIATOR)
			goto fail;

		/* Check that serial exists on parent already */
		s_idx = psbt_find_serial_output(clone, serial - 1);
		if (s_idx == -1)
			goto fail;

		/* Remove output */
		if (wally_psbt_remove_output(clone, s_idx) != WALLY_OK)
			goto fail;
		changed = true;
	}

	/* Note: the entries we struct-copied out of new_node_copy stay
	 * alive after new_node_copy is freed because tal_wally_end
	 * parented every allocation from that session (including
	 * new_node_copy's innards) directly onto the clone; freeing the
	 * top-level struct doesn't free them. (The original code here
	 * tried to strip the copied entries out of new_node_copy first,
	 * but its loops never executed -- `size_t i > -1` is always
	 * false -- so this has always relied on the flat reparenting.) */
	tal_free(changes);
	tal_free(new_node_copy);

	tal_free(*parent_psbt);
	*parent_psbt = clone;
	if (parent_changed)
		*parent_changed = changed;
	return true;

fail:
	tal_free(changes);
	tal_free(new_node_copy);
	tal_free(clone);
	return false;
}

bool psbt_multiview_rebuild_node(const tal_t *ctx,
				 const struct wally_psbt *parent_psbt,
				 struct wally_psbt **node_psbt)
{
	/* How to update this? We could do a comparison.
	 * More easily, we simply clone the parent and update
	 * the correct serial_ids for the node_psbt */
	struct wally_psbt *clone;

	tal_wally_start();
	/* Only failure is alloc */
	if (wally_psbt_clone_alloc(parent_psbt, 0, &clone) != WALLY_OK)
		abort();
	tal_wally_end_onto(ctx, clone, struct wally_psbt);

	/* For every peer's input/output, flip the serial id
	 * on the clone. They should all be present. */
	for (size_t i = 0; i < (*node_psbt)->num_inputs; i++) {
		u64 serial_id;
		int input_index;
		if (!psbt_get_serial_id(&(*node_psbt)->inputs[i].unknowns,
					&serial_id)) {
			tal_wally_end(tal_free(clone));
			return false;
		}

		/* We're the initiator here. If it's not the peer's
		 * input, skip it */
		if (serial_id % 2 == TX_INITIATOR)
			continue;
		/* Down one, as that's where it'll be on the parent */
		input_index = psbt_find_serial_input(clone, serial_id - 1);
		/* Must exist */
		assert(input_index != -1);
		/* Update the cloned input serial to match the node's
		 * view */
		psbt_input_set_serial_id(clone, &clone->inputs[input_index],
					 serial_id);

	}

	for (size_t i = 0; i < (*node_psbt)->num_outputs; i++) {
		u64 serial_id;
		int output_index;
		if (!psbt_get_serial_id(&(*node_psbt)->outputs[i].unknowns,
					&serial_id)) {
			tal_wally_end(tal_free(clone));
			return false;
		}
		/* We're the initiator here. If it's not the peer's
		 * output, skip it */
		if (serial_id % 2 == TX_INITIATOR)
			continue;

		/* Down one, as that's where it'll be on the parent */
		output_index = psbt_find_serial_output(clone,
						       serial_id - 1);
		/* Must exist */
		assert(output_index != -1);

		/* Update the cloned input serial to match the node's
		 * view */
		psbt_output_set_serial_id(clone, &clone->outputs[output_index],
					  serial_id);

	}

	tal_free(*node_psbt);
	*node_psbt = clone;
	return true;
}
