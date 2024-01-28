#include "config.h"
#include <bitcoin/psbt.h>
#include <ccan/ccan/array_size/array_size.h>
#include <ccan/ccan/mem/mem.h>
#include <common/json_channel_type.h>
#include <common/json_stream.h>
#include <common/lease_rates.h>
#include <common/psbt_open.h>
#include <common/type_to_string.h>
#include <plugins/spender/multifundchannel.h>
#include <plugins/spender/openchannel.h>

static struct list_head mfc_commands;

static void
destroy_mfc(struct multifundchannel_command *mfc)
{
	list_del(&mfc->list);
}

void register_mfc(struct multifundchannel_command *mfc)
{
	assert(mfc);

	list_add_tail(&mfc_commands, &mfc->list);
	tal_add_destructor(mfc, &destroy_mfc);
}

static struct multifundchannel_destination *
find_dest_by_channel_id(struct channel_id *cid)
{
	struct multifundchannel_command *mfc, *n;

	list_for_each_safe (&mfc_commands, mfc, n, list) {
		for (size_t i = 0; i < tal_count(mfc->destinations); i++) {
			struct multifundchannel_destination *dest =
				&mfc->destinations[i];
			if (channel_id_eq(&dest->channel_id, cid))
				return dest;
		}
	}

	return NULL;
}

/* There's a few ground rules here about how we store/keep
 * the PSBT input/outputs in such a way that we can Do The
 * Right Thing for each of our peers.
 *
 * Core Lightning will make sure that our peer isn't removing/adding
 * any updates that it's not allowed to (i.e. ours or a different
 * node's that we're pretending are 'ours').
 *
 * The parent copy of the PSBT has all of the inputs/outputs added to it,
 * but the serial_ids are decremented by one to the even-pair, e.g. a
 * serial_id of 3 -> 2; 17 -> 16; etc.
 *
 * If the even-pair of a provided serial_id is taken/occupied,
 * the update is rejected (the parent is unmodified and the
 * function returns false).
 *
 * The peer's inputs/outputs updates are then copied to the parent psbt.
 */
static bool update_parent_psbt(const tal_t *ctx,
			       struct multifundchannel_destination *dest,
			       struct wally_psbt *old_node_psbt,
			       struct wally_psbt *new_node_psbt,
			       struct wally_psbt **parent_psbt)
{
	struct psbt_changeset *changes;
	struct wally_psbt *clone, *new_node_copy;

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
		u64 serial;
		int s_idx;
		const struct wally_psbt_input *in =
			&changes->added_ins[i].input;
		size_t idx = clone->num_inputs;

		if (!psbt_get_serial_id(&in->unknowns, &serial))
			goto fail;

		/* Ignore any input that's ours */
		if (serial % 2 == TX_INITIATOR)
			continue;

		/* Check that serial does not exist on parent already */
		s_idx = psbt_find_serial_input(clone, serial - 1);
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
					 serial - 1);
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
			/* If it's the funding output, we add it */
			if (serial == dest->funding_serial) {
				parent_serial = dest->funding_serial;
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
	}

	/* We want to preserve the memory bits associated with
	 * the inputs/outputs we just copied over when we free
	 * the copy, so remove ones the *added* from the copy.
	 * We go from the back since this will modify the indexes */
	for (size_t i = tal_count(changes->added_ins) - 1;
	     i > -1;
	     i--) {
		psbt_rm_input(new_node_copy,
			      changes->added_ins[i].idx);
	}
	for (size_t i = tal_count(changes->added_outs) - 1;
	     i > -1;
	     i--) {
		psbt_rm_output(new_node_copy,
			      changes->added_outs[i].idx);
	}

	tal_free(changes);
	tal_free(new_node_copy);

	tal_free(*parent_psbt);
	*parent_psbt = clone;
	return true;

fail:
	tal_free(changes);
	tal_free(new_node_copy);
	tal_free(clone);
	return false;
}

/* After all of the changes have been applied to the parent psbt,
 * we update each node_psbt with the changes from every *other* peer.
 *
 * This updated node_psbt is the one that we should pass to
 * openchannel_update for the next round.
 *
 * We do update rounds until every peer returns "commitment_secured:true",
 * which will happen at the same round (as it requires us passing in
 * an identical PSBT as the previous round).
 */
static bool update_node_psbt(const tal_t *ctx,
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

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*
 * To collect signatures from our peers, we use a notification watcher.
 *~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*
 */
static struct command_result *
openchannel_finished(struct multifundchannel_command *mfc)
{
	for (size_t i = 0; i < tal_count(mfc->destinations); i++) {
		struct multifundchannel_destination *dest;
		dest = &mfc->destinations[i];

		/* If there's a single failure, we have to
		 * return the failure to the user. */
		if (dest->state == MULTIFUNDCHANNEL_FAILED) {
			struct json_stream *out;

			plugin_log(mfc->cmd->plugin, LOG_DBG,
				   "mfc %"PRIu64": %u failed, failing."
				  " (%d) %s",
				   mfc->id, dest->index,
				   dest->error_code,
				   dest->error_message);

			out = jsonrpc_stream_fail_data(mfc->cmd,
						       dest->error_code,
						       dest->error_message);
			json_add_node_id(out, "id", &dest->id);
			json_add_string(out, "method", "openchannel_signed");
			if (dest->error_data)
				json_add_jsonstr(out, "data",
						 dest->error_data,
						 strlen(dest->error_data));
			json_object_end(out);

			return mfc_finished(mfc, out);
		}
	}
	mfc->psbt = tal_free(mfc->psbt);
	return multifundchannel_finished(mfc);
}

static struct command_result *
after_openchannel_signed(struct multifundchannel_command *mfc)
{
	--mfc->pending;
	if (mfc->pending == 0)
		return openchannel_finished(mfc);
	else
		return command_still_pending(mfc->cmd);
}

static struct command_result *
openchannel_signed_ok(struct command *cmd,
		      const char *buf,
		      const jsmntok_t *result,
		      struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: `openchannel_signed` done",
		   mfc->id, dest->index);

	/* One of the other commands might have landed here first */
	if (!mfc->final_tx) {
		const jsmntok_t *tx_tok, *txid_tok;

		tx_tok = json_get_member(buf, result, "tx");
		if (!tx_tok)
			plugin_err(mfc->cmd->plugin,
				   "`openchannel_signed` has no 'tx': %.*s",
				   json_tok_full_len(result),
				   json_tok_full(buf, result));

		mfc->final_tx = json_strdup(mfc, buf, tx_tok);

		txid_tok = json_get_member(buf, result, "txid");
		if (!txid_tok)
			plugin_err(mfc->cmd->plugin,
				   "`openchannel_signed` has no 'txid': %.*s",
				   json_tok_full_len(result),
				   json_tok_full(buf, result));

		mfc->final_txid = json_strdup(mfc, buf, txid_tok);
	}

	/* We done !? */
	dest->psbt = tal_free(dest->psbt);
	return after_openchannel_signed(mfc);
}

static struct command_result *
openchannel_signed_err(struct command *cmd,
		       const char *buf,
		       const jsmntok_t *error,
		       struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;

	fail_destination_tok(dest, buf, error);
	return after_openchannel_signed(mfc);
}

static void
openchannel_signed_dest(struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;
	struct command *cmd = mfc->cmd;
	struct out_req *req;

	plugin_log(cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: `openchannel_signed` %s "
		   "psbt %s",
		   mfc->id, dest->index,
		   type_to_string(tmpctx, struct channel_id, &dest->channel_id),
		   type_to_string(tmpctx, struct wally_psbt, dest->psbt));

	req = jsonrpc_request_start(cmd->plugin,
				    cmd,
				    "openchannel_signed",
				    &openchannel_signed_ok,
				    &openchannel_signed_err,
				    dest);
	json_add_channel_id(req->js, "channel_id", &dest->channel_id);
	json_add_psbt(req->js, "signed_psbt", dest->psbt);

	send_outreq(cmd->plugin, req);
}

struct command_result *
perform_openchannel_signed(struct multifundchannel_command *mfc)
{
	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": parallel `openchannel_signed`.",
		   mfc->id);

	mfc->pending = dest_count(mfc, OPEN_CHANNEL);
	for (size_t i = 0; i < tal_count(mfc->destinations); i++) {
		if (!is_v2(&mfc->destinations[i]))
			continue;
		/* We need to 'port' all of the sigs down to the
		 * destination PSBTs */
		update_node_psbt(mfc, mfc->psbt,
				 &mfc->destinations[i].psbt);
		openchannel_signed_dest(&mfc->destinations[i]);
	}

	assert(mfc->pending != 0);
	return command_still_pending(mfc->cmd);
}

static struct command_result *
collect_sigs(struct multifundchannel_command *mfc)
{
	/* There's a very small chance that we'll get a
	 * race condition between when a signature arrives
	 * and all of the fundchannel_completes return.
	 * This flag helps us avoid invoking this twice.*/
	if (mfc->sigs_collected)
		return NULL;

	mfc->sigs_collected = true;
	/* But first! we sanity check that everyone's
	 * expecting the same funding txid */
	for (size_t i = 0; i < tal_count(mfc->destinations); i++) {
		struct multifundchannel_destination *dest;
		struct bitcoin_txid dest_txid;
		dest = &mfc->destinations[i];

		if (!is_v2(dest)) {
			/* Since we're here, double check that
			 * every v1 has their commitment txs */
			assert(dest->state == MULTIFUNDCHANNEL_COMPLETED);
			continue;
		}

		assert(dest->state == MULTIFUNDCHANNEL_SIGNED);
		psbt_txid(NULL, dest->psbt, &dest_txid, NULL);

		assert(bitcoin_txid_eq(mfc->txid, &dest_txid));
	}

	return perform_signpsbt(mfc);
}

struct command_result *
check_sigs_ready(struct multifundchannel_command *mfc)
{
	static struct command_result *result;
	bool ready = true;

	for (size_t i = 0; i < tal_count(mfc->destinations); i++) {
		enum multifundchannel_state state =
			is_v2(&mfc->destinations[i]) ?
				MULTIFUNDCHANNEL_SIGNED :
				MULTIFUNDCHANNEL_COMPLETED;

			ready &= mfc->destinations[i].state == state;
	}

	if (ready) {
		result = collect_sigs(mfc);
		if (result)
			return result;
	}

	return command_still_pending(mfc->cmd);
}

static struct command_result *json_peer_sigs(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *params)
{
	struct channel_id cid;
	const struct wally_psbt *psbt;
	struct multifundchannel_destination *dest;
	const char *err;

	err = json_scan(tmpctx, buf, params,
			"{openchannel_peer_sigs:"
			"{channel_id:%,signed_psbt:%}}",
			JSON_SCAN(json_to_channel_id, &cid),
			JSON_SCAN_TAL(cmd, json_to_psbt, &psbt));
	if (err)
		plugin_err(cmd->plugin,
			   "`openchannel_peer_sigs` did not scan: %s. %*.s",
			   err, json_tok_full_len(params),
			   json_tok_full(buf, params));

	/* Find the destination that's got this channel_id on it! */
	dest = find_dest_by_channel_id(&cid);
	if (!dest) {
		/* if there's no pending destination... whatever */
		plugin_log(cmd->plugin, LOG_DBG,
			   "mfc ??: `openchannel_peer_sigs` no "
			   "pending dest found for channel_id %s",
			   type_to_string(tmpctx, struct channel_id, &cid));
		return notification_handled(cmd);
	}

	plugin_log(cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64":`openchannel_peer_sigs` notice received for"
		   " channel %s",
		   dest->mfc->id,
		   tal_hexstr(tmpctx, &cid, sizeof(cid)));

	/* Combine with the parent. Unknown map dupes are ignored,
	 * so the updated serial_id should persist on the parent */
	tal_wally_start();
	if (wally_psbt_combine(dest->mfc->psbt, psbt) != WALLY_OK)
		plugin_err(cmd->plugin,
			   "mfc %"PRIu64": Unable to combine signed "
			   "PSBT with roll-up. "
			   "Signed %s, prev %s", dest->mfc->id,
			   type_to_string(tmpctx, struct wally_psbt, psbt),
			   type_to_string(tmpctx, struct wally_psbt,
					  dest->mfc->psbt));

	tal_wally_end(dest->mfc->psbt);

	/* Bit of a race is possible here. If we're still waiting for
	 * their commitment sigs to come back, we'll be in
	 * "UPDATED" still. We check that SIGNED is hit before
	 * we mark ourselves as ready to send the sigs, so it's ok
	 * to relax this check */
	if (dest->state == MULTIFUNDCHANNEL_UPDATED)
		dest->state = MULTIFUNDCHANNEL_SIGNED_NOT_SECURED;
	else {
		if (dest->state != MULTIFUNDCHANNEL_SECURED) {
			plugin_log(cmd->plugin, LOG_BROKEN,
				   "mfc %"PRIu64":`openchannel_peer_sigs` "
				   " expected state MULTIFUNDCHANNEL_SECURED (%d),"
				   " state is %d", dest->mfc->id,
				   MULTIFUNDCHANNEL_SECURED,
				   dest->state);
		}
		dest->state = MULTIFUNDCHANNEL_SIGNED;
	}

	/* Possibly free up the struct command for the mfc that
	 * we found.  */
	check_sigs_ready(dest->mfc);

	/* Free up the struct command for *this* call.  */
	return notification_handled(cmd);
}

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*
 * The v2 of channel establishment uses a different RPC flow:
 * `openchannel_init`, `openchannel_update`, && `openchannel_signed`
 *~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*
 */

static struct command_result *
funding_transaction_established(struct multifundchannel_command *mfc)
{
	/* Elements requires a fee output.  */
	/* FIXME: v2 on liquid */
	psbt_elements_normalize_fees(mfc->psbt);

	/* Generate the TXID.  */
	mfc->txid = tal(mfc, struct bitcoin_txid);
	psbt_txid(NULL, mfc->psbt, mfc->txid, NULL);
	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": funding tx %s",
		   mfc->id,
		   type_to_string(tmpctx, struct bitcoin_txid,
				  mfc->txid));

	/* If all we've got is v2 destinations, we're just waiting
	 * for all of our peers to send us their sigs.
	 * Let's check if we've gotten them yet */
	if (dest_count(mfc, FUND_CHANNEL) == 0)
		return check_sigs_ready(mfc);

	/* For any v1 destination, we need to update the destination
	 * outnum with the correct outnum on the now-known
	 * funding transaction */
	for (size_t i = 0; i < tal_count(mfc->destinations); i++) {
		struct multifundchannel_destination *dest;
		if (is_v2(&mfc->destinations[i]))
			continue;

		dest = &mfc->destinations[i];
		dest->outnum = mfc->psbt->num_outputs;
		for (size_t j = 0; j < mfc->psbt->num_outputs; j++) {
			if (memeq(dest->funding_script,
				  tal_bytelen(dest->funding_script),
				  mfc->psbt->outputs[j].script,
				  mfc->psbt->outputs[j].script_len))
				dest->outnum = j;
		}
		if (dest->outnum == mfc->psbt->num_outputs)
			abort();
		assert(dest->outnum < mfc->psbt->num_outputs);
	}

	return perform_fundchannel_complete(mfc);
}

static struct command_result *
openchannel_update_returned(struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;

	--mfc->pending;
	if (mfc->pending == 0)
		return perform_openchannel_update(mfc);
	else
		return command_still_pending(mfc->cmd);
}

static struct command_result *
openchannel_update_ok(struct command *cmd,
		      const char *buf,
		      const jsmntok_t *result,
		      struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;
	const jsmntok_t *psbt_tok, *done_tok;
	bool done;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: openchannel_update %s returned.",
		   mfc->id, dest->index,
		   node_id_to_hexstr(tmpctx, &dest->id));

	assert(!dest->updated_psbt);
	psbt_tok = json_get_member(buf, result, "psbt");
	if (!psbt_tok)
		plugin_err(cmd->plugin,
			   "`openchannel_update` did not return "
			   "'psbt': %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));

	dest->updated_psbt = json_to_psbt(dest->mfc, buf, psbt_tok);
	if (!dest->updated_psbt)
		plugin_err(cmd->plugin,
			   "`openchannel_update` returned invalid "
			   "'psbt': %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));

	/* FIXME: check that the channel id is correct? */
	done_tok = json_get_member(buf, result, "commitments_secured");
	if (!done_tok)
		plugin_err(cmd->plugin,
			   "`openchannel_update` failed to return "
			   "'commitments_secured': %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));

	if (!json_to_bool(buf, done_tok, &done))
		plugin_err(cmd->plugin,
			   "`openchannel_update` returned invalid "
			   "'commitments_secured': %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));

	/* We loop through here several times. We may
	 * reach an intermediate state however,
	 * MULTIFUNDCHANNEL_SIGNED_NOT_SECURED, so we only update
	 * to UPDATED iff we're at the previous state (STARTED) */
	if (dest->state == MULTIFUNDCHANNEL_STARTED)
		dest->state = MULTIFUNDCHANNEL_UPDATED;

	if (done) {
		const jsmntok_t *outnum_tok, *close_to_tok;

		outnum_tok = json_get_member(buf, result, "funding_outnum");
		if (!outnum_tok)
			plugin_err(cmd->plugin,
				   "`openchannel_update` did not return "
				   "'funding_outnum': %.*s",
				   json_tok_full_len(result),
				   json_tok_full(buf, result));

		if (!json_to_number(buf, outnum_tok, &dest->outnum))
		plugin_err(cmd->plugin,
			   "`openchannel_update` returned invalid "
			   "'funding_outnum': %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));

		close_to_tok = json_get_member(buf, result, "close_to");
		if (close_to_tok)
			dest->close_to_script =
				json_tok_bin_from_hex(dest->mfc, buf,
						      close_to_tok);
		else
			dest->close_to_script = NULL;

		/* It's possible they beat us to the SIGNED flag,
		 * in which case we just let that be the more senior
		 * state position */
		if (dest->state == MULTIFUNDCHANNEL_SIGNED_NOT_SECURED)
			dest->state = MULTIFUNDCHANNEL_SIGNED;
		else
			dest->state = MULTIFUNDCHANNEL_SECURED;
	}

	return openchannel_update_returned(dest);
}

static struct command_result *
openchannel_update_err(struct command *cmd,
		       const char *buf,
		       const jsmntok_t *error,
		       struct multifundchannel_destination *dest)
{
	fail_destination_tok(dest, buf, error);
	return openchannel_update_returned(dest);
}

static void
openchannel_update_dest(struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;
	struct command *cmd = mfc->cmd;
	struct out_req *req;

	plugin_log(cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: `openchannel_update` %s "
		   "with psbt %s",
		   mfc->id, dest->index,
		   node_id_to_hexstr(tmpctx, &dest->id),
		   type_to_string(tmpctx, struct wally_psbt, dest->psbt));

	req = jsonrpc_request_start(cmd->plugin,
				    cmd,
				    "openchannel_update",
				    &openchannel_update_ok,
				    &openchannel_update_err,
				    dest);
	json_add_channel_id(req->js, "channel_id", &dest->channel_id);
	json_add_psbt(req->js, "psbt", dest->psbt);

	send_outreq(cmd->plugin, req);
}

struct command_result *
perform_openchannel_update(struct multifundchannel_command *mfc)
{
	size_t i, ready_count = 0;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": parallel `openchannel_update`.",
		   mfc->id);

	/* First we check for failures/finished state */
	for (i = 0; i < tal_count(mfc->destinations); i++) {
		struct multifundchannel_destination *dest;
		dest = &mfc->destinations[i];

		if (dest->state == MULTIFUNDCHANNEL_FAILED)
			return redo_multifundchannel(mfc,
						     "openchannel_update",
						     dest->error_message);

		if (dest->state == MULTIFUNDCHANNEL_SECURED ||
			dest->state == MULTIFUNDCHANNEL_SIGNED) {
			ready_count++;
			continue;
		}

		assert(dest->state == MULTIFUNDCHANNEL_UPDATED ||
			dest->state == MULTIFUNDCHANNEL_STARTED);
	}

	/* Check if we can stop doing this and move to the next
	 * phase */
	if (ready_count == dest_count(mfc, OPEN_CHANNEL))
		return funding_transaction_established(mfc);

	/* Then, we update the parent with every node's result */
	for (i = 0; i < tal_count(mfc->destinations); i++) {
		struct multifundchannel_destination *dest;
		dest = &mfc->destinations[i];

		if (!is_v2(dest))
			continue;

		if (!update_parent_psbt(mfc, dest, dest->psbt,
					dest->updated_psbt,
					&mfc->psbt)) {
			fail_destination_msg(dest, FUNDING_PSBT_INVALID,
					     "Unable to update parent "
					     "with node's PSBT");
			return redo_multifundchannel(mfc,
						     "openchannel_init_parent",
						     dest->error_message);
		}
		/* Get everything sorted correctly */
		psbt_sort_by_serial_id(mfc->psbt);

		tal_free(dest->psbt);
		dest->psbt = dest->updated_psbt;
		dest->updated_psbt = NULL;
	}

	/* Next we update the view of every destination with the
	 * parent viewset */
	for (i = 0; i < tal_count(mfc->destinations); i++) {
		struct multifundchannel_destination *dest;
		dest = &mfc->destinations[i];

		/* We don't *have* psbts for v1 destinations */
		if (!is_v2(dest))
			continue;

		if (!update_node_psbt(mfc, mfc->psbt, &dest->psbt)) {
			fail_destination_msg(dest, FUNDING_PSBT_INVALID,
					     "Unable to update peer's PSBT"
					     " with parent PSBT");
			return redo_multifundchannel(mfc,
						     "openchannel_init_node",
						     dest->error_message);
		}
	}

	mfc->pending = dest_count(mfc, OPEN_CHANNEL);
	for (i = 0; i < tal_count(mfc->destinations); i++) {
		if (is_v2(&mfc->destinations[i]))
			openchannel_update_dest(&mfc->destinations[i]);
	}

	assert(mfc->pending != 0);
	return command_still_pending(mfc->cmd);
}

static struct command_result *
openchannel_init_done(struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;

	--mfc->pending;
	if (mfc->pending == 0)
		return after_channel_start(mfc);
	else
		return command_still_pending(mfc->cmd);
}

static struct command_result *
openchannel_init_ok(struct command *cmd,
		    const char *buf,
		    const jsmntok_t *result,
		    struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;
	const jsmntok_t *psbt_tok;
	const jsmntok_t *channel_id_tok;
	const jsmntok_t *funding_serial_tok;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: openchannel_init %s done.",
		   mfc->id, dest->index,
		   node_id_to_hexstr(tmpctx, &dest->id));

	/* We've got the PSBT and channel_id here */
	psbt_tok = json_get_member(buf, result, "psbt");
	if (!psbt_tok)
		plugin_err(cmd->plugin,
			   "openchannel_init did not return "
			   "'psbt': %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	dest->updated_psbt = json_to_psbt(dest->mfc, buf, psbt_tok);
	if (!dest->updated_psbt)
		plugin_err(cmd->plugin,
			   "openchannel_init returned invalid "
			   "'psbt': %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));

	channel_id_tok = json_get_member(buf, result, "channel_id");
	if (!channel_id_tok)
		plugin_err(cmd->plugin,
			   "openchannel_init did not return "
			   "'channel_id': %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	json_to_channel_id(buf, channel_id_tok, &dest->channel_id);

	funding_serial_tok = json_get_member(buf, result,
					     "funding_serial");
	if (!funding_serial_tok)
		plugin_err(cmd->plugin,
			   "openchannel_init did not return "
			   "'funding_serial': %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	json_to_u64(buf, funding_serial_tok, &dest->funding_serial);

	dest->state = MULTIFUNDCHANNEL_STARTED;

	/* Port any updates onto 'parent' PSBT */
	if (!update_parent_psbt(dest->mfc, dest, dest->psbt,
				dest->updated_psbt, &mfc->psbt)) {
		fail_destination_msg(dest, FUNDING_PSBT_INVALID,
				     "Unable to update parent"
				     " with node's PSBT");
	}

	/* Clone updated-psbt to psbt, so original changeset
	 * will be empty, but tallocate it so we can leave tal_free
	 * logic in `perform_openchannel_update` the same. */
	tal_wally_start();
	wally_psbt_clone_alloc(dest->updated_psbt, 0, &dest->psbt);
	tal_wally_end_onto(mfc, dest->updated_psbt, struct wally_psbt);
	return openchannel_init_done(dest);
}

static struct command_result *
openchannel_init_err(struct command *cmd,
		     const char *buf,
		     const jsmntok_t *error,
		     struct multifundchannel_destination *dest)
{
	fail_destination_tok(dest, buf, error);
	return openchannel_init_done(dest);
}

struct command_result *
openchannel_init_dest(struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;
	struct command *cmd = mfc->cmd;
	struct out_req *req;

	plugin_log(cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: openchannel_init %s.",
		   mfc->id, dest->index,
		   node_id_to_hexstr(tmpctx, &dest->id));

	req = jsonrpc_request_start(cmd->plugin, cmd,
				    "openchannel_init",
				    &openchannel_init_ok,
				    &openchannel_init_err,
				    dest);

	json_add_node_id(req->js, "id", &dest->id);
	assert(!dest->all);
	json_add_string(req->js, "amount",
			fmt_amount_sat(tmpctx, dest->amount));

	/* Copy the original parent down */
	tal_wally_start();
	wally_psbt_clone_alloc(mfc->psbt, 0, &dest->psbt);
	tal_wally_end_onto(mfc, dest->psbt, struct wally_psbt);

	json_add_psbt(req->js, "initialpsbt", dest->psbt);
	if (mfc->cmtmt_feerate_str)
		json_add_string(req->js, "commitment_feerate",
				mfc->cmtmt_feerate_str);
	if (mfc->feerate_str) {
		json_add_string(req->js, "funding_feerate",
				mfc->feerate_str);

		/* If there's no commitment feerate provided, we assume
		 * that the same feerate is to be used on both. This mimics
		 * the behavior of the old-style feerate stuffs */
		if (!mfc->cmtmt_feerate_str)
			json_add_string(req->js, "commitment_feerate",
					mfc->feerate_str);
	}
	json_add_bool(req->js, "announce", dest->announce);
	if (dest->close_to_str)
		json_add_string(req->js, "close_to", dest->close_to_str);

	if (amount_msat_greater(dest->push_msat, AMOUNT_MSAT(0)))
		plugin_log(cmd->plugin, LOG_INFORM,
			   "Using openchannel for %s open, "
			   "ignoring `push_msat` of %s",
			   node_id_to_hexstr(tmpctx, &dest->id),
			   type_to_string(tmpctx, struct amount_msat,
					  &dest->push_msat));

	/* Request some sats from the peer! */
	if (!amount_sat_zero(dest->request_amt)) {
		json_add_string(req->js, "request_amt",
				fmt_amount_sat(tmpctx, dest->request_amt));
		json_add_string(req->js, "compact_lease",
				lease_rates_tohex(tmpctx, dest->rates));
	}

	if (dest->channel_type) {
		json_add_channel_type_arr(req->js,
					  "channel_type", dest->channel_type);
	}
	return send_outreq(cmd->plugin, req);
}

void openchannel_init(struct plugin *p, const char *b, const jsmntok_t *t)
{
	/* Initialize our list! */
	list_head_init(&mfc_commands);
}

const struct plugin_notification openchannel_notifs[] = {
	{
		"openchannel_peer_sigs",
		json_peer_sigs,
	}
};
const size_t num_openchannel_notifs = ARRAY_SIZE(openchannel_notifs);
