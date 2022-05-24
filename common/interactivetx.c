#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/billboard.h>
#include <common/blockheight_states.h>
#include <common/crypto_sync.h>
#include <common/gossip_rcvd_filter.h>
#include <common/gossip_store.h>
#include <common/initial_channel.h>
#include <common/interactivetx.h>
#include <common/lease_rates.h>
#include <common/memleak.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/psbt_internal.h>
#include <common/psbt_open.h>
#include <common/read_peer_msg.h>
#include <common/setup.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>

/*
 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
 * The receiving node: ...
 * - MUST fail the negotiation if: ...
 *  - if has received 4096 `tx_add_input` messages during this negotiation
 */
#define MAX_TX_ADD_INPUT_MSG_RCVD 4096
/*
 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
 * The receiving node: ...
 * - MUST fail the negotiation if: ...
 *  - it has received 4096 `tx_add_output` messages during this negotiation
 */
#define MAX_TX_ADD_OUTPUT_MSG_RCVD 4096

/*
 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
 * The receiving node: ...
 * - MUST fail the negotiation if: ...
 *  - there are more than 252 inputs
 *  - there are more than 252 outputs
 */
#define MAX_FUNDING_INPUTS 252
#define MAX_FUNDING_OUTPUTS 252

static struct wally_psbt *default_next_update(const tal_t *ctx,
					      struct interactivetx_context *ictx)
{
	return ictx->desired_psbt;
}

struct interactivetx_context *new_interactivetx_context(const tal_t *ctx,
							enum tx_role our_role,
							struct per_peer_state *pps,
							struct channel_id channel_id)
{
	struct interactivetx_context *ictx = tal(ctx, struct interactivetx_context);

	ictx->ctx = NULL;
	ictx->our_role = our_role;
	ictx->pps = pps;
	ictx->channel_id = channel_id;
	ictx->tx_add_input_count = 0;
	ictx->tx_add_output_count = 0;
	ictx->next_update = default_next_update;
	ictx->current_psbt = NULL;
	ictx->desired_psbt = NULL;
	ictx->pause_when_complete = false;
	ictx->change_set = NULL;

	return ictx;
}

static bool is_segwit_output(const tal_t *ctx,
			     struct wally_tx_output *output,
			     const u8 *redeemscript)
{
	const u8 *wit_prog;
	if (tal_bytelen(redeemscript) > 0)
		wit_prog = redeemscript;
	else
		wit_prog = wally_tx_output_get_script(ctx, output);

	return is_p2wsh(wit_prog, NULL) || is_p2wpkh(wit_prog, NULL);
}

/* Return first non-handled message or NULL if connection is aborted */
static u8 *read_next_msg(const tal_t *ctx,
			 struct interactivetx_context *state,
			 char **error)
{
	u8 *msg = NULL;

	for (;;) {
		char *desc;
		bool warning;
		struct channel_id actual;
		enum peer_wire t;
		bool from_gossipd;

		/* Prevent runaway memory usage from many messages */
		if (msg)
			tal_free(msg);

		/* This helper routine polls the peer. */
		msg = peer_or_gossip_sync_read(ctx, state->pps, &from_gossipd);

		/* Line should be in STFU mode and not receiving gossip */
		if (from_gossipd) {
			*error = tal_fmt(ctx, "interactivetx got gossip but"
					 " should be in STFU mode.");

			tal_free(msg);
			/* Return NULL so caller knows to stop negotiating. */
			return NULL;
		}

		/* BOLT #1:
		 *
		 * A receiving node:
		 *   - upon receiving a message of _odd_, unknown type:
		 *     - MUST ignore the received message.
		 */
		if (is_unknown_msg_discardable(msg))
			continue;

		/* A helper which decodes an error. */
		if (is_peer_error(msg, msg, &state->channel_id,
				  &desc, &warning)) {
			/* In this case, is_peer_error returns true, but sets
			 * desc to NULL */
			if (!desc)
				continue;

			*error = tal_fmt(ctx, "They sent a %s: %s"
					 warning ? "warning" : "error",
					 desc);

			tal_free(msg);
			/* Return NULL so caller knows to stop negotiating. */
			return NULL;
		}

		/* In theory, we're in the middle of an open/RBF/splice, but
		 * it's possible we can get some different messages in
		 * the meantime! */
		t = fromwire_peektype(msg);
		switch (t) {
		case WIRE_TX_ADD_INPUT:
		case WIRE_TX_REMOVE_INPUT:
		case WIRE_TX_ADD_OUTPUT:
		case WIRE_TX_REMOVE_OUTPUT:
		case WIRE_TX_COMPLETE:
			return msg;
		case WIRE_TX_SIGNATURES:
		case WIRE_FUNDING_LOCKED:
		case WIRE_INIT_RBF:
		case WIRE_OPEN_CHANNEL2:
		case WIRE_INIT:
		case WIRE_ERROR:
		case WIRE_OPEN_CHANNEL:
		case WIRE_ACCEPT_CHANNEL:
		case WIRE_FUNDING_CREATED:
		case WIRE_FUNDING_SIGNED:
		case WIRE_CLOSING_SIGNED:
		case WIRE_UPDATE_ADD_HTLC:
		case WIRE_UPDATE_FULFILL_HTLC:
		case WIRE_UPDATE_FAIL_HTLC:
		case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
		case WIRE_COMMITMENT_SIGNED:
		case WIRE_REVOKE_AND_ACK:
		case WIRE_UPDATE_FEE:
		case WIRE_UPDATE_BLOCKHEIGHT:
		case WIRE_CHANNEL_REESTABLISH:
		case WIRE_ANNOUNCEMENT_SIGNATURES:
		case WIRE_GOSSIP_TIMESTAMP_FILTER:
		case WIRE_ONION_MESSAGE:
		case WIRE_ACCEPT_CHANNEL2:
		case WIRE_ACK_RBF:
		case WIRE_CHANNEL_ANNOUNCEMENT:
		case WIRE_CHANNEL_UPDATE:
		case WIRE_NODE_ANNOUNCEMENT:
		case WIRE_QUERY_CHANNEL_RANGE:
		case WIRE_REPLY_CHANNEL_RANGE:
		case WIRE_QUERY_SHORT_CHANNEL_IDS:
		case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
		case WIRE_WARNING:
		case WIRE_PING:
		case WIRE_PONG:
		case WIRE_SHUTDOWN:
#if EXPERIMENTAL_FEATURES
		case WIRE_STFU:
#endif
		*error = tal_fmt(ctx,
				 "Received invalid message from peer: %d", t);
		return NULL;
		}
	}
}

static char *send_next(const tal_t *ctx,
		       struct interactivetx_context *ictx,
		       bool *finished)
{
	struct channel_id *cid = &ictx->channel_id;
	struct psbt_changeset *set = ictx->change_set;
	u64 serial_id;
	u8 *msg = NULL;
	*finished = false;

	if (!set)
		goto tx_complete;

	if (tal_count(set->added_ins) != 0) {
		const struct input_set *in = &set->added_ins[0];
		struct bitcoin_outpoint outpoint;
		u8 *prevtx;

		if (!psbt_get_serial_id(&in->input.unknowns, &serial_id))
			return "interactivetx ADD_INPUT PSBT has invalid serial_id.";

		if (in->input.utxo)
			prevtx = linearize_wtx(ctx,
					       in->input.utxo);
		else
			return "interactivetx ADD_INPUT PSBT needs the previous transaction set.";

		memcpy(outpoint.txid.shad.sha.u.u8,
		       in->tx_input.txhash,
		       WALLY_TXHASH_LEN);

		outpoint.n = in->tx_input.index;

		msg = towire_tx_add_input(NULL, cid, serial_id,
					  prevtx, in->tx_input.index,
					  in->tx_input.sequence,
					  NULL);

		tal_arr_remove(&set->added_ins, 0);
	}
	else if (tal_count(set->rm_ins) != 0) {
		if (!psbt_get_serial_id(&set->rm_ins[0].input.unknowns,
					&serial_id))
			return "interactivetx RM_INPUT PSBT has invalid serial_id.";

		msg = towire_tx_remove_input(NULL, cid, serial_id);

		tal_arr_remove(&set->rm_ins, 0);
	}
	else if (tal_count(set->added_outs) != 0) {
		struct amount_sat sats;
		struct amount_asset asset_amt;
		const struct output_set *out;
		const u8 *script;

		out = &set->added_outs[0];

		if (!psbt_get_serial_id(&out->output.unknowns, &serial_id))
			return "interactivetx ADD_OUTPUT PSBT has invalid serial_id.";

		asset_amt = wally_tx_output_get_amount(&out->tx_output);
		sats = amount_asset_to_sat(&asset_amt);
		script = wally_tx_output_get_script(ctx, &out->tx_output);

		msg = towire_tx_add_output(NULL,
					   cid,
					   serial_id,
					   sats.satoshis, /* Raw: wire interface */
					   script);

		tal_arr_remove(&set->added_outs, 0);
	}
	else if (tal_count(set->rm_outs) != 0) {
		if (!psbt_get_serial_id(&set->rm_outs[0].output.unknowns,
					&serial_id))
			return "interactivetx RM_OUTPUT PSBT has invalid serial_id.";

		msg = towire_tx_remove_output(NULL, cid, serial_id);

		tal_arr_remove(&set->rm_outs, 0);
	}
	else /* no changes to psbt */
		goto tx_complete;

	if (!msg)
		return "Interactivetx send_next failed to build a message";
	sync_crypto_write(ictx->pps, take(msg));
	return NULL;

tx_complete:

	*finished = true;
	if (!ictx->pause_when_complete) {
		if (ictx->current_psbt->num_inputs > MAX_FUNDING_INPUTS)
			return tal_fmt(ctx, "Humbly refusing to `tx_complete` "
				       "because we have too many inputs (%zu). "
				       "Limit is %zu."
				       ictx->current_psbt->num_inputs,
				       MAX_FUNDING_INPUTS);

		if (ictx->current_psbt->num_outputs > MAX_FUNDING_OUTPUTS)
			return tal_fmt(ctx, "Humbly refusing to `tx_complete` "
				       "because we have too many outputs (%zu). "
				       "Limit is %zu."
				       ictx->current_psbt->num_outputs,
				       MAX_FUNDING_OUTPUTS);

		msg = towire_tx_complete(ctx, cid);
		sync_crypto_write(ictx->pps, msg);
	}
	return NULL;
}

char *process_interactivetx_updates(const tal_t *ctx,
			 	    struct interactivetx_context *ictx,
				    bool *received_tx_complete)
{
	bool we_complete = false, they_complete = false;
	u8 *msg;
	char *error = NULL;
	struct wally_psbt *next_psbt;

	if (ictx->current_psbt == NULL)
		ictx->current_psbt = create_psbt(ictx, 0, 0, 0);

	if (received_tx_complete)
		they_complete = *received_tx_complete;

	/* Build change_set and handle PSBT variables */
	ictx->change_set = tal_free(ictx->change_set);

	/* Call next_update or default to 'desired_psbt' */
	next_psbt = ictx->next_update(ictx, ictx);

	/* Returning NULL from next_update is the same as using `current_psbt`
	 * with no changes -- both indicate no changes */
	if (!next_psbt)
		next_psbt = ictx->current_psbt;

	ictx->change_set = psbt_get_changeset(ictx,
					      ictx->current_psbt,
					      next_psbt);

	/* If current_psbt and next_psbt are the same, dont double free it!
	 * Otherwise we advance `current_psbt` to `next_psbt` and begin
	 * processing the change set in `ictx->change_set` */
	if (ictx->current_psbt != next_psbt) {
		/* psbt_get_changeset requires we keep the current_psbt until
		 * we're done withh change_set */
		tal_steal(ictx->change_set, current_psbt);
		ictx->current_psbt = next_psbt;
	}

	/* As initiator we always start with a single send to start it off */
	if (ictx->our_role == TX_INITIATOR) {
		error = send_next(ctx, ictx, &we_complete);
		if (error)
			return error;

		if (ictx->pause_when_complete && we_complete) {
			psbt_sort_by_serial_id(ictx->current_psbt);
			return NULL;
		}
	}

	/* Loop through tx update turns with peer */
	while (!(we_complete && they_complete)) {
		struct channel_id cid;
		enum peer_wire t;
		u64 serial_id;

		/* Reset their_complete to false every round,
		 * they have to re-affirm every time  */
		they_complete = false;

		if (received_tx_complete)
			*received_tx_complete = false;

		msg = read_next_msg(ctx, ictx, &error);
		if (error)
			return error;

		t = fromwire_peektype(msg);
		switch (t) {
		case WIRE_TX_ADD_INPUT: {
			const u8 *tx_bytes, *redeemscript;
			u32 sequence;
			size_t len;
			struct bitcoin_tx *tx;
			struct bitcoin_outpoint outpoint;

			if (!fromwire_tx_add_input(ctx, msg, &cid,
						   &serial_id,
						   cast_const2(u8 **,
							       &tx_bytes),
						   &outpoint.n, &sequence,
						   cast_const2(u8 **,
							       &redeemscript)))
				return tal_fmt(ctx,
					       "Parsing tx_add_input %s",
					       tal_hex(ctx, msg));

			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 *   - MUST fail the negotiation if: ...
			 *   - if has received 4096 `tx_add_input`
			 *   messages during this negotiation
			 */
			if (++ictx->tx_add_input_count >= MAX_TX_ADD_INPUT_MSG_RCVD)
				return tal_fmt(ctx, "Too many `tx_add_input`s"
					       " received %d",
					       MAX_TX_ADD_INPUT_MSG_RCVD);
			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 *   - MUST fail the negotiation if: ...
			 *   - the `serial_id` has the wrong parity
			 */
			if (serial_id % 2 == ictx->our_role)
				return tal_fmt(ctx,
					       "Invalid serial_id rcvd. %"PRIu64,
					       serial_id);
			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 *   - MUST fail the negotiation if: ...
			 *   - the `serial_id` is already included in
			 *   the transaction
			 */
			if (psbt_find_serial_input(ictx->current_psbt, serial_id) != -1)
				return tal_fmt(ctx, "Duplicate serial_id rcvd."
					       " %"PRIu64, serial_id);

			/* Convert tx_bytes to a tx! */
			len = tal_bytelen(tx_bytes);
			tx = pull_bitcoin_tx(ctx, &tx_bytes, &len);

			if (!tx || len != 0)
				return tal_fmt(ctx, "Invalid tx sent. len: %d",
					       (int)len);

			if (outpoint.n >= tx->wtx->num_outputs)
				return tal_fmt(ctx,
					       "Invalid tx outnum sent. %u",
					       outpoint.n);
			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 *   - MUST fail the negotiation if: ...
			 *   - the `prevtx_out` input of `prevtx` is
			 *   not an `OP_0` to `OP_16` followed by a single push
			 */
			if (!is_segwit_output(ctx,
					      &tx->wtx->outputs[outpoint.n],
					      redeemscript))
				return tal_fmt(ctx,
					       "Invalid tx sent. Not SegWit %s",
					       type_to_string(ctx,
							      struct bitcoin_tx,
							      tx));

			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 *   The receiving node: ...
			 *    - MUST fail the negotiation if:
			 *    - the `prevtx` and `prevtx_vout` are
			 *    identical to a previously added (and not
			 *    removed) input's
			 */
			bitcoin_txid(tx, &outpoint.txid);
			if (psbt_has_input(ictx->current_psbt, &outpoint))
				return tal_fmt(ctx,
					       "Unable to add input %s- "
					       "already present",
					       type_to_string(ctx,
							      struct bitcoin_outpoint,
							      &outpoint));

			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MUST fail the negotiation if: ...
			 *  - there are more than 252 inputs
			 */
			if (ictx->current_psbt->num_inputs + 1 > MAX_FUNDING_INPUTS)
				return tal_fmt(ctx, "Too many inputs. Have %zu,"
					       " Max allowed %zu",
					       ictx->current_psbt->num_inputs + 1,
					       MAX_FUNDING_INPUTS);

			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node:
			 *  - MUST add all received inputs to the transaction
			 */
			struct wally_psbt_input *in =
				psbt_append_input(ictx->current_psbt, &outpoint,
						  sequence, NULL, NULL, NULL);
			if (!in)
				return tal_fmt(ctx,
					       "Unable to add input %s",
					       type_to_string(ctx,
							      struct bitcoin_outpoint,
							      &outpoint));

			tal_wally_start();
			wally_psbt_input_set_utxo(in, tx->wtx);
			tal_wally_end(ictx);

			psbt_input_set_serial_id(ictx->current_psbt,
						 in, serial_id);

			break;
		}
		case WIRE_TX_REMOVE_INPUT: {
			int input_index;

			if (!fromwire_tx_remove_input(msg, &cid, &serial_id))
				return tal_fmt(ctx,
					       "Parsing tx_remove_input %s",
					       tal_hex(ctx, msg));

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node:  ...
			 *   - MUST fail the negotiation if: ...
			 *   - the input or output identified by the
			 *   `serial_id` was not added by the sender
			 */
			if (serial_id % 2 == ictx->our_role)
				return tal_fmt(ctx,
					       "Input can't be removed by peer "
					       "because they did not add it. "
					       "serial_id: %"PRIu64,
					       serial_id);

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node:  ...
			 *   - MUST fail the negotiation if: ...
			 *   - the `serial_id` does not correspond
			 *     to a currently added input (or output)
			 */
			input_index = psbt_find_serial_input(ictx->current_psbt,
							     serial_id);
			/* We choose to error/fail negotiation */
			if (input_index == -1)
				return tal_fmt(ctx,
					       "No input added with serial_id"
					       " %"PRIu64, serial_id);

			psbt_rm_input(ictx->current_psbt, input_index);
			break;
		}
		case WIRE_TX_ADD_OUTPUT: {
			u64 value;
			u8 *scriptpubkey;
			struct wally_psbt_output *out;
			struct amount_sat amt;
			if (!fromwire_tx_add_output(ctx, msg, &cid,
						    &serial_id, &value,
						    &scriptpubkey))
				return tal_fmt(ctx,
					       "Parsing tx_add_output %s",
					       tal_hex(ctx, msg));

			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MUST fail the negotiation if: ...
			 *   - it has received 4096 `tx_add_output`
			 *   messages during this negotiation
			 */
			if (++ictx->tx_add_output_count >= MAX_TX_ADD_OUTPUT_MSG_RCVD)
				return tal_fmt(ctx,
					       "Too many `tx_add_output`s"
					       " received (%d)",
					       MAX_TX_ADD_OUTPUT_MSG_RCVD);

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MUST fail the negotiation if: ...
			 *   - the `serial_id` has the wrong parity
			 */
			if (serial_id % 2 == ictx->our_role)
				return tal_fmt(ctx,
					       "Invalid serial_id rcvd. %"PRIu64,
					       serial_id);

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MUST fail the negotiation if: ...
			 *   - the `serial_id` is already included
			 *   in the transaction */
			if (psbt_find_serial_output(ictx->current_psbt, serial_id) != -1)
				return tal_fmt(ctx,
					       "Duplicate serial_id rcvd."
					       " %"PRIu64, serial_id);
			amt = amount_sat(value);

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MAY fail the negotiation if `script`
			 *   is non-standard */
			if (!is_known_scripttype(scriptpubkey))
				return tal_fmt(ctx, "Script is not standard");

			/*
			 * BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MUST fail the negotiation if: ...
			 *  - there are more than 252 outputs
			 */
			if (ictx->current_psbt->num_outputs + 1 > MAX_FUNDING_OUTPUTS)
				return tal_fmt(ctx, "Too many inputs. Have %zu,"
					       " Max allowed %zu",
					       ictx->current_psbt->num_outputs + 1,
					       MAX_FUNDING_OUTPUTS);

			out = psbt_append_output(ictx->current_psbt,
						 scriptpubkey,
						 amt);

			psbt_output_set_serial_id(ictx->current_psbt,
						  out,
						  serial_id);
			break;
		}
		case WIRE_TX_REMOVE_OUTPUT: {
			int output_index;

			if (!fromwire_tx_remove_output(msg, &cid, &serial_id))
				return tal_fmt(ctx,
						 "Parsing tx_remove_output %s",
						 tal_hex(ctx, msg));

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MUST fail the negotiation if: ...
			 *   - the input or output identified by the
			 *   `serial_id` was not added by the sender
			 */
			if (serial_id % 2 == ictx->our_role)
				return tal_fmt(ctx,
					       "Output can't be removed by peer "
					       "because they did not add it. "
					       "serial_id: %"PRIu64,
					       serial_id);

			/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
			 * The receiving node: ...
			 * - MUST fail the negotiation if: ...
			 *   - the `serial_id` does not correspond to a
			 *     currently added input (or output)
			 */
			output_index = psbt_find_serial_output(ictx->current_psbt,
							       serial_id);
			if (output_index == -1)
				return tal_fmt(ctx,
					       "No output added with serial_id"
					       " %"PRIu64, serial_id);
			psbt_rm_output(ictx->current_psbt, output_index);
			break;
		}
		case WIRE_TX_COMPLETE:
			if (!fromwire_tx_complete(msg, &cid))
				return tal_fmt(ctx,
					       "Parsing tx_complete %s",
					       tal_hex(ctx, msg));
			they_complete = true;
			if (received_tx_complete)
				*received_tx_complete = true;
			break;
		case WIRE_INIT:
		case WIRE_ERROR:
		case WIRE_WARNING:
		case WIRE_OPEN_CHANNEL:
		case WIRE_ACCEPT_CHANNEL:
		case WIRE_FUNDING_CREATED:
		case WIRE_FUNDING_SIGNED:
		case WIRE_FUNDING_LOCKED:
		case WIRE_SHUTDOWN:
		case WIRE_CLOSING_SIGNED:
		case WIRE_UPDATE_ADD_HTLC:
		case WIRE_UPDATE_FULFILL_HTLC:
		case WIRE_UPDATE_FAIL_HTLC:
		case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
		case WIRE_COMMITMENT_SIGNED:
		case WIRE_REVOKE_AND_ACK:
		case WIRE_UPDATE_FEE:
		case WIRE_UPDATE_BLOCKHEIGHT:
		case WIRE_CHANNEL_REESTABLISH:
		case WIRE_ANNOUNCEMENT_SIGNATURES:
		case WIRE_GOSSIP_TIMESTAMP_FILTER:
		case WIRE_OBS2_ONION_MESSAGE:
		case WIRE_ONION_MESSAGE:
		case WIRE_TX_SIGNATURES:
		case WIRE_OPEN_CHANNEL2:
		case WIRE_ACCEPT_CHANNEL2:
		case WIRE_INIT_RBF:
		case WIRE_ACK_RBF:
		case WIRE_CHANNEL_ANNOUNCEMENT:
		case WIRE_CHANNEL_UPDATE:
		case WIRE_NODE_ANNOUNCEMENT:
		case WIRE_QUERY_CHANNEL_RANGE:
		case WIRE_REPLY_CHANNEL_RANGE:
		case WIRE_QUERY_SHORT_CHANNEL_IDS:
		case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
		case WIRE_PING:
		case WIRE_PONG:
#if EXPERIMENTAL_FEATURES
		case WIRE_SPLICE:
		case WIRE_SPLICE_ACK:
		case WIRE_STFU:
#endif
			return tal_fmt(ctx, "Unexpected wire message %s",
				       tal_hex(ctx, msg));
		}

		if (!(we_complete && they_complete))
			send_next(ctx, ictx, &we_complete);
	}

	/* Sort psbt! */
	psbt_sort_by_serial_id(ictx->current_psbt);

	return NULL;
}
