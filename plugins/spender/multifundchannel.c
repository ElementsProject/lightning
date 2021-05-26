#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <ccan/compiler/compiler.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/str/str.h>
#include <ccan/take/take.h>
#include <common/addr.h>
#include <common/amount.h>
#include <common/features.h>
#include <common/json.h>
#include <common/json_stream.h>
#include <common/json_tok.h>
#include <common/jsonrpc_errors.h>
#include <common/node_id.h>
#include <common/psbt_open.h>
#include <common/pseudorand.h>
#include <common/tx_roles.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <plugins/spender/multifundchannel.h>
#include <plugins/spender/openchannel.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

extern const struct chainparams *chainparams;

/* Flag set when any of the destinations has a value of "all".  */
static bool has_all(const struct multifundchannel_command *mfc)
{
	for (size_t i = 0; i < tal_count(mfc->destinations); i++) {
		if (mfc->destinations[i].all)
			return true;
	}
	return false;
}

size_t dest_count(const struct multifundchannel_command *mfc,
		  enum channel_protocol protocol)
{
	size_t count = 0, i;
	for (i = 0; i < tal_count(mfc->destinations); i++) {
		if (mfc->destinations[i].protocol == protocol)
			count++;
	}
	return count;
}

static void fail_destination(struct multifundchannel_destination *dest)
{
	dest->fail_state = dest->state;
	dest->state = MULTIFUNDCHANNEL_FAILED;
}

void fail_destination_tok(struct multifundchannel_destination *dest,
			  const char *buf,
			  const jsmntok_t *error)
{
	const char *err;
	const jsmntok_t *data_tok;

	err = json_scan(tmpctx, buf, error, "{code:%,message:%}",
			JSON_SCAN(json_to_int, &dest->error_code),
			JSON_SCAN_TAL(dest->mfc,
				      json_strdup,
				      &dest->error_message));
	if (err)
		plugin_err(dest->mfc->cmd->plugin,
			   "`fundchannel_complete` failure failed to parse %s",
			   err);

	data_tok = json_get_member(buf, error, "data");
	if (data_tok)
		dest->error_data = json_strdup(dest->mfc, buf, data_tok);
	else
		dest->error_data = NULL;

	fail_destination(dest);
}

void fail_destination_msg(struct multifundchannel_destination *dest,
			  errcode_t error_code,
			  const char *err_str TAKES)
{
	dest->error_code = error_code;
	dest->error_message = tal_strdup(dest->mfc, err_str);
	dest->error_data = NULL;

	fail_destination(dest);
}

/* Return true if this destination failed, false otherwise.  */
static bool dest_failed(struct multifundchannel_destination *dest)
{
	return dest->state == MULTIFUNDCHANNEL_FAILED;
}

bool is_v2(const struct multifundchannel_destination *dest)
{
	return dest->protocol == OPEN_CHANNEL;
}

static bool
has_commitments_secured(const struct multifundchannel_destination *dest)
{
	/* If it failed, make sure we hadn't gotten
	 * commitments yet */
	enum multifundchannel_state state = dest->state;
	if (state == MULTIFUNDCHANNEL_FAILED)
		state = dest->fail_state;

	switch (state) {
	case MULTIFUNDCHANNEL_START_NOT_YET:
	case MULTIFUNDCHANNEL_CONNECTED:
	case MULTIFUNDCHANNEL_STARTED:
	case MULTIFUNDCHANNEL_UPDATED:
		return false;
	case MULTIFUNDCHANNEL_COMPLETED:
	case MULTIFUNDCHANNEL_SECURED:
	case MULTIFUNDCHANNEL_SIGNED_NOT_SECURED:
	case MULTIFUNDCHANNEL_SIGNED:
	case MULTIFUNDCHANNEL_DONE:
		return true;
	case MULTIFUNDCHANNEL_FAILED:
		/* Shouldn't be FAILED */
		break;
	}
	abort();
}

/*-----------------------------------------------------------------------------
Command Cleanup
-----------------------------------------------------------------------------*/

/*~
We disallow the use of command_fail and forward_error directly
in the rest of the code.

This ensures that if we ever fail a multifundchannel, we do cleanup
by doing fundchannel_cancel and unreserveinputs.
*/

/* TODO: This is lengthy enough to deserve its own source file,
clocking in at 240 loc.
*/

/* Object for performing cleanup.  */
struct multifundchannel_cleanup {
	size_t pending;
	struct command_result *(*cb)(void *arg);
	void *arg;
};

/* Done when all cleanup operations have completed.  */
static struct command_result *
mfc_cleanup_complete(struct multifundchannel_cleanup *cleanup)
{
	tal_steal(tmpctx, cleanup);
	return cleanup->cb(cleanup->arg);
}

static struct command_result *
mfc_cleanup_done(struct command *cmd,
		       const char *buf UNUSED,
		       const jsmntok_t *res UNUSED,
		       struct multifundchannel_cleanup *cleanup)
{
	--cleanup->pending;
	if (cleanup->pending == 0)
		return mfc_cleanup_complete(cleanup);
	else
		return command_still_pending(cmd);
}

/* Cleans up a txid by doing `txdiscard` on it.  */
static void
mfc_cleanup_psbt(struct command *cmd,
		 struct multifundchannel_cleanup *cleanup,
		 struct wally_psbt *psbt)
{
	struct wally_psbt *pruned_psbt;
	struct out_req *req = jsonrpc_request_start(cmd->plugin,
						    cmd,
						    "unreserveinputs",
						    &mfc_cleanup_done,
						    &mfc_cleanup_done,
						    cleanup);

	/* We might have peer's inputs on this, get rid of them */
	tal_wally_start();
	if (wally_psbt_clone_alloc(psbt, 0, &pruned_psbt) != WALLY_OK)
		abort();
	tal_wally_end(tal_steal(NULL, pruned_psbt));

	for (size_t i = pruned_psbt->num_inputs - 1;
	     i < pruned_psbt->num_inputs;
	     i--) {
		if (!psbt_input_is_ours(&pruned_psbt->inputs[i]))
			psbt_rm_input(pruned_psbt, i);
	}

	json_add_psbt(req->js, "psbt", take(pruned_psbt));
	json_add_u32(req->js, "reserve", 2016);
	send_outreq(cmd->plugin, req);
}

/* Cleans up a `openchannel_init` by doing `openchannel_abort` for the channel*/
static void
mfc_cleanup_oc(struct command *cmd,
	       struct multifundchannel_cleanup *cleanup,
	       struct multifundchannel_destination *dest)
{
	struct out_req *req = jsonrpc_request_start(cmd->plugin,
						     cmd,
						     "openchannel_abort",
						     &mfc_cleanup_done,
						     &mfc_cleanup_done,
						     cleanup);
	json_add_channel_id(req->js, "channel_id", &dest->channel_id);
	send_outreq(cmd->plugin, req);
}

/* Cleans up a `fundchannel_start` by doing `fundchannel_cancel` on
the node.
*/
static void
mfc_cleanup_fc(struct command *cmd,
	       struct multifundchannel_cleanup *cleanup,
	       struct multifundchannel_destination *dest)
{
	struct out_req *req = jsonrpc_request_start(cmd->plugin,
						    cmd,
						    "fundchannel_cancel",
						    &mfc_cleanup_done,
						    &mfc_cleanup_done,
						    cleanup);
	json_add_node_id(req->js, "id", &dest->id);

	send_outreq(cmd->plugin, req);
}

/* Core cleanup function.  */
static struct command_result *
mfc_cleanup_(struct multifundchannel_command *mfc,
	     struct command_result *(*cb)(void *arg),
	     void *arg)
{
	struct multifundchannel_cleanup *cleanup;
	unsigned int i;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": cleanup!", mfc->id);

	cleanup = tal(mfc, struct multifundchannel_cleanup);
	cleanup->pending = 0;
	cleanup->cb = cb;
	cleanup->arg = arg;

	/* If there's commitments, anywhere, we have to fail/restart.
	 * We also cleanup the PSBT if there's no v2's around */
	if (mfc->psbt) {
		plugin_log(mfc->cmd->plugin, LOG_DBG,
			   "mfc %"PRIu64": unreserveinputs task.", mfc->id);

		++cleanup->pending;
		mfc_cleanup_psbt(mfc->cmd, cleanup, mfc->psbt);
	}
	for (i = 0; i < tal_count(mfc->destinations); ++i) {
		struct multifundchannel_destination *dest;
		dest = &mfc->destinations[i];

		switch (dest->state) {
		case MULTIFUNDCHANNEL_STARTED:
			/* v1 handling */
			if (!is_v2(dest)) {
				plugin_log(mfc->cmd->plugin, LOG_DBG,
					   "mfc %"PRIu64", dest %u: "
					   "fundchannel_cancel task.",
					   mfc->id, dest->index);
				++cleanup->pending;
				mfc_cleanup_fc(mfc->cmd, cleanup, dest);
			} else { /* v2 handling */
				plugin_log(mfc->cmd->plugin, LOG_DBG,
					   "mfc %"PRIu64", dest %u:"
					   " openchannel_abort task.",
					   mfc->id, dest->index);
				++cleanup->pending;
				mfc_cleanup_oc(mfc->cmd, cleanup, dest);
			}
			continue;
		case MULTIFUNDCHANNEL_COMPLETED:
			/* Definitely a v1 */
			plugin_log(mfc->cmd->plugin, LOG_DBG,
				   "mfc %"PRIu64", dest %u: "
				   "fundchannel_cancel task.",
				   mfc->id, dest->index);
			++cleanup->pending;
			mfc_cleanup_fc(mfc->cmd, cleanup, dest);
			continue;
		case MULTIFUNDCHANNEL_UPDATED:
			/* Definitely a v2 */
			plugin_log(mfc->cmd->plugin, LOG_DBG,
				   "mfc %"PRIu64", dest %u:"
				   " openchannel_abort task.",
				   mfc->id, dest->index);
			++cleanup->pending;
			mfc_cleanup_oc(mfc->cmd, cleanup, dest);
			continue;
		case MULTIFUNDCHANNEL_SECURED:
		case MULTIFUNDCHANNEL_SIGNED:
		case MULTIFUNDCHANNEL_SIGNED_NOT_SECURED:
			/* We don't actually *send* the
			 * transaction until here,
			 * but peer isnt going to forget. This
			 * open is borked until an input is
			 * spent or it times out */
			continue;
		case MULTIFUNDCHANNEL_START_NOT_YET:
		case MULTIFUNDCHANNEL_CONNECTED:
		case MULTIFUNDCHANNEL_DONE:
		case MULTIFUNDCHANNEL_FAILED:
			/* Nothing to do ! */
			continue;
		}
		/* We shouldn't make it this far */
		abort();
	}

	if (cleanup->pending == 0)
		return mfc_cleanup_complete(cleanup);
	else
		return command_still_pending(mfc->cmd);
}
#define mfc_cleanup(mfc, cb, arg) \
	mfc_cleanup_(mfc, typesafe_cb(struct command_result *, void *, \
				      (cb), (arg)), \
		     (arg))

/*---------------------------------------------------------------------------*/

/* These are the actual implementations of the cleanup entry functions.  */

struct mfc_fail_object {
	struct multifundchannel_command *mfc;
	struct command *cmd;
	errcode_t code;
	const char *msg;
};

static struct command_result *
mfc_fail_complete(struct mfc_fail_object *obj)
{
	plugin_log(obj->mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": cleanup done, failing.", obj->mfc->id);
	return command_fail(obj->cmd, obj->code, "%s", obj->msg);
}

/* Use this instead of command_fail.  */
static struct command_result *
mfc_fail(struct multifundchannel_command *mfc, errcode_t code,
	 const char *fmt, ...)
{
	struct mfc_fail_object *obj;
	const char *msg;
	va_list ap;

	va_start(ap, fmt);
	msg = tal_vfmt(mfc, fmt, ap);
	va_end(ap);

	obj = tal(mfc, struct mfc_fail_object);
	obj->mfc = mfc;
	obj->cmd = mfc->cmd;
	obj->code = code;
	obj->msg = msg;

	return mfc_cleanup(mfc, &mfc_fail_complete, obj);
}
struct mfc_err_raw_object {
	struct multifundchannel_command *mfc;
	const char *error;
};
static struct command_result *
mfc_err_raw_complete(struct mfc_err_raw_object *obj)
{
	plugin_log(obj->mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": cleanup done, failing raw.", obj->mfc->id);
	return command_err_raw(obj->mfc->cmd, obj->error);
}

/* Use this instead of command_err_raw.  */
static struct command_result *
mfc_err_raw(struct multifundchannel_command *mfc, const char *json_string)
{
	struct mfc_err_raw_object *obj;

	obj = tal(mfc, struct mfc_err_raw_object);
	obj->mfc = mfc;
	obj->error = tal_strdup(obj, json_string);

	return mfc_cleanup(mfc, &mfc_err_raw_complete, obj);
}
struct command_result *
mfc_forward_error(struct command *cmd,
		  const char *buf, const jsmntok_t *error,
		  struct multifundchannel_command *mfc)
{
	plugin_log(cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": forwarding error, about to cleanup.",
		   mfc->id);
	return mfc_err_raw(mfc, json_strdup(tmpctx, buf, error));
}

struct mfc_finished_object {
	struct multifundchannel_command *mfc;
	struct command *cmd;
	struct json_stream *response;
};
static struct command_result *
mfc_finished_complete(struct mfc_finished_object *obj)
{
	plugin_log(obj->mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": cleanup done, finishing command.",
		   obj->mfc->id);
	return command_finished(obj->cmd, obj->response);
}

struct command_result *
mfc_finished(struct multifundchannel_command *mfc,
	     struct json_stream *response)
{
	struct mfc_finished_object *obj;

	/* The response will be constructed by jsonrpc_stream_success,
	which allocates off the command, so it should be safe to
	just store it here.
	*/
	obj = tal(mfc, struct mfc_finished_object);
	obj->mfc = mfc;
	obj->cmd = mfc->cmd;
	obj->response = response;

	return mfc_cleanup(mfc, &mfc_finished_complete, obj);
}

/*---------------------------------------------------------------------------*/
/*~
We now have an unsigned funding transaction in
mfc->psbt and mfc->txid that puts the money into
2-of-2 channel outpoints.

However, we cannot sign and broadcast it yet!
We need to get backout transactions --- the initial
commitment transactions --- in case any of the
peers disappear later.
Those initial commitment transactions are the
unilateral close (force-close) transactions
for each channel.
With unilateral opportunity to close, we can then
safely broadcast the tx, so that in case the
peer disappears, we can recover our funds.

The `fundchannel_complete` command performs the
negotiation with the peer to sign the initial
commiteent transactions.
Only once the `lightningd` has the transactions
signed does the `fundchannel_complete` command
return with a success.
After that point we can `signpsbt`+`sendpsbt`
the transaction.
*/

/*~
And finally we are done.
*/
struct command_result *
multifundchannel_finished(struct multifundchannel_command *mfc)
{
	unsigned int i;
	struct json_stream *out;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": done.", mfc->id);

	out = jsonrpc_stream_success(mfc->cmd);
	json_add_string(out, "tx", mfc->final_tx);
	json_add_string(out, "txid", mfc->final_txid);
	json_array_start(out, "channel_ids");
	for (i = 0; i < tal_count(mfc->destinations); ++i) {
		json_object_start(out, NULL);
		json_add_node_id(out, "id", &mfc->destinations[i].id);
		json_add_channel_id(out, "channel_id",
				    &mfc->destinations[i].channel_id);
		json_add_num(out, "outnum", mfc->destinations[i].outnum);
		if (mfc->destinations[i].close_to_script)
			json_add_hex_talarr(out, "close_to",
				mfc->destinations[i].close_to_script);
		json_object_end(out);
	}
	json_array_end(out);

	json_array_start(out, "failed");
	for (i = 0; i < tal_count(mfc->removeds); ++i) {
		json_object_start(out, NULL);
		json_add_node_id(out, "id", &mfc->removeds[i].id);
		json_add_string(out, "method", mfc->removeds[i].method);
		json_object_start(out, "error"); /* Start error object */
		json_add_s32(out, "code", mfc->removeds[i].error_code);
		json_add_string(out, "message",
				mfc->removeds[i].error_message);
		if (mfc->removeds[i].error_data)
			json_add_jsonstr(out, "data",
					 mfc->removeds[i].error_data);
		json_object_end(out); /* End error object */
		json_object_end(out);
	}
	json_array_end(out);

	return mfc_finished(mfc, out);
}

static struct command_result *
after_sendpsbt(struct command *cmd,
	       const char *buf,
	       const jsmntok_t *result,
	       struct multifundchannel_command *mfc)
{
	const jsmntok_t *tx_tok;
	const jsmntok_t *txid_tok;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": sendpsbt done.", mfc->id);

	tx_tok = json_get_member(buf, result, "tx");
	if (!tx_tok)
		plugin_err(cmd->plugin,
			   "sendpsbt response has no 'tx': %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	mfc->final_tx = json_strdup(mfc, buf, tx_tok);

	txid_tok = json_get_member(buf, result, "txid");
	if (!txid_tok)
		plugin_err(cmd->plugin,
			   "sendpsbt response has no 'txid': %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	mfc->final_txid = json_strdup(mfc, buf, txid_tok);

	/* PSBT is no longer something we need to clean up.  */
	mfc->psbt = tal_free(mfc->psbt);

	return multifundchannel_finished(mfc);
}

static struct command_result *
after_signpsbt(struct command *cmd,
	       const char *buf,
	       const jsmntok_t *result,
	       struct multifundchannel_command *mfc)
{
	const jsmntok_t *field;
	struct wally_psbt *psbt;
	struct out_req *req;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": signpsbt done.", mfc->id);

	field = json_get_member(buf, result, "signed_psbt");
	if (!field)
		plugin_err(mfc->cmd->plugin,
			   "signpsbt did not return 'signed_psbt'? %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	psbt = psbt_from_b64(mfc,
			     buf + field->start,
			     field->end - field->start);
	if (!psbt)
		plugin_err(mfc->cmd->plugin,
			   "signpsbt gave unparseable 'signed_psbt'? %.*s",
			   json_tok_full_len(field),
			   json_tok_full(buf, field));

	if (!psbt_finalize(psbt))
		plugin_err(mfc->cmd->plugin,
			   "mfc %"PRIu64": Signed PSBT won't finalize"
			   "%s", mfc->id,
			   type_to_string(tmpctx, struct wally_psbt, psbt));


	/* Replace the PSBT.  */
	tal_free(mfc->psbt);
	mfc->psbt = tal_steal(mfc, psbt);

	/*~ Now mark all destinations as being done.
	Why mark it now *before* doing `sendpsbt` rather than after?
	Because `sendpsbt` will do approximately this:

	1.  `sendpsbt` launches `bitcoin-cli`.
	2.  `bitcoin-cli` connects to a `bitcoind` over JSON-RPC
	    over HTTP.
	3.  `bitcoind` validates the transactions and puts it int
	    its local mempool.
	4.  `bitcoind` tells `bitcoin-cli` it all went well.
	5.  `bitcoin-cli` tells `sendpsbt` it all went well.

	If some interruption or problem occurs between steps 3
	and 4, then the transaction is already in some node
	mempool and will likely be broadcast, but `sendpsbt` has
	failed.

	And so we have to mark the channels as being "done"
	*before* we do `sendpsbt`.
	If not, if we error on `sendpsbt`, that would cause us to
	`fundchannel_cancel` all the peers, but that is risky,
	as, the funding transaction could still have been
	broadcast and the channels funded.

	That is, we treat `sendpsbt` failure as a possible
	false negative.
	*/
	for (size_t i = 0; i < tal_count(mfc->destinations); ++i) {
		struct multifundchannel_destination *dest;
		enum multifundchannel_state expected_state;

		dest = &mfc->destinations[i];

		/* Check that every dest is in the right state */
		expected_state = is_v2(dest) ?
			MULTIFUNDCHANNEL_SIGNED : MULTIFUNDCHANNEL_COMPLETED;
		assert(dest->state == expected_state);

		dest->state = MULTIFUNDCHANNEL_DONE;
	}

	/* If there's any v2's, we send the tx via `openchannel_signed` */
	if (dest_count(mfc, OPEN_CHANNEL) > 0) {
		return perform_openchannel_signed(mfc);
	}

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": sendpsbt.", mfc->id);

	req = jsonrpc_request_start(mfc->cmd->plugin, mfc->cmd,
				    "sendpsbt",
				    &after_sendpsbt,
				    &mfc_forward_error,
				    mfc);
	json_add_psbt(req->js, "psbt", mfc->psbt);
	/* We already reserved inputs by 2 weeks, we don't need
	 * another 72 blocks. */
	json_add_u32(req->js, "reserve", 0);
	return send_outreq(mfc->cmd->plugin, req);
}

struct command_result *
perform_signpsbt(struct multifundchannel_command *mfc)
{
	struct out_req *req;

	/* Now we sign our inputs. You do remember which inputs
	 * are yours, right? */
	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": signpsbt.", mfc->id);

	req = jsonrpc_request_start(mfc->cmd->plugin, mfc->cmd,
				    "signpsbt",
				    &after_signpsbt,
				    &mfc_forward_error,
				    mfc);
	json_add_psbt(req->js, "psbt", mfc->psbt);

	/* Use input markers to identify which inputs
	 * are ours, only sign those */
	json_array_start(req->js, "signonly");
	for (size_t i = 0; i < mfc->psbt->num_inputs; i++) {
		if (psbt_input_is_ours(&mfc->psbt->inputs[i]))
			json_add_num(req->js, NULL, i);
	}
	json_array_end(req->js);
	return send_outreq(mfc->cmd->plugin, req);
}

/*~
Finally with everything set up correctly we `signpsbt`+`sendpsbt` the
funding transaction.
*/
static struct command_result *
after_fundchannel_complete(struct multifundchannel_command *mfc)
{
	unsigned int i;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": parallel fundchannel_complete  done.",
		   mfc->id);

	/* Check if any fundchannel_complete failed.  */
	for (i = 0; i < tal_count(mfc->destinations); ++i) {
		struct multifundchannel_destination *dest;

		dest = &mfc->destinations[i];
		if (is_v2(dest))
			continue;

		assert(dest->state == MULTIFUNDCHANNEL_COMPLETED
		    || dest->state == MULTIFUNDCHANNEL_FAILED);

		if (dest->state != MULTIFUNDCHANNEL_FAILED)
			continue;

		/* One of them failed, oh no.  */
		return redo_multifundchannel(mfc, "fundchannel_complete",
					     dest->error_message);
	}

	if (dest_count(mfc, OPEN_CHANNEL) > 0)
		return check_sigs_ready(mfc);

	return perform_signpsbt(mfc);
}


static struct command_result *
fundchannel_complete_done(struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;

	--mfc->pending;
	if (mfc->pending == 0)
		return after_fundchannel_complete(mfc);
	else
		return command_still_pending(mfc->cmd);
}

static struct command_result *
fundchannel_complete_ok(struct command *cmd,
			const char *buf,
			const jsmntok_t *result,
			struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;
	const jsmntok_t *channel_id_tok;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: fundchannel_complete %s done.",
		   mfc->id, dest->index,
		   node_id_to_hexstr(tmpctx, &dest->id));

	channel_id_tok = json_get_member(buf, result, "channel_id");
	if (!channel_id_tok)
		plugin_err(cmd->plugin,
			   "fundchannel_complete no channel_id: %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	json_to_channel_id(buf, channel_id_tok, &dest->channel_id);

	dest->state = MULTIFUNDCHANNEL_COMPLETED;
	return fundchannel_complete_done(dest);
}

static struct command_result *
fundchannel_complete_err(struct command *cmd,
			 const char *buf,
			 const jsmntok_t *error,
			 struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: "
		   "failed! fundchannel_complete %s: %.*s",
		   mfc->id, dest->index,
		   node_id_to_hexstr(tmpctx, &dest->id),
		   json_tok_full_len(error), json_tok_full(buf, error));

	fail_destination_tok(dest, buf, error);
	return fundchannel_complete_done(dest);
}

static void
fundchannel_complete_dest(struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;
	struct command *cmd = mfc->cmd;
	struct out_req *req;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: fundchannel_complete %s.",
		   mfc->id, dest->index,
		   node_id_to_hexstr(tmpctx, &dest->id));

	req = jsonrpc_request_start(cmd->plugin,
				    cmd,
				    "fundchannel_complete",
				    &fundchannel_complete_ok,
				    &fundchannel_complete_err,
				    dest);
	json_add_node_id(req->js, "id", &dest->id);
	json_add_psbt(req->js, "psbt", mfc->psbt);

	send_outreq(cmd->plugin, req);
}

struct command_result *
perform_fundchannel_complete(struct multifundchannel_command *mfc)
{
	unsigned int i;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": parallel fundchannel_complete.",
		   mfc->id);

	mfc->pending = dest_count(mfc, FUND_CHANNEL);

	for (i = 0; i < tal_count(mfc->destinations); ++i) {
		if (!is_v2(&mfc->destinations[i]))
			fundchannel_complete_dest(&mfc->destinations[i]);
	}

	assert(mfc->pending != 0);
	return command_still_pending(mfc->cmd);
}

/*~ The PSBT we are holding currently has no outputs.
We now proceed to filling in those outputs now that
we know what the funding scriptpubkeys are.

First thing we do is to shuffle the outputs.
This is needed in order to decorrelate the transaction
outputs from the parameters passed into the command.
We should assume that the caller of the command might
inadvertently leak important privacy data in the order
of its arguments, so we shuffle the outputs.
*/
static struct command_result *
perform_funding_tx_finalize(struct multifundchannel_command *mfc)
{
	struct multifundchannel_destination **deck;
	char *content = tal_strdup(tmpctx, "");
	size_t v1_dest_count = dest_count(mfc, FUND_CHANNEL);
	size_t v2_dest_count = dest_count(mfc, OPEN_CHANNEL);
	size_t i, deck_i;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": Creating funding tx.",
		   mfc->id);

	/* Construct a deck of destinations.  */
	deck = tal_arr(tmpctx, struct multifundchannel_destination *,
		       v1_dest_count + mfc->change_needed);

	deck_i = 0;
	for (i = 0; i < tal_count(mfc->destinations); i++) {
		if (is_v2(&mfc->destinations[i]))
			continue;

		assert(deck_i < tal_count(deck));
		deck[deck_i++] = &mfc->destinations[i];
	}

	/* Add a NULL into the deck as a proxy for change output, if
	 * needed.  */
	if (mfc->change_needed)
		deck[v1_dest_count] = NULL;
	/* Fisher-Yates shuffle.  */
	for (i = tal_count(deck); i > 1; --i) {
		size_t j = pseudorand(i);
		if (j == i - 1)
			continue;
		struct multifundchannel_destination *tmp;
		tmp = deck[j];
		deck[j] = deck[i - 1];
		deck[i - 1] = tmp;
	}

	/* Now that we have our outputs shuffled, add outputs to the PSBT.  */
	for (unsigned int outnum = 0; outnum < tal_count(deck); ++outnum) {
		if (outnum != 0)
			tal_append_fmt(&content, ", ");
		if (deck[outnum]) {
			/* Funding outpoint.  */
			struct multifundchannel_destination *dest;
			dest = deck[outnum];
			(void) psbt_insert_output(mfc->psbt,
						  dest->funding_script,
						  dest->amount,
						  outnum);
			/* The actual output index will be based on the
			 * serial_id if this contains any v2 outputs */
			if (v2_dest_count == 0)
				dest->outnum = outnum;
			tal_append_fmt(&content, "%s: %s",
				       type_to_string(tmpctx, struct node_id,
						      &dest->id),
				       type_to_string(tmpctx,
						      struct amount_sat,
						      &dest->amount));
		} else {
			/* Change output.  */
			assert(mfc->change_needed);
			(void) psbt_insert_output(mfc->psbt,
						  mfc->change_scriptpubkey,
						  mfc->change_amount,
						  outnum);
			tal_append_fmt(&content, "change: %s",
				       type_to_string(tmpctx,
						      struct amount_sat,
						      &mfc->change_amount));
		}
	}

	if (v2_dest_count > 0) {
		/* Add serial_ids to all the new outputs */
		psbt_add_serials(mfc->psbt, TX_INITIATOR);

		/* Now we stash the 'mfc' command, so when/if
		 * signature notifications start coming
		 * in, we'll catch them. */
		register_mfc(mfc);

		/* Take a side-quest to finish filling out
		 * the funding tx */
		return perform_openchannel_update(mfc);
	}

	/* We've only got v1 destinations, move onward */
	/* Elements requires a fee output.  */
	psbt_elements_normalize_fees(mfc->psbt);

	/* Generate the TXID.  */
	mfc->txid = tal(mfc, struct bitcoin_txid);
	psbt_txid(NULL, mfc->psbt, mfc->txid, NULL);

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": funding tx %s: %s",
		   mfc->id,
		   type_to_string(tmpctx, struct bitcoin_txid,
				  mfc->txid),
		   content);

	/* Now we can feed the TXID and outnums to the peer.  */
	return perform_fundchannel_complete(mfc);
}

/*---------------------------------------------------------------------------*/

/*~
We perform all the `fundchannel_start` in parallel.

We need to parallelize `fundchannel_start` execution
since the command has to wait for a response from
the remote peer.
The remote peer is not under our control and might
respond after a long time.

By doing them in parallel, the time it takes to
perform all the `fundchannel_start` is only the
slowest time among all peers.
This is important since faster peers might impose a
timeout on channel opening and fail subsequent
steps if we take too long before running
`fundchannel_complete`.
*/

/* All fundchannel_start/openchannel_init commands have returned
 * with either success or failure.
*/
struct command_result *
after_channel_start(struct multifundchannel_command *mfc)
{
	unsigned int i;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": parallel channel starts done.",
		   mfc->id);

	/* Check if any channel start failed.  */
	for (i = 0; i < tal_count(mfc->destinations); ++i) {
		struct multifundchannel_destination *dest;

		dest = &mfc->destinations[i];

		assert(dest->state == MULTIFUNDCHANNEL_STARTED
		    || dest->state == MULTIFUNDCHANNEL_FAILED);

		if (dest->state != MULTIFUNDCHANNEL_FAILED)
			continue;

		/* One of them failed, oh no.  */
		return redo_multifundchannel(mfc,
					     is_v2(dest) ?
					     "openchannel_init" :
					     "fundchannel_start",
					     dest->error_message);
	}

	/* Next step.  */
	return perform_funding_tx_finalize(mfc);
}

static struct command_result *
fundchannel_start_done(struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;

	--mfc->pending;
	if (mfc->pending == 0)
		return after_channel_start(mfc);
	else
		return command_still_pending(mfc->cmd);
}

static struct command_result *
fundchannel_start_ok(struct command *cmd,
		     const char *buf,
		     const jsmntok_t *result,
		     struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;
	const jsmntok_t *address_tok;
	const jsmntok_t *script_tok;
	const jsmntok_t *close_to_tok;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: fundchannel_start %s done.",
		   mfc->id, dest->index,
		   node_id_to_hexstr(tmpctx, &dest->id));

	/* Extract funding_address.  */
	address_tok = json_get_member(buf, result, "funding_address");
	if (!address_tok)
		plugin_err(cmd->plugin,
			   "fundchannel_start did not "
			   "return 'funding_address': %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	dest->funding_addr = json_strdup(dest->mfc, buf, address_tok);
	/* Extract scriptpubkey.  */
	script_tok = json_get_member(buf, result, "scriptpubkey");
	if (!script_tok)
		plugin_err(cmd->plugin,
			   "fundchannel_start did not "
			   "return 'scriptpubkey': %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	dest->funding_script = json_tok_bin_from_hex(dest->mfc,
						     buf, script_tok);
	if (!dest->funding_script)
		plugin_err(cmd->plugin,
			   "fundchannel_start did not "
			   "return parseable 'scriptpubkey': %.*s",
			   json_tok_full_len(script_tok),
			   json_tok_full(buf, script_tok));

	close_to_tok = json_get_member(buf, result, "close_to");
	/* Only returned if a) we requested and b) peer supports
	 * opt_upfront_shutdownscript */
	if (close_to_tok) {
		dest->close_to_script =
			json_tok_bin_from_hex(dest->mfc, buf, close_to_tok);
	} else
		dest->close_to_script = NULL;


	dest->state = MULTIFUNDCHANNEL_STARTED;

	return fundchannel_start_done(dest);
}

static struct command_result *
fundchannel_start_err(struct command *cmd,
		      const char *buf,
		      const jsmntok_t *error,
		      struct multifundchannel_destination *dest)
{
	plugin_log(dest->mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: "
		   "failed! fundchannel_start %s: %.*s.",
		   dest->mfc->id, dest->index,
		   node_id_to_hexstr(tmpctx, &dest->id),
		   json_tok_full_len(error),
		   json_tok_full(buf, error));
	/*
	You might be wondering why we do not just use
	mfc_forward_error here.
	The reason is that other `fundchannel_start`
	commands are running in the meantime,
	and it is still ambiguous whether the opening
	of other destinations was started or not.

	After all parallel `fundchannel_start`s have
	completed, we can then fail.
	*/

	fail_destination_tok(dest, buf, error);
	return fundchannel_start_done(dest);
}

static void
fundchannel_start_dest(struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;
	struct command *cmd = mfc->cmd;
	struct out_req *req;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: fundchannel_start %s.",
		   mfc->id, dest->index,
		   node_id_to_hexstr(tmpctx, &dest->id));

	req = jsonrpc_request_start(cmd->plugin,
				    cmd,
				    "fundchannel_start",
				    &fundchannel_start_ok,
				    &fundchannel_start_err,
				    dest);

	json_add_node_id(req->js, "id", &dest->id);
	assert(!dest->all);
	json_add_string(req->js, "amount",
			fmt_amount_sat(tmpctx, dest->amount));

	if (mfc->cmtmt_feerate_str)
		json_add_string(req->js, "feerate", mfc->cmtmt_feerate_str);
	else if (mfc->feerate_str)
		json_add_string(req->js, "feerate", mfc->feerate_str);
	json_add_bool(req->js, "announce", dest->announce);
	json_add_string(req->js, "push_msat",
			fmt_amount_msat(tmpctx, dest->push_msat));
	if (dest->close_to_str)
		json_add_string(req->js, "close_to", dest->close_to_str);

	send_outreq(cmd->plugin, req);
}

static struct command_result *
perform_channel_start(struct multifundchannel_command *mfc)
{
	unsigned int i;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": fundchannel_start parallel "
		   "with PSBT %s",
		   mfc->id,
		   type_to_string(tmpctx, struct wally_psbt, mfc->psbt));

	mfc->pending = tal_count(mfc->destinations);

	/* Since v2 is now available, we branch depending
	 * on the capability of the peer and our feaures */
	for (i = 0; i < tal_count(mfc->destinations); ++i) {
		if (is_v2(&mfc->destinations[i]))
			openchannel_init_dest(&mfc->destinations[i]);
		else
			fundchannel_start_dest(&mfc->destinations[i]);
	}

	assert(mfc->pending != 0);
	return command_still_pending(mfc->cmd);
}


/*---------------------------------------------------------------------------*/

/*~ Create an initial funding PSBT.

This creation of the initial funding PSBT is solely to reserve inputs for
our use.
This lets us initiate later with fundchannel_start with confidence that we
can actually afford the channels we will create.
*/

static struct command_result *
mfc_psbt_acquired(struct multifundchannel_command *mfc)
{
	/* Add serials to all of our input/outputs, so they're stable
	 * for the life of the tx */
	psbt_add_serials(mfc->psbt, TX_INITIATOR);

	/* We also mark all of our inputs as *ours*, so we
	 * can easily identify them for `signpsbt`, later */
	for (size_t i = 0; i < mfc->psbt->num_inputs; i++)
		psbt_input_mark_ours(mfc->psbt, &mfc->psbt->inputs[i]);

	return perform_channel_start(mfc);
}

static struct command_result *
after_newaddr(struct command *cmd,
	      const char *buf,
	      const jsmntok_t *result,
	      struct multifundchannel_command *mfc)
{
	const jsmntok_t *field;

	field = json_get_member(buf, result, "bech32");
	if (!field)
		plugin_err(cmd->plugin,
			   "No bech32 field in newaddr result: %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	if (json_to_address_scriptpubkey(mfc, chainparams, buf, field,
					 &mfc->change_scriptpubkey)
	 != ADDRESS_PARSE_SUCCESS)
		plugin_err(cmd->plugin,
			   "Unparseable bech32 field in newaddr result: %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));

	return mfc_psbt_acquired(mfc);
}

static struct command_result *
acquire_change_address(struct multifundchannel_command *mfc)
{
	struct out_req *req;
	req = jsonrpc_request_start(mfc->cmd->plugin, mfc->cmd,
				    "newaddr",
				    &after_newaddr, &mfc_forward_error,
				    mfc);
	json_add_string(req->js, "addresstype", "bech32");
	return send_outreq(mfc->cmd->plugin, req);
}

static struct command_result *
handle_mfc_change(struct multifundchannel_command *mfc)
{
	size_t change_weight;
	struct amount_sat change_fee, fee_paid, total_fee;
	struct amount_sat change_min_limit;

	/* Determine if adding a change output is worth it.
	 * Get the weight of a change output and how much it
	 * costs.
	 */
	change_weight = bitcoin_tx_output_weight(
				BITCOIN_SCRIPTPUBKEY_P2WPKH_LEN);

	/* To avoid 'off-by-one' errors due to rounding down
	 * (which we do in `amount_tx_fee`), we find the total calculated
	 * fees (estimated_weight + change weight @ feerate) and subtract
	 * the originally calculated fees (estimated_weight @ feerate) */
	fee_paid = amount_tx_fee(mfc->feerate_per_kw,
				 mfc->estimated_final_weight);
	total_fee = amount_tx_fee(mfc->feerate_per_kw,
				  mfc->estimated_final_weight + change_weight);
	if (!amount_sat_sub(&change_fee, total_fee, fee_paid))
		abort();

	/* The limit is equal to the change_fee plus the dust limit.  */
	if (!amount_sat_add(&change_min_limit,
			    change_fee, chainparams->dust_limit))
		plugin_err(mfc->cmd->plugin,
			   "Overflow dust limit and change fee.");

	/* Is the excess over the limit?  */
	if (amount_sat_greater(mfc->excess_sat, change_min_limit)) {
		bool ok = amount_sat_sub(&mfc->change_amount,
					 mfc->excess_sat, change_fee);
		assert(ok);
		mfc->change_needed = true;
		if (!mfc->change_scriptpubkey)
			return acquire_change_address(mfc);
	} else
		mfc->change_needed = false;

	return mfc_psbt_acquired(mfc);
}

/* If one of the destinations specified "all", figure out how much that is.  */
static struct command_result *
compute_mfc_all(struct multifundchannel_command *mfc)
{
	size_t all_index = SIZE_MAX;
	struct multifundchannel_destination *all_dest;

	assert(has_all(mfc));

	for (size_t i = 0; i < tal_count(mfc->destinations); ++i) {
		struct multifundchannel_destination *dest;
		dest = &mfc->destinations[i];
		if (dest->all) {
			assert(all_index == SIZE_MAX);
			all_index = i;
			continue;
		}
		/* Subtract the amount from the excess.  */
		if (!amount_sat_sub(&mfc->excess_sat,
				    mfc->excess_sat, dest->amount))
			/* Not enough funds!  */
			return mfc_fail(mfc, FUND_CANNOT_AFFORD,
					"Insufficient funds.");
	}
	assert(all_index != SIZE_MAX);
	all_dest = &mfc->destinations[all_index];

	/* Is the excess above the dust amount?  */
	if (amount_sat_less(mfc->excess_sat, chainparams->dust_limit))
		return mfc_fail(mfc, FUND_OUTPUT_IS_DUST,
				"Output 'all' %s would be dust",
				type_to_string(tmpctx, struct amount_sat,
					       &mfc->excess_sat));

	/* Assign the remainder to the 'all' output.  */
	all_dest->amount = mfc->excess_sat;
	if (!feature_negotiated(plugin_feature_set(mfc->cmd->plugin),
				all_dest->their_features,
				OPT_LARGE_CHANNELS)
	 && amount_sat_greater(all_dest->amount,
			       chainparams->max_funding))
		all_dest->amount = chainparams->max_funding;
	/* Remove it from the excess.  */
	bool ok = amount_sat_sub(&mfc->excess_sat,
				 mfc->excess_sat, all_dest->amount);
	assert(ok);
	/* Remove the 'all' flag.  */
	all_dest->all = false;

	/* Continue.  */
	return handle_mfc_change(mfc);
}

static struct command_result *
after_fundpsbt(struct command *cmd,
	       const char *buf,
	       const jsmntok_t *result,
	       struct multifundchannel_command *mfc)
{
	const jsmntok_t *field;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": %s done.",
		   mfc->id, mfc->utxos_str ? "utxopsbt" : "fundpsbt");

	field = json_get_member(buf, result, "psbt");
	if (!field)
		goto fail;

	mfc->psbt = psbt_from_b64(mfc,
				  buf + field->start,
				  field->end - field->start);
	if (!mfc->psbt)
		goto fail;

	field = json_get_member(buf, result, "feerate_per_kw");
	if (!field || !json_to_u32(buf, field, &mfc->feerate_per_kw))
		goto fail;

	field = json_get_member(buf, result, "estimated_final_weight");
	if (!field || !json_to_u32(buf, field, &mfc->estimated_final_weight))
		goto fail;

	/* msat LOL.  */
	field = json_get_member(buf, result, "excess_msat");
	if (!field || !parse_amount_sat(&mfc->excess_sat,
					buf + field->start,
					field->end - field->start))
		goto fail;

	if (has_all(mfc))
		return compute_mfc_all(mfc);
	return handle_mfc_change(mfc);

fail:
	plugin_err(mfc->cmd->plugin,
		   "Unexpected result from fundpsbt/utxopsbt: %.*s",
		   json_tok_full_len(result),
		   json_tok_full(buf, result));

}


static struct command_result *
perform_fundpsbt(struct multifundchannel_command *mfc)
{
	struct out_req *req;

	/* If the user specified utxos we should use utxopsbt instead
	 * of fundpsbt.  */
	if (mfc->utxos_str) {
		plugin_log(mfc->cmd->plugin, LOG_DBG,
			   "mfc %"PRIu64": utxopsbt.",
			   mfc->id);

		req = jsonrpc_request_start(mfc->cmd->plugin,
					    mfc->cmd,
					    "utxopsbt",
					    &after_fundpsbt,
					    &mfc_forward_error,
					    mfc);
		json_add_jsonstr(req->js, "utxos", mfc->utxos_str);
		json_add_bool(req->js, "reservedok", false);
	} else {
		plugin_log(mfc->cmd->plugin, LOG_DBG,
			   "mfc %"PRIu64": fundpsbt.",
			   mfc->id);

		req = jsonrpc_request_start(mfc->cmd->plugin,
					    mfc->cmd,
					    "fundpsbt",
					    &after_fundpsbt,
					    &mfc_forward_error,
					    mfc);
		json_add_u32(req->js, "minconf", mfc->minconf);
	}

	/* The entire point is to reserve the inputs. */
	/*  BOLT #2:
	 * The sender:
	 *...
	 *     - SHOULD ensure the funding transaction confirms in the next 2016
	 *       blocks.
	 */
	json_add_u32(req->js, "reserve", 2016);
	/* How much do we need to reserve?  */
	if (has_all(mfc))
		json_add_string(req->js, "satoshi", "all");
	else {
		struct amount_sat sum = AMOUNT_SAT(0);
		for (size_t i = 0; i < tal_count(mfc->destinations); ++i) {
			if (!amount_sat_add(&sum,
					    sum, mfc->destinations[i].amount))
				return mfc_fail(mfc, JSONRPC2_INVALID_PARAMS,
						"Overflow while summing "
						"destination values.");
		}
		json_add_string(req->js, "satoshi",
				type_to_string(tmpctx, struct amount_sat,
					       &sum));
	}
	json_add_string(req->js, "feerate",
			mfc->feerate_str ? mfc->feerate_str : "normal");

	{
		size_t startweight;
		size_t num_outs = tal_count(mfc->destinations);
		/* Assume 1 input.
		 * As long as lightningd does not select more than 252
		 * inputs, that estimation should be correct.
		 */
		startweight = bitcoin_tx_core_weight(1, num_outs)
			    + ( bitcoin_tx_output_weight(
					BITCOIN_SCRIPTPUBKEY_P2WSH_LEN)
			      * num_outs
			      );
		json_add_string(req->js, "startweight",
				tal_fmt(tmpctx, "%zu", startweight));
	}

	/* If we've got v2 opens, we need to use a min weight of 110. */
	/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #3:
	 * The minimum witness weight for an input is 110.
	 */
	if (dest_count(mfc, OPEN_CHANNEL) > 0) {
		json_add_string(req->js, "min_witness_weight",
				tal_fmt(tmpctx, "%u", 110));
	}


	return send_outreq(mfc->cmd->plugin, req);
}

/*---------------------------------------------------------------------------*/
/*~
First, connect to all the peers.

This is a convenience both to us and to the user.

We delegate parsing for valid node IDs to the
`multiconnect`.
In addition, this means the user does not have to
connect to the specified nodes.

In particular, some implementations (including some
versions of C-Lightning) will disconnect in case
of funding channel failure.
And with a *multi* funding, it is more likely to
fail due to having to coordinate many more nodes.
*/

/* Check results of connect.  */
static struct command_result *
after_multiconnect(struct multifundchannel_command *mfc)
{
	unsigned int i;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": multiconnect done.", mfc->id);

	/* Check if anyone failed.  */
	for (i = 0; i < tal_count(mfc->destinations); ++i) {
		struct multifundchannel_destination *dest;

		dest = &mfc->destinations[i];

		assert(dest->state == MULTIFUNDCHANNEL_CONNECTED
		    || dest->state == MULTIFUNDCHANNEL_FAILED);

		if (dest->state != MULTIFUNDCHANNEL_FAILED)
			continue;

		/* One of them failed, oh no. */
		return redo_multifundchannel(mfc, "connect",
					     dest->error_message);
	}

	return perform_fundpsbt(mfc);
}

static struct command_result *
connect_done(struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;

	--mfc->pending;
	if (mfc->pending == 0)
		return after_multiconnect(mfc);
	else
		return command_still_pending(mfc->cmd);
}


static struct command_result *
connect_ok(struct command *cmd,
	   const char *buf,
	   const jsmntok_t *result,
	   struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;
	const jsmntok_t *features_tok;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: connect done.",
		   mfc->id, dest->index);

	features_tok = json_get_member(buf, result, "features");
	if (!features_tok)
		plugin_err(cmd->plugin,
			   "'connect' did not return 'features'? %.*s",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));
	dest->their_features = json_tok_bin_from_hex(mfc, buf, features_tok);
	if (!dest->their_features)
		plugin_err(cmd->plugin,
			   "'connect' has unparesable 'features'? %.*s",
			   json_tok_full_len(features_tok),
			   json_tok_full(buf, features_tok));

	/* Set the open protocol to use now */
	if (feature_negotiated(plugin_feature_set(mfc->cmd->plugin),
			       dest->their_features,
			       OPT_DUAL_FUND))
		dest->protocol = OPEN_CHANNEL;

	dest->state = MULTIFUNDCHANNEL_CONNECTED;
	return connect_done(dest);
}

static struct command_result *
connect_err(struct command *cmd,
	    const char *buf,
	    const jsmntok_t *error,
	    struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: failed! connect %s: %.*s.",
		   mfc->id, dest->index,
		   node_id_to_hexstr(tmpctx, &dest->id),
		   json_tok_full_len(error),
		   json_tok_full(buf, error));

	fail_destination_tok(dest, buf, error);
	return connect_done(dest);
}

static void
connect_dest(struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;
	struct command *cmd = mfc->cmd;
	const char *id;
	struct out_req *req;

	id = node_id_to_hexstr(tmpctx, &dest->id);
	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: connect %s.",
		   mfc->id, dest->index, id);

	req = jsonrpc_request_start(cmd->plugin, cmd,
				    "connect",
				    &connect_ok,
				    &connect_err,
				    dest);
	if (dest->addrhint)
		json_add_string(req->js, "id",
				tal_fmt(tmpctx, "%s@%s",
					id,
					dest->addrhint));
	else
		json_add_node_id(req->js, "id", &dest->id);
	send_outreq(cmd->plugin, req);
}

/*-----------------------------------------------------------------------------
Starting
-----------------------------------------------------------------------------*/

/* Initiate the multiconnect.  */
static struct command_result *
perform_multiconnect(struct multifundchannel_command *mfc)
{
	unsigned int i;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": multiconnect.", mfc->id);

	mfc->pending = tal_count(mfc->destinations);

	for (i = 0; i < tal_count(mfc->destinations); ++i)
		connect_dest(&mfc->destinations[i]);

	assert(mfc->pending != 0);
	return command_still_pending(mfc->cmd);
}


/* Initiate the multifundchannel execution.  */
static struct command_result *
perform_multifundchannel(struct multifundchannel_command *mfc)
{
	return perform_multiconnect(mfc);
}


/*-----------------------------------------------------------------------------
Re-try Entry Point
-----------------------------------------------------------------------------*/
/*~ We do cleanup, then we remove failed destinations and if we still have
 * the minimum number, re-run.
*/
struct multifundchannel_redo {
	struct multifundchannel_command *mfc;
	const char *failing_method;
};

/* Filter the failing destinations.  */
static struct command_result *
post_cleanup_redo_multifundchannel(struct multifundchannel_redo *redo)
{
	struct multifundchannel_command *mfc = redo->mfc;
	const char *failing_method = redo->failing_method;
	size_t i;
	struct multifundchannel_destination *old_destinations;
	struct multifundchannel_destination *new_destinations;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": Filtering destinations.",
		   mfc->id);

	/* We got the args now.  */
	tal_free(redo);

	/* Clean up previous funding transaction if any.  */
	mfc->psbt = tal_free(mfc->psbt);
	mfc->txid = tal_free(mfc->txid);

	/* Filter out destinations.  */
	old_destinations = tal_steal(tmpctx, mfc->destinations);
	mfc->destinations = NULL;
	new_destinations = tal_arr(mfc, struct multifundchannel_destination,
				   0);

	for (i = 0; i < tal_count(old_destinations); ++i) {
		struct multifundchannel_destination *dest;

		dest = &old_destinations[i];

		/* We have to fail any v2 that has commitments already */
		if (is_v2(dest) && has_commitments_secured(dest)
		     && !dest_failed(dest)) {
			fail_destination_msg(dest, FUNDING_STATE_INVALID,
					     "Attempting retry,"
					     " yet this peer already has"
					     " exchanged commitments and is"
					     " using the v2 open protocol."
					     " Must spend input to reset.");
		}

		if (dest_failed(dest)) {
		    /* We can't re-try committed v2's */
			struct multifundchannel_removed removed;

			plugin_log(mfc->cmd->plugin, LOG_DBG,
				   "mfc %"PRIu64", dest %u: "
				   "failed.",
				   mfc->id, dest->index);

			removed.id = dest->id;
			removed.method = failing_method;
			removed.error_message = dest->error_message;
			removed.error_code = dest->error_code;
			removed.error_data = dest->error_data;
			/* Add to removeds.  */
			tal_arr_expand(&mfc->removeds, removed);
		} else {
			plugin_log(mfc->cmd->plugin, LOG_DBG,
				   "mfc %"PRIu64", dest %u: "
				   "succeeded.",
				   mfc->id, dest->index);

			/* Reset its state.  */
			dest->state = MULTIFUNDCHANNEL_START_NOT_YET;
			/* We do not mess with `dest->index` so we have
			a stable id between reattempts.
			*/
			/* Re-add to new destinations.  */
			tal_arr_expand(&new_destinations, *dest);
		}
	}
	mfc->destinations = new_destinations;

	if (tal_count(mfc->destinations) < mfc->minchannels) {
		/* Too many failed. */
		struct json_stream *out;

		assert(tal_count(mfc->removeds) != 0);

		plugin_log(mfc->cmd->plugin, LOG_DBG,
			   "mfc %"PRIu64": %zu destinations failed, failing.",
			   mfc->id, tal_count(mfc->removeds));

		/* Blame it on the last.  */
		i = tal_count(mfc->removeds) - 1;

		out = jsonrpc_stream_fail_data(mfc->cmd,
					       mfc->removeds[i].error_code,
					       mfc->removeds[i].error_message);
		json_add_node_id(out, "id", &mfc->removeds[i].id);
		json_add_string(out, "method", failing_method);
		if (mfc->removeds[i].error_data)
			json_add_jsonstr(out, "data",
					 mfc->removeds[i].error_data);

		/* Close 'data'.  */
		json_object_end(out);

		return mfc_finished(mfc, out);
	}

	/* Okay, we still have destinations to try --- reinvoke.  */
	return perform_multifundchannel(mfc);
}

struct command_result *
redo_multifundchannel(struct multifundchannel_command *mfc,
		      const char *failing_method,
		      const char *why)
{
	struct multifundchannel_redo *redo;

	assert(mfc->pending == 0);

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": trying redo despite '%s' failure (%s);"
		   " will cleanup for now.",
		   mfc->id, failing_method, why);

	redo = tal(mfc, struct multifundchannel_redo);
	redo->mfc = mfc;
	redo->failing_method = failing_method;

	return mfc_cleanup(mfc, &post_cleanup_redo_multifundchannel, redo);
}

/*-----------------------------------------------------------------------------
Input Validation
-----------------------------------------------------------------------------*/

/* Validates the destinations input argument.

Returns NULL if checking of destinations array worked,
or non-NULL if it failed (and this function has already
executed mfc_fail).
*/
static struct command_result *
param_destinations_array(struct command *cmd, const char *name,
			 const char *buffer, const jsmntok_t *tok,
			 struct multifundchannel_destination **dests)
{
	size_t i;
	const jsmntok_t *json_dest;
	bool has_all = false;

	if (tok->type != JSMN_ARRAY)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "must be an array");
	if (tok->size < 1)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "must have at least one entry");

	*dests = tal_arr(cmd, struct multifundchannel_destination, tok->size);
	for (i = 0; i < tal_count(*dests); ++i)
		(*dests)[i].state = MULTIFUNDCHANNEL_START_NOT_YET;

	json_for_each_arr(i, json_dest, tok) {
		struct multifundchannel_destination *dest;
		const char *id;
		char *addrhint;
		struct amount_sat *amount;
		bool *announce;
		struct amount_msat *push_msat;

		dest = &(*dests)[i];

		if (!param(cmd, buffer, json_dest,
			   p_req("id", param_string, &id),
			   p_req("amount", param_sat_or_all, &amount),
			   p_opt_def("announce", param_bool, &announce, true),
			   p_opt_def("push_msat", param_msat, &push_msat,
				     AMOUNT_MSAT(0)),
			   /* FIXME: do address validation here?
			    * Note that it will fail eventually (when
			    * passed in to fundchannel_start) if invalid*/
			   p_opt("close_to", param_string,
				 &dest->close_to_str),
			   NULL))
			return command_param_failed();

		addrhint = strchr(id, '@');
		if (addrhint) {
			/* Split at @.  */
			size_t idlen = (size_t) (addrhint - id);
			addrhint = tal_strdup(*dests, addrhint + 1);
			id = tal_strndup(*dests, take(id), idlen);
		}

		if (!node_id_from_hexstr(id, strlen(id), &dest->id))
			return command_fail_badparam(cmd, name, buffer,
						     json_dest,
						     "invalid node id");

		if (!amount_sat_eq(*amount, AMOUNT_SAT(-1ULL)) &&
		    amount_sat_less(*amount, chainparams->dust_limit))
			return command_fail_badparam(cmd, name, buffer,
						     json_dest,
						     "output would be dust");

		dest->index = i;
		dest->addrhint = addrhint;
		dest->their_features = NULL;
		dest->funding_script = NULL;
		dest->funding_addr = NULL;
		dest->all = amount_sat_eq(*amount, AMOUNT_SAT(-1ULL));
		dest->amount = dest->all ? AMOUNT_SAT(0) : *amount;
		dest->announce = *announce;
		dest->push_msat = *push_msat;
		dest->psbt = NULL;
		dest->updated_psbt = NULL;
		dest->protocol = FUND_CHANNEL;

		/* Only one destination can have "all" indicator.  */
		if (dest->all) {
			if (has_all)
				return command_fail_badparam(cmd, name, buffer,
							     json_dest,
							     "only one destination "
							     "can indicate \"all\" "
							     "for 'amount'.");
			else
				has_all = true;
		}

		/* Make sure every id is unique.  */
		for (size_t j = 0; j < i; j++) {
			if (node_id_eq(&dest->id, &(*dests)[j].id))
				return command_fail_badparam(cmd, name, buffer,
							     json_dest,
							     "Duplicate destination");
		}
	}

	return NULL;
}

static struct command_result *
param_positive_number(struct command *cmd,
		      const char *name,
		      const char *buffer,
		      const jsmntok_t *tok,
		      unsigned int **num)
{
	struct command_result *res = param_number(cmd, name, buffer, tok, num);
	if (res)
		return res;
	if (**num == 0)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be a positive integer");
	return NULL;
}

/*-----------------------------------------------------------------------------
Command Entry Point
-----------------------------------------------------------------------------*/
static struct command_result *
json_multifundchannel(struct command *cmd,
		      const char *buf,
		      const jsmntok_t *params)
{
	struct multifundchannel_destination *dests;
	const char *feerate_str, *cmtmt_feerate_str;
	u32 *minconf;
	const jsmntok_t *utxos_tok;
	u32 *minchannels;

	struct multifundchannel_command *mfc;

	if (!param(cmd, buf, params,
		   p_req("destinations", param_destinations_array, &dests),
		   p_opt("feerate", param_string, &feerate_str),
		   p_opt_def("minconf", param_number, &minconf, 1),
		   p_opt("utxos", param_tok, &utxos_tok),
		   p_opt("minchannels", param_positive_number, &minchannels),
		   p_opt("commitment_feerate", param_string, &cmtmt_feerate_str),
		   NULL))
		return command_param_failed();

	/* Should exist; it would only nonexist if it were a notification.  */
	assert(cmd->id);

	mfc = tal(cmd, struct multifundchannel_command);
	mfc->id = *cmd->id;
	mfc->cmd = cmd;

	/* Steal destinations array, and set up mfc pointers */
	mfc->destinations = tal_steal(mfc, dests);
	for (size_t i = 0; i < tal_count(mfc->destinations); i++)
		mfc->destinations[i].mfc = mfc;

	mfc->feerate_str = feerate_str;
	mfc->cmtmt_feerate_str = cmtmt_feerate_str;
	mfc->minconf = *minconf;
	if (utxos_tok)
		mfc->utxos_str = tal_strndup(mfc, json_tok_full(buf, utxos_tok),
					     json_tok_full_len(utxos_tok));
	else
		mfc->utxos_str = NULL;
	/* Default is that all must succeed. */
	mfc->minchannels = minchannels ? *minchannels : tal_count(mfc->destinations);
	mfc->removeds = tal_arr(mfc, struct multifundchannel_removed, 0);
	mfc->psbt = NULL;
	mfc->change_scriptpubkey = NULL;
	mfc->txid = NULL;
	mfc->final_tx = NULL;
	mfc->final_txid = NULL;

	mfc->sigs_collected = false;

	return perform_multifundchannel(mfc);
}

const struct plugin_command multifundchannel_commands[] = {
	{
		"multifundchannel",
		"channels",
		"Fund channels to {destinations}, which is an array of "
		"objects containing peer {id}, {amount}, and optional "
		"{announce} and {push_msat}.  "
		"A single transaction will be used to fund all the "
		"channels.  "
		"Use {feerate} for the transaction, select outputs that are "
		"buried {minconf} blocks deep, or specify a set of {utxos}.",
		"Fund multiple channels at once.",
		json_multifundchannel
	}
};
const size_t num_multifundchannel_commands =
	ARRAY_SIZE(multifundchannel_commands);
