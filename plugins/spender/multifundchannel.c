#include "config.h"
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/addr.h>
#include <common/channel_type.h>
#include <common/json_channel_type.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/psbt_open.h>
#include <common/pseudorand.h>
#include <plugins/spender/multifundchannel.h>
#include <plugins/spender/openchannel.h>

extern const struct chainparams *chainparams;

/* Which destinations has a value of "all", or -1.  */
static struct multifundchannel_destination *all_dest(const struct multifundchannel_command *mfc)
{
	for (size_t i = 0; i < tal_count(mfc->destinations); i++) {
		if (mfc->destinations[i].all)
			return &mfc->destinations[i];
	}
	return NULL;
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
			  enum jsonrpc_errcode error_code,
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

static struct command_result *unreserve_call(struct command *cmd,
					     struct wally_psbt *psbt,
					     void *cb, void *cbdata)
{
	struct wally_psbt *pruned_psbt;
	struct out_req *req = jsonrpc_request_start(cmd->plugin,
						    cmd,
						    "unreserveinputs",
						    cb, cb, cbdata);

	/* We might have peer's inputs on this, get rid of them */
	tal_wally_start();
	if (wally_psbt_clone_alloc(psbt, 0, &pruned_psbt) != WALLY_OK)
		abort();
	tal_wally_end_onto(NULL, pruned_psbt, struct wally_psbt);

	for (size_t i = pruned_psbt->num_inputs - 1;
	     i < pruned_psbt->num_inputs;
	     i--) {
		if (!psbt_input_is_ours(&pruned_psbt->inputs[i]))
			psbt_rm_input(pruned_psbt, i);
	}

	json_add_psbt(req->js, "psbt", take(pruned_psbt));
	json_add_u32(req->js, "reserve", 2016);
	return send_outreq(cmd->plugin, req);
}

/* Cleans up a txid by doing `txdiscard` on it.  */
static void
mfc_cleanup_psbt(struct command *cmd,
		 struct multifundchannel_cleanup *cleanup,
		 struct wally_psbt *psbt)
{
	unreserve_call(cmd, psbt, mfc_cleanup_done, cleanup);
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
	enum jsonrpc_errcode code;
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
mfc_fail(struct multifundchannel_command *mfc, enum jsonrpc_errcode code,
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
		json_add_channel_type(out, "channel_type",
				      mfc->destinations[i].channel_type);
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
					 mfc->removeds[i].error_data,
					 strlen(mfc->removeds[i].error_data));
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

	if (!psbt_set_version(psbt, 2)) {
		/* It should be well-formed? */
		plugin_err(mfc->cmd->plugin,
			   "mfc: could not set PSBT version: %s",
		   		fmt_wally_psbt(tmpctx, mfc->psbt));
	}

	if (!psbt_finalize(psbt))
		plugin_err(mfc->cmd->plugin,
			   "mfc %"PRIu64": Signed PSBT won't finalize"
			   "%s", mfc->id,
			   fmt_wally_psbt(tmpctx, psbt));


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
		   fmt_node_id(tmpctx, &dest->id));

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
		   fmt_node_id(tmpctx, &dest->id),
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
		   fmt_node_id(tmpctx, &dest->id));

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

/*~ The PSBT we are holding currently has no outputs
  (except an optional change output).
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
	u32 psbt_version = mfc->psbt->version;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": Creating funding tx.",
		   mfc->id);

	/* We operate over PSBTv2 only */
	if (!psbt_set_version(mfc->psbt, 2)) {
		/* It should be well-formed? */
		plugin_err(mfc->cmd->plugin,
			   "mfc: could not set PSBT version: %s",
		   		fmt_wally_psbt(tmpctx, mfc->psbt));
	}

	/* Construct a deck of destinations.  */
	deck = tal_arr(tmpctx, struct multifundchannel_destination *,
		       v1_dest_count);

	deck_i = 0;
	for (i = 0; i < tal_count(mfc->destinations); i++) {
		if (is_v2(&mfc->destinations[i]))
			continue;

		assert(deck_i < tal_count(deck));
		deck[deck_i++] = &mfc->destinations[i];
	}

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
		struct multifundchannel_destination *dest;

		if (outnum != 0)
			tal_append_fmt(&content, ", ");

		/* Funding outpoint.  */
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
			       fmt_node_id(tmpctx, &dest->id),
			       fmt_amount_sat(tmpctx, dest->amount));
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
		   fmt_bitcoin_txid(tmpctx, mfc->txid),
		   content);

	if (!psbt_set_version(mfc->psbt, psbt_version)) {
		/* It should be well-formed? */
		plugin_err(mfc->cmd->plugin,
			   "mfc: could not set PSBT version: %s",
		   		fmt_wally_psbt(tmpctx, mfc->psbt));
	}

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

struct channel_type *json_bits_to_channel_type(const tal_t *ctx,
					       const char *buffer, const jsmntok_t *tok)
{
	u8 *features = tal_arr(NULL, u8, 0);
	size_t i;
	const jsmntok_t *t;

	if (tok->type != JSMN_ARRAY)
		return tal_free(features);

	json_for_each_arr(i, t, tok) {
		u32 fbit;
		if (!json_to_u32(buffer, t, &fbit))
			return tal_free(features);
		set_feature_bit(&features, fbit);
	}
	return channel_type_from(ctx, take(features));
}

static struct command_result *
fundchannel_start_ok(struct command *cmd,
		     const char *buf,
		     const jsmntok_t *result,
		     struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;
	const char *err;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: fundchannel_start %s done.",
		   mfc->id, dest->index,
		   fmt_node_id(tmpctx, &dest->id));

	/* May not be set */
	dest->close_to_script = NULL;
	err = json_scan(mfc, buf, result,
			"{funding_address:%,"
			"scriptpubkey:%,"
			"channel_type:{bits:%},"
			"close_to?:%}",
			JSON_SCAN_TAL(mfc, json_strdup, &dest->funding_addr),
			JSON_SCAN_TAL(mfc, json_tok_bin_from_hex, &dest->funding_script),
			JSON_SCAN_TAL(mfc, json_bits_to_channel_type, &dest->channel_type),
			JSON_SCAN_TAL(mfc, json_tok_bin_from_hex, &dest->close_to_script));
	if (err)
		plugin_err(cmd->plugin,
			   "fundchannel_start parsing error: %s", err);

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
		   fmt_node_id(tmpctx, &dest->id),
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
		   fmt_node_id(tmpctx, &dest->id));

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
	json_add_amount_msat(req->js, "push_msat", dest->push_msat);

	if (dest->close_to_str)
		json_add_string(req->js, "close_to", dest->close_to_str);

	if (dest->mindepth)
		json_add_u32(req->js, "mindepth", *dest->mindepth);

	if (dest->channel_type) {
		json_add_channel_type_arr(req->js,
					  "channel_type", dest->channel_type);
	}

	if (dest->reserve)
		json_add_string(
		    req->js, "reserve",
		    fmt_amount_sat(tmpctx, *dest->reserve));

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
		   fmt_wally_psbt(tmpctx, mfc->psbt));

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

	return perform_channel_start(mfc);
}

/* Limited recursion if we discover 'all' is too big for non-wumbo! */
static struct command_result *
perform_fundpsbt(struct multifundchannel_command *mfc, u32 feerate);

static struct command_result *
retry_fundpsbt_capped_all(struct command *cmd,
			  const char *buf,
			  const jsmntok_t *result,
			  struct multifundchannel_command *mfc)
{
	/* We've unreserved this, now free it and try again! */
	tal_free(mfc->psbt);
	return perform_fundpsbt(mfc, mfc->feerate_per_kw);
}

static struct command_result *
after_fundpsbt(struct command *cmd,
	       const char *buf,
	       const jsmntok_t *result,
	       struct multifundchannel_command *mfc)
{
	const jsmntok_t *field;
	struct multifundchannel_destination *all;

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

	if (!psbt_set_version(mfc->psbt, 2))
		goto fail;

	/* Mark our inputs now, so we unreserve correctly on failure! */
	for (size_t i = 0; i < mfc->psbt->num_inputs; i++)
		psbt_input_mark_ours(mfc->psbt, &mfc->psbt->inputs[i]);

	field = json_get_member(buf, result, "feerate_per_kw");
	if (!field || !json_to_u32(buf, field, &mfc->feerate_per_kw))
		goto fail;

	field = json_get_member(buf, result, "estimated_final_weight");
	if (!field || !json_to_u32(buf, field, &mfc->estimated_final_weight))
		goto fail;

	all = all_dest(mfc);
	if (all) {
		struct amount_msat msat;

		/* excess_msat is amount to use for "all".  */
		field = json_get_member(buf, result, "excess_msat");
		if (!field || !parse_amount_msat(&msat,
						 buf + field->start,
						 field->end - field->start)
		    || !amount_msat_to_sat(&all->amount, msat))
			goto fail;

		/* Subtract amounts we're using for the other outputs */
		for (size_t i = 0; i < tal_count(mfc->destinations); i++) {
			if (mfc->destinations[i].all)
				continue;
			if (!amount_sat_sub(&all->amount,
					    all->amount,
					    mfc->destinations[i].amount)) {
				return mfc_fail(mfc, JSONRPC2_INVALID_PARAMS,
						"Insufficient funds for `all`"
						" output");
			}
		}

		/* Remove the 'all' flag.  */
		all->all = false;

		/* It's first grade, Spongebob! */
		if (!feature_negotiated(plugin_feature_set(mfc->cmd->plugin),
					all->their_features,
					OPT_LARGE_CHANNELS)
		    && amount_sat_greater(all->amount,
					  chainparams->max_funding)) {
			/* Oh, crap!  Set this amount and retry! */
			plugin_log(mfc->cmd->plugin, LOG_INFORM,
				   "'all' was too large for non-wumbo channel, trimming from %s to %s",
				   fmt_amount_sat(tmpctx, all->amount),
				   fmt_amount_sat(tmpctx, chainparams->max_funding));
			all->amount = chainparams->max_funding;
			return unreserve_call(mfc->cmd, mfc->psbt,
					      retry_fundpsbt_capped_all, mfc);
		}
	}
	return mfc_psbt_acquired(mfc);

fail:
	plugin_err(mfc->cmd->plugin,
		   "Unexpected result from fundpsbt/utxopsbt: %.*s",
		   json_tok_full_len(result),
		   json_tok_full(buf, result));

}

static bool any_dest_negotiated_anchors(const struct plugin *plugin,
					const struct multifundchannel_destination *dests)
{
	for (size_t i = 0; i < tal_count(dests); i++) {
		if (feature_negotiated(plugin_feature_set(plugin),
				       dests[i].their_features,
				       OPT_ANCHORS_ZERO_FEE_HTLC_TX))
			return true;
	}
	return false;
}

static struct command_result *
perform_fundpsbt(struct multifundchannel_command *mfc, u32 feerate)
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
		json_add_jsonstr(req->js, "utxos",
				 mfc->utxos_str, strlen(mfc->utxos_str));
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
		/* If there's any v2 opens, we can't use p2sh inputs */
		json_add_bool(req->js, "nonwrapped",
			      dest_count(mfc, OPEN_CHANNEL) > 0);
	}

	/* If we're about to open an anchor channel, we need emergency funds! */
	if (any_dest_negotiated_anchors(mfc->cmd->plugin,
					mfc->destinations)) {
		json_add_bool(req->js, "opening_anchor_channel", true);
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
	if (all_dest(mfc) != NULL)
		json_add_string(req->js, "satoshi", "all");
	else {
		struct amount_sat sum = AMOUNT_SAT(0);
		for (size_t i = 0; i < tal_count(mfc->destinations); ++i) {
			struct amount_sat requested
				= mfc->destinations[i].request_amt;

			if (!amount_sat_add(&sum,
					    sum, mfc->destinations[i].amount))
				return mfc_fail(mfc, JSONRPC2_INVALID_PARAMS,
						"Overflow while summing "
						"destination values.");
			/* Also add in any fees for requested amt! */
			if (!amount_sat_zero(requested)) {
				struct amount_sat fee;

				/* Assume they send >= what we've
				 * requested (otherwise we error) */
				if (!lease_rates_calc_fee(mfc->destinations[i].rates,
							  requested, requested,
							  feerate,
							  &fee))
					return mfc_fail(mfc, JSONRPC2_INVALID_PARAMS,
							"Overflow calculating"
							" lease fee.");


				if (!amount_sat_add(&sum, sum, fee))
					return mfc_fail(mfc, JSONRPC2_INVALID_PARAMS,
							"Overflow while summing"
							" lease fee");
			}
		}
		json_add_string(req->js, "satoshi",
				fmt_amount_sat(tmpctx, sum));
	}
	json_add_string(req->js, "feerate", tal_fmt(tmpctx, "%uperkw", feerate));

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
	/* BOLT-WHERE? #3:
	 * The minimum witness weight for an input is 110.
	 */
	if (dest_count(mfc, OPEN_CHANNEL) > 0) {
		json_add_string(req->js, "min_witness_weight",
				tal_fmt(tmpctx, "%u", 110));
	}

	/* Handle adding a change output if required. */
	json_add_bool(req->js, "excess_as_change", true);

	return send_outreq(mfc->cmd->plugin, req);
}

static struct command_result *
after_getfeerate(struct command *cmd,
		 const char *buf,
		 const jsmntok_t *result,
		 struct multifundchannel_command *mfc)
{
	const char *err;
	u32 feerate;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": 'parsefeerate' done", mfc->id);

	err = json_scan(tmpctx, buf, result,
			"{perkw:%}",
			JSON_SCAN(json_to_number, &feerate));
	if (err)
		mfc_fail(mfc, JSONRPC2_INVALID_PARAMS,
			 "Unable to parse feerate %s: %*.s",
			 err, json_tok_full_len(result),
			 json_tok_full(buf, result));

	return perform_fundpsbt(mfc, feerate);
}

static struct command_result *
getfeerate(struct multifundchannel_command *mfc)
{
	struct out_req *req;
	/* With the introduction of channel leases (option_will_fund),
	 * we need to include enough in the PSBT to cover our expected
	 * fees for the channel open. This requires that we know
	 * the feerate ahead of time, so that we can figure the
	 * expected lease fees, and add that to the funding amount. */
	req = jsonrpc_request_start(mfc->cmd->plugin,
				    mfc->cmd,
				    "parsefeerate",
				    &after_getfeerate,
				    &mfc_forward_error,
				    mfc);

	/* Internally, it defaults to 'opening', so we use that here */
	json_add_string(req->js, "feerate",
			mfc->feerate_str ? mfc->feerate_str: "opening");

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

	return getfeerate(mfc);
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

	dest->state = MULTIFUNDCHANNEL_CONNECTED;

	/* Set the open protocol to use now */
	if (feature_negotiated(plugin_feature_set(mfc->cmd->plugin),
			       dest->their_features,
			       OPT_DUAL_FUND))
		dest->protocol = OPEN_CHANNEL;
	else if (!amount_sat_zero(dest->request_amt) || !(!dest->rates))
		/* Return an error */
		fail_destination_msg(dest, FUNDING_V2_NOT_SUPPORTED,
				     "Tried to buy a liquidity ad"
				     " but we(?) don't have"
				     " experimental-dual-fund"
				     " enabled");

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
		   fmt_node_id(tmpctx, &dest->id),
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

	id = fmt_node_id(tmpctx, &dest->id);
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
static void
perform_multifundchannel(struct multifundchannel_command *mfc)
{
	perform_multiconnect(mfc);
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
			/* FIXME: If this were an array of pointers,
			 * we could make dest itself the parent of
			 * ->addrhint and not need this wart! */
			tal_steal(new_destinations, dest->addrhint);
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
					 mfc->removeds[i].error_data,
					 strlen(mfc->removeds[i].error_data));

		/* Close 'data'.  */
		json_object_end(out);

		return mfc_finished(mfc, out);
	}

	/* Okay, we still have destinations to try: wait a second in case it
	 * takes that long to disconnect from peer, then retry.  */
	plugin_timer(mfc->cmd->plugin, time_from_sec(1),
		     perform_multifundchannel, mfc);
	return command_still_pending(mfc->cmd);
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
		struct amount_sat *amount, *request_amt;
		bool *announce;
		struct amount_msat *push_msat;
		struct lease_rates *rates;

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
			   p_opt_def("request_amt", param_sat, &request_amt,
				     AMOUNT_SAT(0)),
			   p_opt("compact_lease", param_lease_hex, &rates),
			   p_opt("mindepth", param_u32, &dest->mindepth),
			   p_opt("reserve", param_sat, &dest->reserve),
			   p_opt("channel_type", param_channel_type, &dest->channel_type),
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

		if (!amount_sat_zero(*request_amt) && !rates)
			return command_fail_badparam(cmd, name, buffer,
					             json_dest,
						     "Must pass in 'compact_"
						     "lease' if requesting"
						     " funds from peer");
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
		dest->request_amt = *request_amt;
		dest->rates = tal_steal(*dests, rates);

		/* Stop leak detection from complaining. */
		tal_free(id);
		tal_free(amount);
		tal_free(push_msat);
		tal_free(request_amt);
		tal_free(announce);

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

static struct command_result *param_utxos_str(struct command *cmd, const char *name,
					      const char * buffer, const jsmntok_t *tok,
					      const char **str)
{
	if (tok->type != JSMN_ARRAY)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "should be an array");
	*str = tal_strndup(cmd, buffer + tok->start,
			   tok->end - tok->start);
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
	u32 *minconf;
	u32 *minchannels;

	struct multifundchannel_command *mfc;

	mfc = tal(cmd, struct multifundchannel_command);
	if (!param(cmd, buf, params,
		   p_req("destinations", param_destinations_array, &dests),
		   p_opt("feerate", param_string, &mfc->feerate_str),
		   p_opt_def("minconf", param_number, &minconf, 1),
		   p_opt("utxos", param_utxos_str, &mfc->utxos_str),
		   p_opt("minchannels", param_positive_number, &minchannels),
		   p_opt("commitment_feerate", param_string, &mfc->cmtmt_feerate_str),
		   NULL))
		return command_param_failed();

	/* Should exist; it would only nonexist if it were a notification.  */
	assert(cmd->id);

	mfc->id = *cmd->id;
	mfc->cmd = cmd;

	/* Steal destinations array, and set up mfc pointers */
	mfc->destinations = tal_steal(mfc, dests);
	for (size_t i = 0; i < tal_count(mfc->destinations); i++)
		mfc->destinations[i].mfc = mfc;

	mfc->minconf = *minconf;
	/* Default is that all must succeed. */
	mfc->minchannels = minchannels ? *minchannels : tal_count(mfc->destinations);
	mfc->removeds = tal_arr(mfc, struct multifundchannel_removed, 0);
	mfc->psbt = NULL;
	mfc->txid = NULL;
	mfc->final_tx = NULL;
	mfc->final_txid = NULL;

	mfc->sigs_collected = false;

	perform_multifundchannel(mfc);
	return command_still_pending(mfc->cmd);
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
