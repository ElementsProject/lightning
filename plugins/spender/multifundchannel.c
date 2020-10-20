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
#include <common/pseudorand.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <plugins/spender/multifundchannel.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/* Current state of the funding process.  */
enum multifundchannel_state {
	/* We have not yet performed `fundchannel_start`.  */
	MULTIFUNDCHANNEL_START_NOT_YET = 0,
	/* The `connect` command failed.  `*/
	MULTIFUNDCHANNEL_CONNECT_FAILED,
	/* The `fundchannel_start` command succeeded.  */
	MULTIFUNDCHANNEL_STARTED,
	/* The `fundchannel_start` command failed.  */
	MULTIFUNDCHANNEL_START_FAILED,
	/* The `fundchannel_complete` command failed.  */
	MULTIFUNDCHANNEL_COMPLETE_FAILED,
	/* The transaction might now be broadcasted.  */
	MULTIFUNDCHANNEL_DONE
};

/* The object for a single destination.  */
struct multifundchannel_destination {
	/* The overall multifundchannel command object.  */
	struct multifundchannel_command *mfc;

	/* The overall multifundchannel_command contains an
	array of multifundchannel_destinations.
	This provides the index within the array.

	This is used in debug printing.
	*/
	unsigned int index;

	/* ID for this destination.  */
	struct node_id id;
	/* Address hint for this destination, NULL if not
	specified.
	*/
	const char *addrhint;
	/* The features this destination has.  */
	const u8 *their_features;

	/* Whether we have `fundchannel_start`, failed `connect` or
	`fundchannel_complete`, etc.
	*/
	enum multifundchannel_state state;

	/* The actual target script and address.  */
	const u8 *funding_script;
	const char *funding_addr;

	/* The bitcoin address to close to */
	const char *close_to_str;

	/* The scriptpubkey we will close to. Only set if
	 * peer supports opt_upfront_shutdownscript and
	 * we passsed in a valid close_to_str */
	const u8 *close_to_script;

	/* The amount to be funded for this destination.
	If the specified amount is "all" then the `all`
	flag is set, and the amount is initially 0 until
	we have figured out how much exactly "all" is,
	after the dryrun stage.
	*/
	bool all;
	struct amount_sat amount;

	/* The output index for this destination.  */
	unsigned int outnum;

	/* Whether the channel to this destination will
	be announced.
	*/
	bool announce;
	/* How much of the initial funding to push to
	the destination.
	*/
	struct amount_msat push_msat;

	/* The actual channel_id.  */
	const char *channel_id;

	/* Any error messages.  */
	const char *error;
	errcode_t code;
};

/* Stores a destination that was removed due to some failure.  */
struct multifundchannel_removed {
	/* The destination we removed.  */
	struct node_id id;
	/* The method that failed:
	connect, fundchannel_start, fundchannel_complete.
	*/
	const char *method;
	/* The error that caused this destination to be removed, in JSON.  */
	const char *error;
	errcode_t code;
};

/* The object for a single multifundchannel command.  */
struct multifundchannel_command {
	/* A unique numeric identifier for this particular
	multifundchannel execution.

	This is used for debug logs; we want to be able to
	identify *which* multifundchannel is being described
	in the debug logs, especially if the user runs
	multiple `multifundchannel` commands in parallel, or
	in very close sequence, which might confuse us with
	*which* debug message belongs with *which* command.

	We actually just reuse the id from the cmd.
	Store it here for easier access.
	*/
	u64 id;

	/* The plugin-level command.  */
	struct command *cmd;
	/* An array of destinations.  */
	struct multifundchannel_destination *destinations;
	/* Number of pending parallel fundchannel_start or
	fundchannel_complete.
	*/
	size_t pending;

	/* The feerate desired by the user.
	 * If cmtmt_feerate_str is present, will only be used
	 * for the funding transaction. */
	const char *feerate_str;

	/* The feerate desired by the user for
	 * the channel commitment and HTLC txs.
	 * If not provided, defaults to the feerate_str
	 * value. */
	const char *cmtmt_feerate_str;

	/* The minimum number of confirmations for owned
	UTXOs to be selected.
	*/
	u32 minconf;
	/* The set of utxos to be used.  */
	const char *utxos_str;
	/* How long should we keep going if things fail. */
	size_t minchannels;
	/* Array of destinations that were removed in a best-effort
	attempt to fund as many channels as possible.
	*/
	struct multifundchannel_removed *removeds;

	/* The PSBT of the funding transaction we are building.
	Prior to `fundchannel_start` completing for all destinations,
	this contains an unsigned incomplete transaction that is just a
	reservation of the inputs.
	After `fundchannel_start`, this contains an unsigned transaction
	with complete outputs.
	After `fundchannel_complete`, this contains a signed, finalized
	transaction.
	*/
	struct wally_psbt *psbt;
	/* The actual feerate of the PSBT.  */
	u32 feerate_per_kw;
	/* The expected weight of the PSBT after adding in all the outputs.
	 * In weight units (sipa).  */
	u32 estimated_final_weight;
	/* Excess satoshi from the PSBT.
	 * If "all" this is the entire amount; if not "all" this is the
	 * proposed change amount, which if dusty should be donated to
	 * the miners.
	 */
	struct amount_sat excess_sat;

	/* A convenient change address. NULL at the start, filled in
	 * if we detect we need it.  */
	const u8 *change_scriptpubkey;
	/* Whether we need a change output.  */
	bool change_needed;
	/* The change amount.  */
	struct amount_sat change_amount;

	/* The txid of the final funding transaction.  */
	struct bitcoin_txid *txid;

	/* The actual tx of the actual final funding transaction
	that was broadcast.
	*/
	const char *final_tx;
	const char *final_txid;
};

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

/* Cleans up a PSBT.  */
static void
mfc_cleanup_psbt(struct command *cmd,
		 struct multifundchannel_cleanup *cleanup,
		 struct wally_psbt *psbt);
/* Cleans up a `fundchannel_start`ed node id.  */
static void
mfc_cleanup_fc(struct command *cmd,
	       struct multifundchannel_cleanup *cleanup,
	       struct multifundchannel_destination *dest);
/* Run at completion of all cleanup tasks.  */
static struct command_result *
mfc_cleanup_complete(struct multifundchannel_cleanup *cleanup);

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

	if (mfc->psbt) {
		plugin_log(mfc->cmd->plugin, LOG_DBG,
			   "mfc %"PRIu64": unreserveinputs task.", mfc->id);

		++cleanup->pending;
		mfc_cleanup_psbt(mfc->cmd, cleanup, mfc->psbt);
	}
	for (i = 0; i < tal_count(mfc->destinations); ++i) {
		struct multifundchannel_destination *dest;
		dest = &mfc->destinations[i];

		/* If not started, nothing to clean up.  */
		if (dest->state != MULTIFUNDCHANNEL_STARTED)
			continue;

		plugin_log(mfc->cmd->plugin, LOG_DBG,
			   "mfc %"PRIu64", dest %u: "
			   "fundchannel_cancel task.",
			   mfc->id, dest->index);

		++cleanup->pending;
		mfc_cleanup_fc(mfc->cmd, cleanup, dest);
	}

	if (cleanup->pending == 0)
		return mfc_cleanup_complete(cleanup);
	else
		return command_still_pending(mfc->cmd);
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
	struct out_req *req = jsonrpc_request_start(cmd->plugin,
						    cmd,
						    "unreserveinputs",
						    &mfc_cleanup_done,
						    &mfc_cleanup_done,
						    cleanup);
	json_add_psbt(req->js, "psbt", psbt);
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
/* Done when all cleanup operations have completed.  */
static struct command_result *
mfc_cleanup_complete(struct multifundchannel_cleanup *cleanup)
{
	tal_steal(tmpctx, cleanup);
	return cleanup->cb(cleanup->arg);
}
#define mfc_cleanup(mfc, cb, arg) \
	mfc_cleanup_(mfc, typesafe_cb(struct command_result *, void *, \
				      (cb), (arg)), \
		     (arg))

/* Use this instead of command_fail.  */
static struct command_result *
mfc_fail(struct multifundchannel_command *, errcode_t code,
	 const char *fmt, ...);
/* Use this instead of forward_error.  */
static struct command_result *
mfc_forward_error(struct command *cmd,
		  const char *buf, const jsmntok_t *error,
		  struct multifundchannel_command *);
/* Use this instead of command_finished.  */
static struct command_result *
mfc_finished(struct multifundchannel_command *, struct json_stream *response);
/* Use this instead of command_err_raw.  */
static struct command_result *
mfc_err_raw(struct multifundchannel_command *, const char *json_string);

/*---------------------------------------------------------------------------*/

/* These are the actual implementations of the cleanup entry functions.  */

struct mfc_fail_object {
	struct multifundchannel_command *mfc;
	struct command *cmd;
	errcode_t code;
	const char *msg;
};
static struct command_result *
mfc_fail_complete(struct mfc_fail_object *obj);
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
static struct command_result *
mfc_fail_complete(struct mfc_fail_object *obj)
{
	plugin_log(obj->mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": cleanup done, failing.", obj->mfc->id);
	return command_fail(obj->cmd, obj->code, "%s", obj->msg);
}

struct mfc_err_raw_object {
	struct multifundchannel_command *mfc;
	const char *error;
};
static struct command_result *
mfc_err_raw_complete(struct mfc_err_raw_object *obj);
static struct command_result *
mfc_err_raw(struct multifundchannel_command *mfc, const char *json_string)
{
	struct mfc_err_raw_object *obj;

	obj = tal(mfc, struct mfc_err_raw_object);
	obj->mfc = mfc;
	obj->error = tal_strdup(obj, json_string);

	return mfc_cleanup(mfc, &mfc_err_raw_complete, obj);
}
static struct command_result *
mfc_err_raw_complete(struct mfc_err_raw_object *obj)
{
	plugin_log(obj->mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": cleanup done, failing raw.", obj->mfc->id);
	return command_err_raw(obj->mfc->cmd, obj->error);
}
static struct command_result *
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
mfc_finished_complete(struct mfc_finished_object *obj);
static struct command_result *
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
static struct command_result *
mfc_finished_complete(struct mfc_finished_object *obj)
{
	plugin_log(obj->mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": cleanup done, finishing command.",
		   obj->mfc->id);
	return command_finished(obj->cmd, obj->response);
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
		dest->channel_id = NULL;
		dest->error = NULL;

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

/*-----------------------------------------------------------------------------
Command Processing
-----------------------------------------------------------------------------*/

/* Function to redo multifundchannel after a failure.
*/
static struct command_result *
redo_multifundchannel(struct multifundchannel_command *mfc,
		      const char *failing_method);

static struct command_result *
perform_multiconnect(struct multifundchannel_command *mfc);

/* Initiate the multifundchannel execution.  */
static struct command_result *
perform_multifundchannel(struct multifundchannel_command *mfc)
{
	return perform_multiconnect(mfc);
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

static void
connect_dest(struct multifundchannel_destination *dest);

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

static struct command_result *
connect_ok(struct command *cmd,
	   const char *buf,
	   const jsmntok_t *result,
	   struct multifundchannel_destination *dest);
static struct command_result *
connect_err(struct command *cmd,
	    const char *buf,
	    const jsmntok_t *error,
	    struct multifundchannel_destination *dest);

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

static struct command_result *
connect_done(struct multifundchannel_destination *dest);

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

	return connect_done(dest);
}
static struct command_result *
connect_err(struct command *cmd,
	    const char *buf,
	    const jsmntok_t *error,
	    struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;
	const jsmntok_t *code_tok;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: failed! connect %s: %.*s.",
		   mfc->id, dest->index,
		   node_id_to_hexstr(tmpctx, &dest->id),
		   json_tok_full_len(error),
		   json_tok_full(buf, error));

	code_tok = json_get_member(buf, error, "code");
	if (!code_tok)
		plugin_err(cmd->plugin,
			   "`connect` failure did not have `code`? "
			   "%.*s",
			   json_tok_full_len(error),
			   json_tok_full(buf, error));
	if (!json_to_errcode(buf, code_tok, &dest->code))
		plugin_err(cmd->plugin,
			   "`connect` has unparseable `code`? "
			   "%.*s",
			   json_tok_full_len(code_tok),
			   json_tok_full(buf, code_tok));

	dest->state = MULTIFUNDCHANNEL_CONNECT_FAILED;
	dest->error = json_strdup(mfc, buf, error);

	return connect_done(dest);
}

static struct command_result *
after_multiconnect(struct multifundchannel_command *mfc);

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
perform_fundpsbt(struct multifundchannel_command *mfc);

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

		assert(dest->state == MULTIFUNDCHANNEL_START_NOT_YET
		    || dest->state == MULTIFUNDCHANNEL_CONNECT_FAILED);

		if (dest->state != MULTIFUNDCHANNEL_CONNECT_FAILED)
			continue;

		/* One of them failed, oh no. */
		return redo_multifundchannel(mfc, "connect");
	}

	return perform_fundpsbt(mfc);
}

/*---------------------------------------------------------------------------*/

/*~ Create an initial funding PSBT.

This creation of the initial funding PSBT is solely to reserve inputs for
our use.
This lets us initiate later with fundchannel_start with confidence that we
can actually afford the channels we will create.
*/

static struct command_result *
after_fundpsbt(struct command *cmd,
	       const char *buf,
	       const jsmntok_t *result,
	       struct multifundchannel_command *mfc);

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

	/* The entire point is to reserve the inputs.  */
	json_add_bool(req->js, "reserve", true);
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

	return send_outreq(mfc->cmd->plugin, req);
}

static struct command_result *
compute_mfc_all(struct multifundchannel_command *mfc);
static struct command_result *
handle_mfc_change(struct multifundchannel_command *mfc);

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
acquire_change_address(struct multifundchannel_command *mfc);
static struct command_result *
mfc_psbt_acquired(struct multifundchannel_command *mfc);

static struct command_result *
handle_mfc_change(struct multifundchannel_command *mfc)
{
	size_t change_weight;
	struct amount_sat change_fee;
	struct amount_sat change_min_limit;

	/* Determine if adding a change output is worth it.
	 * Get the weight of a change output and how much it
	 * costs.
	 */
	change_weight = bitcoin_tx_output_weight(
				BITCOIN_SCRIPTPUBKEY_P2WPKH_LEN);
	change_fee = amount_tx_fee(mfc->feerate_per_kw, change_weight);
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

static struct command_result *
after_newaddr(struct command *cmd,
	      const char *buf,
	      const jsmntok_t *result,
	      struct multifundchannel_command *mfc);

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
perform_fundchannel_start(struct multifundchannel_command *mfc);
static struct command_result *
mfc_psbt_acquired(struct multifundchannel_command *mfc)
{
	return perform_fundchannel_start(mfc);
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

static void
fundchannel_start_dest(struct multifundchannel_destination *dest);
static struct command_result *
perform_fundchannel_start(struct multifundchannel_command *mfc)
{
	unsigned int i;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": fundchannel_start parallel.", mfc->id);

	mfc->pending = tal_count(mfc->destinations);

	for (i = 0; i < tal_count(mfc->destinations); ++i)
		fundchannel_start_dest(&mfc->destinations[i]);

	assert(mfc->pending != 0);
	return command_still_pending(mfc->cmd);
}

/* Handles fundchannel_start success and failure.  */
static struct command_result *
fundchannel_start_ok(struct command *cmd,
		     const char *buf,
		     const jsmntok_t *result,
		     struct multifundchannel_destination *dest);
static struct command_result *
fundchannel_start_err(struct command *cmd,
		      const char *buf,
		      const jsmntok_t *error,
		      struct multifundchannel_destination *dest);

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
			fmt_amount_sat(tmpctx, &dest->amount));

	if (mfc->cmtmt_feerate_str)
		json_add_string(req->js, "feerate", mfc->cmtmt_feerate_str);
	else if (mfc->feerate_str)
		json_add_string(req->js, "feerate", mfc->feerate_str);
	json_add_bool(req->js, "announce", dest->announce);
	json_add_string(req->js, "push_msat",
			fmt_amount_msat(tmpctx, &dest->push_msat));
	if (dest->close_to_str)
		json_add_string(req->js, "close_to", dest->close_to_str);

	send_outreq(cmd->plugin, req);
}

static struct command_result *
fundchannel_start_done(struct multifundchannel_destination *dest);

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
	struct multifundchannel_command *mfc = dest->mfc;
	const jsmntok_t *code_tok;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: "
		   "failed! fundchannel_start %s: %.*s.",
		   mfc->id, dest->index,
		   node_id_to_hexstr(tmpctx, &dest->id),
		   json_tok_full_len(error),
		   json_tok_full(buf, error));

	code_tok = json_get_member(buf, error, "code");
	if (!code_tok)
		plugin_err(cmd->plugin,
			   "`fundchannel_start` failure did not have `code`? "
			   "%.*s",
			   json_tok_full_len(error),
			   json_tok_full(buf, error));
	if (!json_to_errcode(buf, code_tok, &dest->code))
		plugin_err(cmd->plugin,
			   "`fundchannel_start` has unparseable `code`? "
			   "%.*s",
			   json_tok_full_len(code_tok),
			   json_tok_full(buf, code_tok));

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

	dest->state = MULTIFUNDCHANNEL_START_FAILED;
	dest->error = json_strdup(dest->mfc, buf, error);

	return fundchannel_start_done(dest);
}

static struct command_result *
after_fundchannel_start(struct multifundchannel_command *mfc);

static struct command_result *
fundchannel_start_done(struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;

	--mfc->pending;
	if (mfc->pending == 0)
		return after_fundchannel_start(mfc);
	else
		return command_still_pending(mfc->cmd);
}

static struct command_result *
perform_funding_tx_finalize(struct multifundchannel_command *mfc);

/* All fundchannel_start commands have returned with either
success or failure.
*/
static struct command_result *
after_fundchannel_start(struct multifundchannel_command *mfc)
{
	unsigned int i;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": parallel fundchannel_start done.",
		   mfc->id);

	/* Check if any fundchannel_start failed.  */
	for (i = 0; i < tal_count(mfc->destinations); ++i) {
		struct multifundchannel_destination *dest;

		dest = &mfc->destinations[i];

		assert(dest->state == MULTIFUNDCHANNEL_STARTED
		    || dest->state == MULTIFUNDCHANNEL_START_FAILED);

		if (dest->state != MULTIFUNDCHANNEL_START_FAILED)
			continue;

		/* One of them failed, oh no.  */
		return redo_multifundchannel(mfc, "fundchannel_start");
	}

	/* Next step.  */
	return perform_funding_tx_finalize(mfc);
}

/*---------------------------------------------------------------------------*/

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
perform_fundchannel_complete(struct multifundchannel_command *mfc);

static struct command_result *
perform_funding_tx_finalize(struct multifundchannel_command *mfc)
{
	struct multifundchannel_destination **deck;
	char *content = tal_strdup(tmpctx, "");

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": Creating funding tx.",
		   mfc->id);

	/* Construct a deck of destinations.  */
	deck = tal_arr(tmpctx, struct multifundchannel_destination *,
		       tal_count(mfc->destinations) + mfc->change_needed);
	for (size_t i = 0; i < tal_count(mfc->destinations); ++i)
		deck[i] = &mfc->destinations[i];
	/* Add a NULL into the deck as a proxy for change output, if
	 * needed.  */
	if (mfc->change_needed)
		deck[tal_count(mfc->destinations)] = NULL;
	/* Fisher-Yates shuffle.  */
	for (size_t i = tal_count(deck); i > 1; --i) {
		size_t j = pseudorand(i);
		if (j == i - 1)
			continue;
		struct multifundchannel_destination *tmp;
		tmp = deck[j];
		deck[j] = deck[i - 1];
		deck[i - 1] = tmp;
	}

	/* Now that we have the outputs shuffled, add outputs to the PSBT.  */
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

static void
fundchannel_complete_dest(struct multifundchannel_destination *dest);

static struct command_result *
perform_fundchannel_complete(struct multifundchannel_command *mfc)
{
	unsigned int i;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": parallel fundchannel_complete.",
		   mfc->id);

	mfc->pending = tal_count(mfc->destinations);

	for (i = 0; i < tal_count(mfc->destinations); ++i)
		fundchannel_complete_dest(&mfc->destinations[i]);

	assert(mfc->pending != 0);
	return command_still_pending(mfc->cmd);
}

static struct command_result *
fundchannel_complete_ok(struct command *cmd,
			const char *buf,
			const jsmntok_t *result,
			struct multifundchannel_destination *dest);
static struct command_result *
fundchannel_complete_err(struct command *cmd,
			 const char *buf,
			 const jsmntok_t *error,
			 struct multifundchannel_destination *dest);

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
	json_add_string(req->js, "txid",
			type_to_string(tmpctx, struct bitcoin_txid,
				       mfc->txid));
	json_add_num(req->js, "txout", dest->outnum);

	send_outreq(cmd->plugin, req);
}

static struct command_result *
fundchannel_complete_done(struct multifundchannel_destination *dest);

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
	dest->channel_id = json_strdup(mfc, buf, channel_id_tok);

	return fundchannel_complete_done(dest);
}
static struct command_result *
fundchannel_complete_err(struct command *cmd,
			 const char *buf,
			 const jsmntok_t *error,
			 struct multifundchannel_destination *dest)
{
	struct multifundchannel_command *mfc = dest->mfc;
	const jsmntok_t *code_tok;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64", dest %u: "
		   "failed! fundchannel_complete %s: %.*s",
		   mfc->id, dest->index,
		   node_id_to_hexstr(tmpctx, &dest->id),
		   json_tok_full_len(error), json_tok_full(buf, error));

	code_tok = json_get_member(buf, error, "code");
	if (!code_tok)
		plugin_err(cmd->plugin,
			   "`fundchannel_complete` failure "
			   "did not have `code`? "
			   "%.*s",
			   json_tok_full_len(error),
			   json_tok_full(buf, error));
	if (!json_to_errcode(buf, code_tok, &dest->code))
		plugin_err(cmd->plugin,
			   "`fundchannel_complete` has unparseable `code`? "
			   "%.*s",
			   json_tok_full_len(error),
			   json_tok_full(buf, error));

	dest->state = MULTIFUNDCHANNEL_COMPLETE_FAILED;
	dest->error = json_strdup(mfc, buf, error);

	return fundchannel_complete_done(dest);
}

static struct command_result *
after_fundchannel_complete(struct multifundchannel_command *mfc);

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
perform_sendpsbt(struct multifundchannel_command *mfc);

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

		assert(dest->state == MULTIFUNDCHANNEL_STARTED
		    || dest->state == MULTIFUNDCHANNEL_COMPLETE_FAILED);

		if (dest->state != MULTIFUNDCHANNEL_COMPLETE_FAILED)
			continue;

		/* One of them failed, oh no.  */
		return redo_multifundchannel(mfc, "fundchannel_complete");
	}

	return perform_sendpsbt(mfc);
}

/*---------------------------------------------------------------------------*/
/*~
Finally with everything set up correctly we `signpsbt`+`sendpsbt` the
funding transaction.
*/

static struct command_result *
after_signpsbt(struct command *cmd,
	       const char *buf,
	       const jsmntok_t *result,
	       struct multifundchannel_command *mfc);

static struct command_result *
perform_sendpsbt(struct multifundchannel_command *mfc)
{
	struct out_req *req;

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": signpsbt.", mfc->id);

	req = jsonrpc_request_start(mfc->cmd->plugin, mfc->cmd,
				    "signpsbt",
				    &after_signpsbt,
				    &mfc_forward_error,
				    mfc);
	json_add_psbt(req->js, "psbt", mfc->psbt);
	return send_outreq(mfc->cmd->plugin, req);
}

static struct command_result *
after_sendpsbt(struct command *cmd,
	       const char *buf,
	       const jsmntok_t *result,
	       struct multifundchannel_command *mfc);

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
		dest = &mfc->destinations[i];
		dest->state = MULTIFUNDCHANNEL_DONE;
	}

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": sendpsbt.", mfc->id);

	req = jsonrpc_request_start(mfc->cmd->plugin, mfc->cmd,
				    "sendpsbt",
				    &after_sendpsbt,
				    &mfc_forward_error,
				    mfc);
	json_add_psbt(req->js, "psbt", mfc->psbt);
	return send_outreq(mfc->cmd->plugin, req);
}

static struct command_result *
multifundchannel_finished(struct multifundchannel_command *mfc);

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

/*---------------------------------------------------------------------------*/
/*~
And finally we are done.
*/

static struct command_result *
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
		json_add_string(out, "channel_id", mfc->destinations[i].channel_id);
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
		json_add_jsonstr(out, "error", mfc->removeds[i].error);
		json_object_end(out);
	}
	json_array_end(out);

	return mfc_finished(mfc, out);
}

/*~ We do cleanup, then we remove failed destinations and if we still have
 * the minimum number, re-run.
*/
struct multifundchannel_redo {
	struct multifundchannel_command *mfc;
	const char *failing_method;
};

static struct command_result *
post_cleanup_redo_multifundchannel(struct multifundchannel_redo *redo);

static struct command_result *
redo_multifundchannel(struct multifundchannel_command *mfc,
		      const char *failing_method)
{
	struct multifundchannel_redo *redo;

	assert(mfc->pending == 0);

	plugin_log(mfc->cmd->plugin, LOG_DBG,
		   "mfc %"PRIu64": trying redo despite '%s' failure; "
		   "will cleanup for now.",
		   mfc->id, failing_method);

	redo = tal(mfc, struct multifundchannel_redo);
	redo->mfc = mfc;
	redo->failing_method = failing_method;

	return mfc_cleanup(mfc, &post_cleanup_redo_multifundchannel, redo);
}

/* Return true if this destination failed, false otherwise.  */
static bool dest_failed(struct multifundchannel_destination *dest)
{
	switch (dest->state) {
	case MULTIFUNDCHANNEL_START_NOT_YET:
	case MULTIFUNDCHANNEL_STARTED:
	case MULTIFUNDCHANNEL_DONE:
		return false;

	case MULTIFUNDCHANNEL_CONNECT_FAILED:
	case MULTIFUNDCHANNEL_START_FAILED:
	case MULTIFUNDCHANNEL_COMPLETE_FAILED:
		return true;
	}
	abort();
}

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

		if (dest_failed(dest)) {
			struct multifundchannel_removed removed;

			plugin_log(mfc->cmd->plugin, LOG_DBG,
				   "mfc %"PRIu64", dest %u: "
				   "failed.",
				   mfc->id, dest->index);

			removed.id = dest->id;
			removed.method = failing_method;
			removed.error = dest->error;
			removed.code = dest->code;
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
					       mfc->removeds[i].code,
					       tal_fmt(tmpctx,
						       "'%s' failed",
						       failing_method));
		json_add_node_id(out, "id", &mfc->removeds[i].id);
		json_add_string(out, "method", failing_method);
		json_add_jsonstr(out, "error", mfc->removeds[i].error);

		/* Close 'data'.  */
		json_object_end(out);

		return mfc_finished(mfc, out);
	}

	/* Okay, we still have destinations to try --- reinvoke.  */
	return perform_multifundchannel(mfc);
}

static struct command_result *param_positive_number(struct command *cmd,
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

/* Entry function.  */
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

