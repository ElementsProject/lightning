#include "config.h"
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <inttypes.h>
#include <lightningd/forwards.h>
#include <lightningd/htlc_end.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <wallet/wallet.h>

static u64 forward_index_inc(struct lightningd *ld,
			     enum forward_status status,
			     struct short_channel_id in_channel,
			     const struct amount_msat *in_amount,
			     const struct short_channel_id *out_channel,
			     enum wait_index idx)
{
	return wait_index_increment(ld, WAIT_SUBSYSTEM_FORWARD, idx,
				    "status", forward_status_name(status),
				    "in_channel", short_channel_id_to_str(tmpctx, &in_channel),
				    "=in_msat", in_amount ? tal_fmt(tmpctx, "%"PRIu64, in_amount->millisatoshis) : NULL, /* Raw: JSON output */
				    "out_channel", out_channel ? short_channel_id_to_str(tmpctx, out_channel): NULL,
				    NULL);
}

void forward_index_deleted(struct lightningd *ld,
			   enum forward_status status,
			   struct short_channel_id in_channel,
			   const struct amount_msat *in_amount,
			   const struct short_channel_id *out_channel)
{
	forward_index_inc(ld, status, in_channel, in_amount, out_channel,
			  WAIT_INDEX_DELETED);
}

/* Fortuntely, dbids start at 1, not 0! */
u64 forward_index_created(struct lightningd *ld,
			  enum forward_status status,
			  struct short_channel_id in_channel,
			  struct amount_msat in_amount,
			  const struct short_channel_id *out_channel)
{
	return forward_index_inc(ld, status, in_channel, &in_amount, out_channel,
				 WAIT_INDEX_CREATED);
}

u64 forward_index_update_status(struct lightningd *ld,
				enum forward_status status,
				struct short_channel_id in_channel,
				struct amount_msat in_amount,
				const struct short_channel_id *out_channel)
{
	return forward_index_inc(ld, status, in_channel, &in_amount, out_channel,
				 WAIT_INDEX_UPDATED);
}

bool string_to_forward_status(const char *status_str,
			      size_t len,
			      enum forward_status *status)
{
	if (memeqstr(status_str, len, "offered")) {
		*status = FORWARD_OFFERED;
		return true;
	} else if (memeqstr(status_str, len, "settled")) {
		*status = FORWARD_SETTLED;
		return true;
	} else if (memeqstr(status_str, len, "failed")) {
		*status = FORWARD_FAILED;
		return true;
	} else if (memeqstr(status_str, len, "local_failed")) {
		*status = FORWARD_LOCAL_FAILED;
		return true;
	}
	return false;
}

/* Warp this process to ensure the consistent json object structure
 * between 'listforwards' API and 'forward_event' notification. */
void json_add_forwarding_object(struct json_stream *response,
				const char *fieldname,
				const struct forwarding *cur,
				const struct sha256 *payment_hash)
{
	json_object_start(response, fieldname);

	/* Only for forward_event */
	if (payment_hash)
		json_add_sha256(response, "payment_hash", payment_hash);
	json_add_short_channel_id(response, "in_channel", &cur->channel_in);

#ifdef COMPAT_V0121
	if (cur->htlc_id_in != HTLC_INVALID_ID)
#endif
		json_add_u64(response, "in_htlc_id", cur->htlc_id_in);

	/* This can be unknown if we failed before channel lookup */
	if (cur->channel_out.u64 != 0) {
		json_add_short_channel_id(response, "out_channel",
					  &cur->channel_out);
		if (cur->htlc_id_out)
			json_add_u64(response, "out_htlc_id", *cur->htlc_id_out);
	}
	json_add_amount_msat(response, "in_msat", cur->msat_in);

	/* These can be unset (aka zero) if we failed before channel lookup */
	if (!amount_msat_eq(cur->msat_out, AMOUNT_MSAT(0))) {
		json_add_amount_msat(response, "out_msat", cur->msat_out);
		json_add_amount_msat(response, "fee_msat", cur->fee);
	}
	json_add_string(response, "status", forward_status_name(cur->status));

	if (cur->failcode != 0) {
		json_add_num(response, "failcode", cur->failcode);
		json_add_string(response, "failreason",
				onion_wire_name(cur->failcode));
	}

	/* Old forwards don't have this field */
	if (cur->forward_style != FORWARD_STYLE_UNKNOWN)
		json_add_string(response, "style",
				forward_style_name(cur->forward_style));

#ifdef COMPAT_V070
		/* If a forwarding doesn't have received_time it was created
		 * before we added the tracking, do not include it here. */
	if (cur->received_time.ts.tv_sec) {
		json_add_timeabs(response, "received_time", cur->received_time);
		if (cur->resolved_time)
			json_add_timeabs(response, "resolved_time", *cur->resolved_time);
	}
#else
	json_add_timeabs(response, "received_time", cur->received_time);
	if (cur->resolved_time)
		json_add_timeabs(response, "resolved_time", *cur->resolved_time);
#endif
	json_object_end(response);
}

static void listforwardings_add_forwardings(struct json_stream *response,
					    struct wallet *wallet,
					    enum forward_status status,
					    const struct short_channel_id *chan_in,
					    const struct short_channel_id *chan_out)
{
	const struct forwarding *forwardings;

	forwardings = wallet_forwarded_payments_get(wallet, tmpctx, status, chan_in, chan_out);

	json_array_start(response, "forwards");
	for (size_t i=0; i<tal_count(forwardings); i++) {
		const struct forwarding *cur = &forwardings[i];
		json_add_forwarding_object(response, NULL, cur, NULL);
	}
	json_array_end(response);

	tal_free(forwardings);
}

static struct command_result *param_forward_status(struct command *cmd,
						   const char *name,
						   const char *buffer,
						   const jsmntok_t *tok,
						   enum forward_status **status)
{
	*status = tal(cmd, enum forward_status);
	if (string_to_forward_status(buffer + tok->start,
				     tok->end - tok->start,
				     *status))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "Unrecognized status");
}

static struct command_result *json_listforwards(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{

	struct json_stream *response;
	struct short_channel_id *chan_in, *chan_out;
	enum forward_status *status;

	if (!param(cmd, buffer, params,
		   p_opt_def("status", param_forward_status, &status,
			     FORWARD_ANY),
		   p_opt("in_channel", param_short_channel_id, &chan_in),
		   p_opt("out_channel", param_short_channel_id, &chan_out),
		   NULL))
		return command_param_failed();

	response = json_stream_success(cmd);
	listforwardings_add_forwardings(response, cmd->ld->wallet, *status, chan_in, chan_out);

	return command_success(cmd, response);
}

static const struct json_command listforwards_command = {
	"listforwards",
	"channels",
	json_listforwards,
	"List all forwarded payments and their information optionally filtering by [status], [in_channel] and [out_channel]"
};
AUTODATA(json_command, &listforwards_command);

static struct command_result *param_forward_delstatus(struct command *cmd,
						      const char *name,
						      const char *buffer,
						      const jsmntok_t *tok,
						      enum forward_status **status)
{
	struct command_result *ret;

	ret = param_forward_status(cmd, name, buffer, tok, status);
	if (ret)
		return ret;

	switch (**status) {
	case FORWARD_OFFERED:
		return command_fail_badparam(cmd, name, buffer, tok,
					     "delforward status cannot be offered");
	case FORWARD_ANY:
		return command_fail_badparam(cmd, name, buffer, tok,
					     "delforward status cannot be any");
	case FORWARD_SETTLED:
	case FORWARD_FAILED:
	case FORWARD_LOCAL_FAILED:
		return NULL;
	}
	abort();
}

static struct command_result *json_delforward(struct command *cmd,
					      const char *buffer,
					      const jsmntok_t *obj UNNEEDED,
					      const jsmntok_t *params)
{
	struct short_channel_id *chan_in;
	u64 *htlc_id;
	enum forward_status *status;

	if (!param(cmd, buffer, params,
		   p_req("in_channel", param_short_channel_id, &chan_in),
		   p_req("in_htlc_id", param_u64, &htlc_id),
		   p_req("status", param_forward_delstatus, &status),
		   NULL))
		return command_param_failed();

#ifdef COMPAT_V0121
	/* Special value used if in_htlc_id is missing */
	if (*htlc_id == HTLC_INVALID_ID)
		htlc_id = NULL;
#endif

	if (!wallet_forward_delete(cmd->ld->wallet,
				   chan_in, htlc_id, *status))
		return command_fail(cmd, DELFORWARD_NOT_FOUND,
				    "Could not find that forward");

	return command_success(cmd, json_stream_success(cmd));
}

static const struct json_command delforward_command = {
	"delforward",
	"channels",
	json_delforward,
	"Delete a forwarded payment by [in_channel], [in_htlc_id] and [status]"
};
AUTODATA(json_command, &delforward_command);
