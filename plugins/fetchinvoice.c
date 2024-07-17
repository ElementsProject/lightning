#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/json_out/json_out.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/blindedpath.h>
#include <common/bolt12_merkle.h>
#include <common/dijkstra.h>
#include <common/gossmap.h>
#include <common/gossmods_listpeerchannels.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/onion_message.h>
#include <common/overflows.h>
#include <common/route.h>
#include <errno.h>
#include <plugins/establish_onion_path.h>
#include <plugins/fetchinvoice.h>
#include <plugins/libplugin.h>
#include <plugins/offers.h>
#include <secp256k1_schnorrsig.h>
#include <sodium.h>

static LIST_HEAD(sent_list);

struct sent {
	/* We're in sent_invreqs, awaiting reply. */
	struct list_node list;
	/* The secret used by reply */
	struct secret *reply_secret;
	/* The command which sent us. */
	struct command *cmd;
	/* The offer we are trying to get an invoice/payment for. */
	struct tlv_offer *offer;

	/* Blinded paths they told us to use (if any) */
	struct blinded_path **their_paths;
	/* Direct destination (used iff no their_paths) */
	struct pubkey *direct_dest;

	/* When creating blinded return path, use scid not pubkey for intro node. */
	struct short_channel_id_dir *dev_path_use_scidd;

	/* Force reply path, for testing. */
	struct pubkey *dev_reply_path;

	/* The invreq we sent, OR the invoice we sent */
	struct tlv_invoice_request *invreq;

	struct tlv_invoice *inv;
	struct preimage inv_preimage;
	struct json_escape *inv_label;
	/* How long to wait for response before giving up. */
	u32 wait_timeout;
};

static struct sent *find_sent_by_secret(const struct secret *pathsecret)
{
	struct sent *i;

	list_for_each(&sent_list, i, list) {
		if (i->reply_secret && secret_eq_consttime(i->reply_secret, pathsecret))
			return i;
	}
	return NULL;
}

/* Hack to suppress warnings when we finish a different command */
static void discard_result(struct command_result *ret)
{
}

/* Returns NULL if it wasn't an error. */
static struct command_result *handle_error(struct command *cmd,
					   struct sent *sent,
					   const char *buf,
					   const jsmntok_t *om)
{
	const u8 *data;
	size_t dlen;
	struct tlv_invoice_error *err;
	struct json_out *details;
	const jsmntok_t *errtok;

	errtok = json_get_member(buf, om, "invoice_error");
	if (!errtok)
		return NULL;

	data = json_tok_bin_from_hex(cmd, buf, errtok);
	dlen = tal_bytelen(data);
	details = json_out_new(cmd);

	plugin_log(cmd->plugin, LOG_DBG, "errtok = %.*s",
		   json_tok_full_len(errtok),
		   json_tok_full(buf, errtok));
	json_out_start(details, NULL, '{');
	err = fromwire_tlv_invoice_error(cmd, &data, &dlen);
	if (!err) {
		plugin_log(cmd->plugin, LOG_DBG,
			   "Invalid invoice_error %.*s",
			   json_tok_full_len(errtok),
			   json_tok_full(buf, errtok));
		json_out_addstr(details, "invoice_error_hex",
				tal_strndup(tmpctx,
					    buf + errtok->start,
					    errtok->end - errtok->start));
	} else {
		char *failstr;

		/* FIXME: with a bit more generate-wire.py support,
		 * we could have fieldnames and even types. */
		if (err->erroneous_field)
			json_out_add(details, "erroneous_field", false,
				     "%"PRIu64, *err->erroneous_field);
		if (err->suggested_value)
			json_out_addstr(details, "suggested_value",
					tal_hex(tmpctx,
						err->suggested_value));
		/* If they don't include this, it'll be empty */
		failstr = tal_strndup(tmpctx,
				      err->error,
				      tal_bytelen(err->error));
		json_out_addstr(details, "error", failstr);
	}
	json_out_end(details, '}');
	discard_result(command_done_err(sent->cmd,
					OFFER_BAD_INVREQ_REPLY,
					"Remote node sent failure message",
						details));
	return command_hook_success(cmd);
}

/* BOLT-offers #12:
 * - if the invoice is a response to an `invoice_request`:
 *   - MUST reject the invoice if all fields less than type 160 do not
 *     exactly match the `invoice_request`.
 */
static bool invoice_matches_request(struct command *cmd,
				    const u8 *invbin,
				    const struct tlv_invoice_request *invreq)
{
	size_t len1, len2;
	u8 *wire;

	/* We linearize then strip signature.  This is dumb! */
	wire = tal_arr(tmpctx, u8, 0);
	towire_tlv_invoice_request(&wire, invreq);
	len1 = tlv_span(wire, 0, 159, NULL);

	len2 = tlv_span(invbin, 0, 159, NULL);
	return memeq(wire, len1, invbin, len2);
}

static struct command_result *handle_invreq_response(struct command *cmd,
						     struct sent *sent,
						     const char *buf,
						     const jsmntok_t *om)
{
	const u8 *invbin, *cursor;
	const jsmntok_t *invtok;
	size_t len;
	struct tlv_invoice *inv;
	struct sha256 merkle, sighash;
	struct json_stream *out;
	const char *badfield;
	u64 *expected_amount;

	invtok = json_get_member(buf, om, "invoice");
	if (!invtok) {
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "Neither invoice nor invoice_request_failed in reply %.*s",
			   json_tok_full_len(om),
			   json_tok_full(buf, om));
		discard_result(command_fail(sent->cmd,
					    OFFER_BAD_INVREQ_REPLY,
					    "Neither invoice nor invoice_request_failed in reply %.*s",
					    json_tok_full_len(om),
					    json_tok_full(buf, om)));
		return command_hook_success(cmd);
	}

	invbin = json_tok_bin_from_hex(cmd, buf, invtok);
	cursor = invbin;
	len = tal_bytelen(invbin);
 	inv = fromwire_tlv_invoice(cmd, &cursor, &len);
	if (!inv) {
		badfield = "invoice";
		goto badinv;
	}

	/* Raw send?  Just fwd reply. */
	if (plugin_developer_mode(cmd->plugin) && !sent->offer) {
		out = jsonrpc_stream_success(sent->cmd);
		json_add_string(out, "invoice", invoice_encode(tmpctx, inv));
		discard_result(command_finished(sent->cmd, out));
		return command_hook_success(cmd);
	}

	/* BOLT-offers #12:
	 * - if the invoice is a response to an `invoice_request`:
	 *   - MUST reject the invoice if all fields less than type 160 do not
	 *     exactly match the `invoice_request`.
	 */
	if (!invoice_matches_request(cmd, invbin, sent->invreq)) {
		badfield = "invoice_request match";
		goto badinv;
	}

	/* BOLT-offers #12:
	 *     - if `offer_node_id` is present (invoice_request for an offer):
	 * 	  - MUST reject the invoice if `invoice_node_id` is not equal to `offer_node_id`.
	 */
	if (!inv->invoice_node_id || !pubkey_eq(inv->offer_node_id, inv->invoice_node_id)) {
		badfield = "invoice_node_id";
		goto badinv;
	}

	/* BOLT-offers #12:
	 *   - MUST reject the invoice if `signature` is not a valid signature
	 *      using `invoice_node_id` as described in [Signature Calculation]
	 */
	merkle_tlv(inv->fields, &merkle);
	sighash_from_merkle("invoice", "signature", &merkle, &sighash);

	if (!inv->signature
	    || !check_schnorr_sig(&sighash, &inv->invoice_node_id->pubkey, inv->signature)) {
		badfield = "signature";
		goto badinv;
	}

	/* BOLT-offers #12:
	 * A reader of an invoice:
	 *   - MUST reject the invoice if `invoice_amount` is not present.
	 */
	if (!inv->invoice_amount) {
		badfield = "invoice_amount";
		goto badinv;
	}

	/* Get the amount we expected: firstly, if that's what we sent,
	 * secondly, if specified in the invoice. */
	if (inv->invreq_amount) {
		expected_amount = tal_dup(tmpctx, u64, inv->invreq_amount);
	} else if (inv->offer_amount && !inv->offer_currency) {
		expected_amount = tal(tmpctx, u64);

		*expected_amount = *inv->offer_amount;
		if (inv->invreq_quantity) {
			/* We should never have sent this! */
			if (mul_overflows_u64(*expected_amount,
					      *inv->invreq_quantity)) {
				badfield = "quantity overflow";
				goto badinv;
			}
			*expected_amount *= *inv->invreq_quantity;
		}
	} else
		expected_amount = NULL;

	/* BOLT-offers-recurrence #12:
	 * - if the offer contained `recurrence`:
	 *   - MUST reject the invoice if `recurrence_basetime` is not set.
	 */
	if (inv->invreq_recurrence_counter && !inv->invoice_recurrence_basetime) {
		badfield = "recurrence_basetime";
		goto badinv;
	}

	out = jsonrpc_stream_success(sent->cmd);
	json_add_string(out, "invoice", invoice_encode(tmpctx, inv));
	json_object_start(out, "changes");
	/* BOLT-offers #12:
	 *   - SHOULD confirm authorization if `invoice_amount`.`msat` is not within
	 *     the amount range authorized.
	 */
	/* We always tell them this unless it's trivial to calc and
	 * exactly as expected. */
	if (!expected_amount || *inv->invoice_amount != *expected_amount) {
		json_add_amount_msat(out, "amount_msat",
				     amount_msat(*inv->invoice_amount));
	}
	json_object_end(out);

	/* We tell them about next period at this point, if any. */
	if (inv->offer_recurrence) {
		u64 next_counter, next_period_idx;
		u64 paywindow_start, paywindow_end;

		next_counter = *inv->invreq_recurrence_counter + 1;
		if (inv->invreq_recurrence_start)
			next_period_idx = *inv->invreq_recurrence_start
				+ next_counter;
		else
			next_period_idx = next_counter;

		/* If this was the last, don't tell them about a next! */
		if (!inv->offer_recurrence_limit
		    || next_period_idx <= *inv->offer_recurrence_limit) {
			json_object_start(out, "next_period");
			json_add_u64(out, "counter", next_counter);
			json_add_u64(out, "starttime",
				     offer_period_start(*inv->invoice_recurrence_basetime,
							next_period_idx,
							inv->offer_recurrence));
			json_add_u64(out, "endtime",
				     offer_period_start(*inv->invoice_recurrence_basetime,
							next_period_idx + 1,
							inv->offer_recurrence) - 1);

			offer_period_paywindow(inv->offer_recurrence,
					       inv->offer_recurrence_paywindow,
					       inv->offer_recurrence_base,
					       *inv->invoice_recurrence_basetime,
					       next_period_idx,
					       &paywindow_start, &paywindow_end);
			json_add_u64(out, "paywindow_start", paywindow_start);
			json_add_u64(out, "paywindow_end", paywindow_end);
			json_object_end(out);
		}
	}

	discard_result(command_finished(sent->cmd, out));
	return command_hook_success(cmd);

badinv:
	plugin_log(cmd->plugin, LOG_DBG, "Failed invoice due to %s", badfield);
	discard_result(command_fail(sent->cmd,
				    OFFER_BAD_INVREQ_REPLY,
				    "Incorrect %s field in %.*s",
				    badfield,
				    json_tok_full_len(invtok),
				    json_tok_full(buf, invtok)));
	return command_hook_success(cmd);
}

struct command_result *handle_invoice_onion_message(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *om,
						    const struct secret *pathsecret)
{
	struct sent *sent;
	struct command_result *err;

	sent = find_sent_by_secret(pathsecret);
	if (!sent)
		return NULL;

	plugin_log(cmd->plugin, LOG_DBG, "Received onion message reply for invoice_request: %.*s",
		   json_tok_full_len(om),
		   json_tok_full(buf, om));

	err = handle_error(cmd, sent, buf, om);
	if (err)
		return err;

	if (sent->invreq)
		return handle_invreq_response(cmd, sent, buf, om);

	return NULL;
}

static void destroy_sent(struct sent *sent)
{
	list_del(&sent->list);
}

/* We've received neither a reply nor a payment; return failure. */
static void timeout_sent_invreq(struct sent *sent)
{
	/* This will free sent! */
	discard_result(command_fail(sent->cmd, OFFER_TIMEOUT,
				    "Timeout waiting for response"));
}

static struct command_result *sendonionmsg_done(struct command *cmd,
						const char *buf UNUSED,
						const jsmntok_t *result UNUSED,
						struct sent *sent)
{
	tal_steal(cmd, plugin_timer(cmd->plugin,
				    time_from_sec(sent->wait_timeout),
				    timeout_sent_invreq, sent));
	sent->cmd = cmd;
	list_add_tail(&sent_list, &sent->list);
	tal_add_destructor(sent, destroy_sent);
	return command_still_pending(cmd);
}

static struct command_result *param_offer(struct command *cmd,
					  const char *name,
					  const char *buffer,
					  const jsmntok_t *tok,
					  struct tlv_offer **offer)
{
	char *fail;

	*offer = offer_decode(cmd, buffer + tok->start, tok->end - tok->start,
			      plugin_feature_set(cmd->plugin), chainparams,
			      &fail);
	if (!*offer)
		return command_fail_badparam(cmd, name, buffer, tok,
					     tal_fmt(cmd,
						     "Unparsable offer: %s",
						     fail));
	return NULL;
}

static struct blinded_path *make_reply_path(const tal_t *ctx,
					    const struct sent *sent,
					    const struct pubkey *path,
					    struct secret *reply_secret)
{
	struct pubkey *ids;

	assert(tal_count(path) > 0);

	randombytes_buf(reply_secret, sizeof(struct secret));

	if (sent->dev_reply_path) {
		ids = sent->dev_reply_path;
	} else {
		size_t nhops = tal_count(path);
		/* FIXME: Could create an independent reply path, not just
		 * reverse existing. */
		ids = tal_arr(tmpctx, struct pubkey, nhops - 1);
		for (int i = nhops - 2; i >= 0; i--)
			ids[nhops - 2 - i] = path[i];
	}


	/* Reply path */
	return incoming_message_blinded_path(ctx, ids, NULL, reply_secret);
}

/* Container while we're establishing paths */
struct establishing_paths {
	/* Index into sent->their_paths, if that's not NULL */
	int which_blinded_path;
	struct sent *sent;
	struct tlv_onionmsg_tlv *final_tlv;
	struct command_result *(*done)(struct command *cmd,
				       const char *buf UNUSED,
				       const jsmntok_t *result UNUSED,
				       struct sent *sent);
};

static const struct blinded_path *current_their_path(const struct establishing_paths *epaths)
{
	if (tal_count(epaths->sent->their_paths) == 0)
		return NULL;
	assert(epaths->which_blinded_path < tal_count(epaths->sent->their_paths));
	return epaths->sent->their_paths[epaths->which_blinded_path];
}

static struct command_result *establish_path_done(struct command *cmd,
						  const struct pubkey *path,
						  struct establishing_paths *epaths)
{
	struct onion_message *omsg;
	struct sent *sent = epaths->sent;
	struct tlv_onionmsg_tlv *final_tlv = epaths->final_tlv;

	/* Create transient secret so we can validate reply! */
	sent->reply_secret = tal(sent, struct secret);

	/* FIXME: Maybe we should allow this? */
	if (tal_count(path) == 1)
		return command_fail(cmd, PAY_ROUTE_NOT_FOUND,
				    "Refusing to talk to ourselves");

	/* Add reply path to final_tlv (it already contains invoice_request/invoice) */
	final_tlv->reply_path = make_reply_path(final_tlv, sent, path, sent->reply_secret);

	/* Replace first hop with scidd if they said to */
	if (sent->dev_path_use_scidd)
		sciddir_or_pubkey_from_scidd(&final_tlv->reply_path->first_node_id,
					     sent->dev_path_use_scidd);

	omsg = outgoing_onion_message(tmpctx, path, NULL, current_their_path(epaths), final_tlv);
	return inject_onionmessage(cmd, omsg, epaths->done, forward_error, sent);
}

/* Mutual recursion */
static struct command_result *try_establish(struct command *cmd,
					    struct establishing_paths *epaths);

static struct command_result *establish_path_fail(struct command *cmd,
						  const char *why,
						  struct establishing_paths *epaths)
{
	const struct blinded_path *bpath = current_their_path(epaths);

	/* No blinded paths?  We fail to establish connection directly */
	if (!bpath) {
		return command_fail(cmd, OFFER_ROUTE_NOT_FOUND,
				    "Failed: could not route or connect directly to %s: %s",
				    fmt_pubkey(tmpctx, epaths->sent->direct_dest), why);
	}

	plugin_log(cmd->plugin, LOG_DBG, "establish path to %s failed: %s",
		   fmt_sciddir_or_pubkey(tmpctx, &bpath->first_node_id), why);
	if (epaths->which_blinded_path == tal_count(epaths->sent->their_paths) - 1) {
		return command_fail(cmd, OFFER_ROUTE_NOT_FOUND,
				    "Failed: could not route or connect directly to blinded path at %s: %s",
				    fmt_sciddir_or_pubkey(tmpctx, &bpath->first_node_id),
				    why);
	}

	/* Try the next one */
	epaths->which_blinded_path++;
	return try_establish(cmd, epaths);
}

static struct command_result *try_establish(struct command *cmd,
					    struct establishing_paths *epaths)
{
	struct pubkey target;
	const struct blinded_path *bpath = current_their_path(epaths);

	if (!bpath) {
		target = *epaths->sent->direct_dest;
	} else {
		struct sciddir_or_pubkey first = bpath->first_node_id;
		if (!first.is_pubkey && !convert_to_scidd(cmd, &first))
			return establish_path_fail(cmd, "Cannot resolve scidd", epaths);
		target = first.pubkey;
	}

	return establish_onion_path(cmd, get_gossmap(cmd->plugin), &id, &target,
				    disable_connect,
				    establish_path_done,
				    establish_path_fail,
				    epaths);
}

static struct command_result *send_message(struct command *cmd,
					   struct sent *sent,
					   struct tlv_onionmsg_tlv *final_tlv STEALS,
					   struct command_result *(*done)
					   (struct command *cmd,
					    const char *buf UNUSED,
					    const jsmntok_t *result UNUSED,
					    struct sent *sent))
{
	struct establishing_paths *epaths = tal(sent, struct establishing_paths);

	epaths->which_blinded_path = 0;
	epaths->sent = sent;
	epaths->final_tlv = tal_steal(epaths, final_tlv);
	epaths->done = done;

	return try_establish(cmd, epaths);
}

/* We've received neither a reply nor a payment; return failure. */
static void timeout_sent_inv(struct sent *sent)
{
	struct json_out *details = json_out_new(sent);

	json_out_start(details, NULL, '{');
	json_out_addstr(details, "invstring", invoice_encode(tmpctx, sent->inv));
	json_out_end(details, '}');

	/* This will free sent! */
	discard_result(command_done_err(sent->cmd, OFFER_TIMEOUT,
					"Failed: timeout waiting for response",
					details));
}

static struct command_result *prepare_inv_timeout(struct command *cmd,
						  const char *buf UNUSED,
						  const jsmntok_t *result UNUSED,
						  struct sent *sent)
{
	tal_steal(cmd, plugin_timer(cmd->plugin,
				    time_from_sec(sent->wait_timeout),
				    timeout_sent_inv, sent));
	return sendonionmsg_done(cmd, buf, result, sent);
}

static struct command_result *fetchinvoice_path_done(struct command *cmd,
						     const struct pubkey *path,
						     struct sent *sent)
{
	struct tlv_onionmsg_tlv *payload = tlv_onionmsg_tlv_new(sent);

	payload->invoice_request = tal_arr(payload, u8, 0);
	towire_tlv_invoice_request(&payload->invoice_request, sent->invreq);

	return send_message(cmd, sent, payload, sendonionmsg_done);
}

static struct command_result *fetchinvoice_path_fail(struct command *cmd,
						     const char *why,
						     struct sent *sent)
{
	return command_fail(cmd, OFFER_ROUTE_NOT_FOUND,
			    "Failed: could not route, could not connect: %s",
			    why);
}

static struct command_result *invreq_done(struct command *cmd,
					  const char *buf,
					  const jsmntok_t *result,
					  struct sent *sent)
{
	const jsmntok_t *t;
	char *fail;

	/* Get invoice request */
	t = json_get_member(buf, result, "bolt12");
	if (!t)
		return command_fail(cmd, LIGHTNINGD,
				    "Missing bolt12 %.*s",
				    json_tok_full_len(result),
				    json_tok_full(buf, result));

	plugin_log(cmd->plugin, LOG_DBG,
		   "invoice_request: %.*s",
		   json_tok_full_len(t),
		   json_tok_full(buf, t));

	sent->inv = NULL;
	sent->invreq = invrequest_decode(sent,
					 buf + t->start,
					 t->end - t->start,
					 plugin_feature_set(cmd->plugin),
					 chainparams,
					 &fail);
	if (!sent->invreq)
		return command_fail(cmd, LIGHTNINGD,
				    "Invalid invoice_request %.*s: %s",
				    json_tok_full_len(t),
				    json_tok_full(buf, t),
				    fail);

	/* Now that's given us the previous base, check this is an OK time
	 * to request an invoice. */
	if (sent->invreq->invreq_recurrence_counter) {
		u64 *base;
		const jsmntok_t *pbtok;
		u64 period_idx = *sent->invreq->invreq_recurrence_counter;

		if (sent->invreq->invreq_recurrence_start)
			period_idx += *sent->invreq->invreq_recurrence_start;

		/* BOLT-offers-recurrence #12:
		 * - if the offer contained `recurrence_limit`:
		 *   - MUST NOT send an `invoice_request` for a period greater
		 *     than `max_period`
		 */
		if (sent->invreq->offer_recurrence_limit
		    && period_idx > *sent->invreq->offer_recurrence_limit)
			return command_fail(cmd, LIGHTNINGD,
					    "Can't send invreq for period %"
					    PRIu64" (limit %u)",
					    period_idx,
					    *sent->invreq->offer_recurrence_limit);

		/* BOLT-offers-recurrence #12:
		 * - SHOULD NOT send an `invoice_request` for a period which has
		 *   already passed.
		 */
		/* If there's no recurrence_base, we need a previous payment
		 * for this: fortunately createinvoicerequest does that
		 * lookup. */
		pbtok = json_get_member(buf, result, "previous_basetime");
		if (pbtok) {
			base = tal(tmpctx, u64);
			json_to_u64(buf, pbtok, base);
		} else if (sent->invreq->offer_recurrence_base)
			base = &sent->invreq->offer_recurrence_base->basetime;
		else {
			/* happens with *recurrence_base == 0 */
			assert(*sent->invreq->invreq_recurrence_counter == 0);
			base = NULL;
		}

		if (base) {
			u64 period_start, period_end, now = time_now().ts.tv_sec;
			offer_period_paywindow(sent->invreq->offer_recurrence,
					       sent->invreq->offer_recurrence_paywindow,
					       sent->invreq->offer_recurrence_base,
					       *base, period_idx,
					       &period_start, &period_end);
			if (now < period_start)
				return command_fail(cmd, LIGHTNINGD,
						    "Too early: can't send until time %"
						    PRIu64" (in %"PRIu64" secs)",
						    period_start,
						    period_start - now);
			if (now > period_end)
				return command_fail(cmd, LIGHTNINGD,
						    "Too late: expired time %"
						    PRIu64" (%"PRIu64" secs ago)",
						    period_end,
						    now - period_end);
		}
	}

	return establish_onion_path(cmd, get_gossmap(cmd->plugin), &id,
				    sent->invreq->offer_node_id,
				    disable_connect,
				    fetchinvoice_path_done,
				    fetchinvoice_path_fail,
				    sent);
}

static struct command_result *param_dev_scidd(struct command *cmd, const char *name,
					      const char *buffer, const jsmntok_t *tok,
					      struct short_channel_id_dir **scidd)
{
	if (!plugin_developer_mode(cmd->plugin))
		return command_fail_badparam(cmd, name, buffer, tok,
					     "not available outside --developer mode");

	*scidd = tal(cmd, struct short_channel_id_dir);
	if (short_channel_id_dir_from_str(buffer + tok->start, tok->end - tok->start, *scidd))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be a short_channel_id of form NxNxN/dir");
}

static struct command_result *param_dev_reply_path(struct command *cmd, const char *name,
						   const char *buffer, const jsmntok_t *tok,
						   struct pubkey **path)
{
	size_t i;
	const jsmntok_t *t;

	if (!plugin_developer_mode(cmd->plugin))
		return command_fail_badparam(cmd, name, buffer, tok,
					     "not available outside --developer mode");

	if (tok->type != JSMN_ARRAY)
		return command_fail_badparam(cmd, name, buffer, tok, "Must be array");

	*path = tal_arr(cmd, struct pubkey, tok->size);

	json_for_each_arr(i, t, tok) {
		if (!json_to_pubkey(buffer, t, &(*path)[i]))
			return command_fail_badparam(cmd, name, buffer, t, "invalid pubkey");
	}
	return NULL;
}

/* Fetches an invoice for this offer, and makes sure it corresponds. */
struct command_result *json_fetchinvoice(struct command *cmd,
					 const char *buffer,
					 const jsmntok_t *params)
{
	struct amount_msat *msat;
	const char *rec_label, *payer_note;
	struct out_req *req;
	struct tlv_invoice_request *invreq;
	struct sent *sent = tal(cmd, struct sent);
	u32 *timeout;
	u64 *quantity;
	u32 *recurrence_counter, *recurrence_start;

	if (!param(cmd, buffer, params,
		   p_req("offer", param_offer, &sent->offer),
		   p_opt("amount_msat", param_msat, &msat),
		   p_opt("quantity", param_u64, &quantity),
		   p_opt("recurrence_counter", param_number, &recurrence_counter),
		   p_opt("recurrence_start", param_number, &recurrence_start),
		   p_opt("recurrence_label", param_string, &rec_label),
		   p_opt_def("timeout", param_number, &timeout, 60),
		   p_opt("payer_note", param_string, &payer_note),
		   p_opt("dev_path_use_scidd", param_dev_scidd, &sent->dev_path_use_scidd),
		   p_opt("dev_reply_path", param_dev_reply_path, &sent->dev_reply_path),
		   NULL))
		return command_param_failed();

	if (!offers_enabled)
		return command_fail(cmd, LIGHTNINGD,
				    "experimental-offers not enabled");

	sent->wait_timeout = *timeout;
	sent->their_paths = sent->offer->offer_paths;
	sent->direct_dest = sent->offer->offer_node_id;

	/* BOLT-offers #12:
	 * - SHOULD not respond to an offer if the current time is after
	 *   `offer_absolute_expiry`.
	 */
	if (sent->offer->offer_absolute_expiry
	    && time_now().ts.tv_sec > *sent->offer->offer_absolute_expiry)
		return command_fail(cmd, OFFER_EXPIRED, "Offer expired");

	/* BOLT-offers #12:
	 * The writer:
	 *  - if it is responding to an offer:
	 *    - MUST copy all fields from the offer (including unknown fields).
	 */
	invreq = invoice_request_for_offer(sent, sent->offer);
	invreq->invreq_recurrence_counter = tal_steal(invreq, recurrence_counter);
	invreq->invreq_recurrence_start = tal_steal(invreq, recurrence_start);
	invreq->invreq_quantity = tal_steal(invreq, quantity);

	/* BOLT-offers-recurrence #12:
	 * - if `offer_amount` is not present:
	 *       - MUST specify `invreq_amount`.
	 *     - otherwise:
	 *       - MAY omit `invreq_amount`.
	 *       - if it sets `invreq_amount`:
	 *         - MUST specify `invreq_amount`.`msat` as greater or equal to
	 *           amount expected by `offer_amount` (and, if present,
	 *          `offer_currency` and `invreq_quantity`).
	 */
	if (invreq->offer_amount) {
		/* FIXME: Check after quantity? */
		if (msat) {
			invreq->invreq_amount = tal_dup(invreq, u64,
							&msat->millisatoshis); /* Raw: tu64 */
		}
	} else {
		if (!msat)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "msatoshi parameter required");
		invreq->invreq_amount = tal_dup(invreq, u64,
						&msat->millisatoshis); /* Raw: tu64 */
	}

	/* BOLT-offers #12:
	 * - if `offer_quantity_max` is present:
	 *    - MUST set `invreq_quantity` to greater than zero.
	 *    - if `offer_quantity_max` is non-zero:
	 *      - MUST set `invreq_quantity` less than or equal to
	 *       `offer_quantity_max`.
	 */
	if (invreq->offer_quantity_max) {
		if (!invreq->invreq_quantity)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "quantity parameter required");
		if (*invreq->invreq_quantity == 0)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "quantity parameter must be non-zero");
		if (*invreq->offer_quantity_max
		    && *invreq->invreq_quantity > *invreq->offer_quantity_max)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "quantity must be <= %"PRIu64,
					    *invreq->offer_quantity_max);
	} else {
		if (invreq->invreq_quantity)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "quantity parameter unnecessary");
	}

	/* BOLT-offers-recurrence #12:
	 * - if the offer contained `recurrence`:
	 */
	if (invreq->offer_recurrence) {
		/* BOLT-offers-recurrence #12:
		 *    - for the initial request:
		 *...
		 *      - MUST set `recurrence_counter` `counter` to 0.
		 */
		/* BOLT-offers-recurrence #12:
		 *    - for any successive requests:
		 *...
		 *      - MUST set `recurrence_counter` `counter` to one greater
		 *        than the highest-paid invoice.
		 */
		if (!invreq->invreq_recurrence_counter)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "needs recurrence_counter");

		/* BOLT-offers-recurrence #12:
		 *    - if the offer contained `recurrence_base` with
		 *      `start_any_period` non-zero:
		 *      - MUST include `recurrence_start`
		 *...
		 *    - otherwise:
		 *      - MUST NOT include `recurrence_start`
		 */
		if (invreq->offer_recurrence_base
		    && invreq->offer_recurrence_base->start_any_period) {
			if (!invreq->invreq_recurrence_start)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "needs recurrence_start");
		} else {
			if (invreq->invreq_recurrence_start)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "unnecessary recurrence_start");
		}

		/* recurrence_label uniquely identifies this series of
		 * payments */
		if (!rec_label)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "needs recurrence_label");
	} else {
		/* BOLT-offers-recurrence #12:
		 * - otherwise:
		 *   - MUST NOT set `recurrence_counter`.
		 *   - MUST NOT set `recurrence_start`
		 */
		if (invreq->invreq_recurrence_counter)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "unnecessary recurrence_counter");
		if (invreq->invreq_recurrence_start)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "unnecessary recurrence_start");
	}

	/* BOLT-offers #12:
	 *
	 * - if `offer_chains` is set:
	 *   - MUST set `invreq_chain` to one of `offer_chains` unless that
	 *     chain is bitcoin, in which case it MAY omit `invreq_chain`.
	 * - otherwise:
	 *   - if it sets `invreq_chain` it MUST set it to bitcoin.
	 */
	/* We already checked that we're compatible chain, in param_offer */
	if (!streq(chainparams->network_name, "bitcoin")) {
		invreq->invreq_chain = tal_dup(invreq, struct bitcoin_blkid,
					       &chainparams->genesis_blockhash);
	}

	/* BOLT-offers #12:
	 *   - if it supports bolt12 invoice request features:
	 *     - MUST set `invreq_features`.`features` to the bitmap of features.
	 */
	invreq->invreq_features
		= plugin_feature_set(cmd->plugin)->bits[BOLT12_OFFER_FEATURE];

	/* invreq->invreq_payer_note is not a nul-terminated string! */
	if (payer_note)
		invreq->invreq_payer_note = tal_dup_arr(invreq, utf8,
							payer_note,
							strlen(payer_note),
							0);

	/* Make the invoice request (fills in payer_key and payer_info) */
	req = jsonrpc_request_start(cmd->plugin, cmd, "createinvoicerequest",
				    &invreq_done,
				    &forward_error,
				    sent);

	/* We don't want this is the database: that's only for ones we publish */
	json_add_string(req->js, "bolt12", invrequest_encode(tmpctx, invreq));
	json_add_bool(req->js, "savetodb", false);
	if (rec_label)
		json_add_string(req->js, "recurrence_label", rec_label);
	return send_outreq(cmd->plugin, req);
}

/* FIXME: Using a hook here is not ideal: technically it doesn't mean
 * it's actually hit the db!  But using waitinvoice is also suboptimal
 * because we don't have libplugin infra to cancel a pending req (and I
 * want to rewrite our wait* API anyway) */
struct command_result *invoice_payment(struct command *cmd,
				       const char *buf,
				       const jsmntok_t *params)
{
	struct sent *i;
	const jsmntok_t *ptok, *preimagetok, *msattok;
	struct preimage preimage;
	struct amount_msat msat;

	ptok = json_get_member(buf, params, "payment");
	preimagetok = json_get_member(buf, ptok, "preimage");
	msattok = json_get_member(buf, ptok, "msat");
	if (!preimagetok || !msattok)
		plugin_err(cmd->plugin,
			   "Invalid invoice_payment %.*s",
			   json_tok_full_len(params),
			   json_tok_full(buf, params));

	hex_decode(buf + preimagetok->start,
		   preimagetok->end - preimagetok->start,
		   &preimage, sizeof(preimage));
	json_to_msat(buf, msattok, &msat);

	list_for_each(&sent_list, i, list) {
		struct out_req *req;

		if (!i->inv)
			continue;
		if (!preimage_eq(&preimage, &i->inv_preimage))
			continue;

		/* It was paid!  Success.  Return as per waitinvoice. */
		req = jsonrpc_request_start(cmd->plugin, i->cmd, "waitinvoice",
					    &forward_result,
					    &forward_error,
					    i);
		json_add_escaped_string(req->js, "label", i->inv_label);
		discard_result(send_outreq(cmd->plugin, req));
		break;
	}
	return command_hook_success(cmd);
}

static struct command_result *sendinvoice_path_done(struct command *cmd,
						    const struct pubkey *path,
						    struct sent *sent)
{
	struct tlv_onionmsg_tlv *payload = tlv_onionmsg_tlv_new(sent);

	payload->invoice = tal_arr(payload, u8, 0);
	towire_tlv_invoice(&payload->invoice, sent->inv);

	return send_message(cmd, sent, payload, prepare_inv_timeout);
}

static struct command_result *sendinvoice_path_fail(struct command *cmd,
						    const char *why,
						    struct sent *sent)
{
	return command_fail(cmd, OFFER_ROUTE_NOT_FOUND,
			    "Failed: could not route, could not connect: %s",
			    why);
}

static struct command_result *createinvoice_done(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *result,
						 struct sent *sent)
{
	const jsmntok_t *invtok = json_get_member(buf, result, "bolt12");
	char *fail;

	/* Replace invoice with signed one */
	tal_free(sent->inv);
	sent->inv = invoice_decode(sent,
				   buf + invtok->start,
				   invtok->end - invtok->start,
				   plugin_feature_set(cmd->plugin),
				   chainparams,
				   &fail);
	if (!sent->inv) {
		plugin_log(cmd->plugin, LOG_BROKEN,
			   "Bad createinvoice %.*s: %s",
			   json_tok_full_len(invtok),
			   json_tok_full(buf, invtok),
			   fail);
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Bad createinvoice response %s", fail);
	}

	/* BOLT-offers #12:
	 *     - if it sends an invoice in response:
	 *       - MUST use `offer_paths` if present, otherwise MUST use
	 *         `invreq_payer_id` as the node id to send to.
	 */
	sent->their_paths = sent->invreq->offer_paths;
	sent->direct_dest = sent->invreq->invreq_payer_id;

	return establish_onion_path(cmd, get_gossmap(cmd->plugin), &id,
				    sent->invreq->invreq_payer_id,
				    disable_connect,
				    sendinvoice_path_done,
				    sendinvoice_path_fail,
				    sent);
}

static struct command_result *sign_invoice(struct command *cmd,
					   struct sent *sent)
{
	struct out_req *req;

	/* Get invoice signature and put in db so we can receive payment */
	req = jsonrpc_request_start(cmd->plugin, cmd, "createinvoice",
				    &createinvoice_done,
				    &forward_error,
				    sent);
	json_add_string(req->js, "invstring", invoice_encode(tmpctx, sent->inv));
	json_add_preimage(req->js, "preimage", &sent->inv_preimage);
	json_add_escaped_string(req->js, "label", sent->inv_label);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *param_invreq(struct command *cmd,
					   const char *name,
					   const char *buffer,
					   const jsmntok_t *tok,
					   struct tlv_invoice_request **invreq)
{
	char *fail;
	int badf;
	u8 *wire;
	struct sha256 merkle, sighash;

	/* BOLT-offers #12:
	 *   - if `invreq_chain` is not present:
	 *     - MUST fail the request if bitcoin is not a supported chain.
	 *   - otherwise:
	 *     - MUST fail the request if `invreq_chain`.`chain` is not a
	 *       supported chain.
	 */
	*invreq = invrequest_decode(cmd,
				    buffer + tok->start, tok->end - tok->start,
				    plugin_feature_set(cmd->plugin),
				    chainparams,
				    &fail);
	if (!*invreq)
		return command_fail_badparam(cmd, name, buffer, tok,
					     tal_fmt(cmd,
						     "Unparsable invoice_request: %s",
						     fail));
	/* BOLT-offers #12:
	 * The reader:
	 *   - MUST fail the request if `invreq_payer_id` or `invreq_metadata`
	 *     are not present.
	 *   - MUST fail the request if any non-signature TLV fields greater or
	 *     equal to 160.
	 *   - if `invreq_features` contains unknown _odd_ bits that are
	 *     non-zero:
	 *     - MUST ignore the bit.
	 *   - if `invreq_features` contains unknown _even_ bits that are
	 *     non-zero:
	 *     - MUST fail the request.
	 */
	if (!(*invreq)->invreq_payer_id)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Missing invreq_payer_id");

	if (!(*invreq)->invreq_metadata)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Missing invreq_metadata");

	wire = tal_arr(tmpctx, u8, 0);
	towire_tlv_invoice_request(&wire, *invreq);
	if (tlv_span(wire, 160, 239, NULL) != 0
	    || tlv_span(wire, 1001, UINT64_MAX, NULL) != 0) {
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Invalid high-numbered fields");
	}

	badf = features_unsupported(plugin_feature_set(cmd->plugin),
				    (*invreq)->invreq_features,
				    BOLT12_INVREQ_FEATURE);
	if (badf != -1) {
		return command_fail_badparam(cmd, name, buffer, tok,
					     tal_fmt(tmpctx,
						     "unknown feature %i",
						     badf));
	}

	/* BOLT-offers #12:
	 * - MUST fail the request if `signature` is not correct as detailed in [Signature
	 *   Calculation](#signature-calculation) using the `invreq_payer_id`.
	 */
	merkle_tlv((*invreq)->fields, &merkle);
	sighash_from_merkle("invoice_request", "signature", &merkle, &sighash);

	if (!(*invreq)->signature)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Missing signature");
	if (!check_schnorr_sig(&sighash,
			       &(*invreq)->invreq_payer_id->pubkey,
			       (*invreq)->signature))
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Invalid signature");

	/* Plugin handles these automatically, you shouldn't send one
	 * manually. */
	if ((*invreq)->offer_node_id) {
		return command_fail_badparam(cmd, name, buffer, tok,
					     "This is based on an offer?");
	}

	/* BOLT-offers #12:
	 *  - otherwise (no `offer_node_id`, not a response to our offer):
	 *     - MUST fail the request if any of the following are present:
	 *       - `offer_chains`, `offer_features` or `offer_quantity_max`.
	 *     - MUST fail the request if `invreq_amount` is not present.
	 */
	if ((*invreq)->offer_chains)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Unexpected offer_chains");
	if ((*invreq)->offer_features)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Unexpected offer_features");
	if ((*invreq)->offer_quantity_max)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Unexpected offer_quantity_max");
	if (!(*invreq)->invreq_amount)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Missing invreq_amount");

	/* BOLT-offers #12:
	 *  - otherwise (no `offer_node_id`, not a response to our offer):
	 *...
	 *     - MAY use `offer_amount` (or `offer_currency`) for informational display to user.
	 */
	if ((*invreq)->offer_amount && (*invreq)->offer_currency) {
		plugin_notify_message(cmd, LOG_INFORM,
				      "invoice_request offers %.*s%"PRIu64" as %s",
				      (int)tal_bytelen((*invreq)->offer_currency),
				      (*invreq)->offer_currency,
				      *(*invreq)->offer_amount,
				      fmt_amount_msat(tmpctx,
						      amount_msat(*(*invreq)->invreq_amount)));
	}
	return NULL;
}

struct command_result *json_sendinvoice(struct command *cmd,
					const char *buffer,
					const jsmntok_t *params)
{
	struct amount_msat *msat;
	u32 *timeout;
	struct sent *sent = tal(cmd, struct sent);

	sent->offer = NULL;
	sent->cmd = cmd;

	/* FIXME: Support recurring invoice_requests? */
	if (!param(cmd, buffer, params,
		   p_req("invreq", param_invreq, &sent->invreq),
		   p_req("label", param_label, &sent->inv_label),
		   p_opt("amount_msat", param_msat, &msat),
		   p_opt_def("timeout", param_number, &timeout, 90),
		   NULL))
		return command_param_failed();

	if (!offers_enabled)
		return command_fail(cmd, LIGHTNINGD,
				    "experimental-offers not enabled");

	sent->dev_path_use_scidd = NULL;
	sent->dev_reply_path = NULL;
	sent->their_paths = sent->invreq->offer_paths;
	sent->direct_dest = sent->invreq->invreq_payer_id;

	/* BOLT-offers #12:
	 *   - if the invoice is in response to an `invoice_request`:
	 *     - MUST copy all non-signature fields from the `invoice_request`
	 *       (including unknown fields).
	 */
	sent->inv = invoice_for_invreq(sent, sent->invreq);

	/* This is how long we'll wait for a reply for. */
	sent->wait_timeout = *timeout;

	/* BOLT-offers #12:
	 * - if `invreq_amount` is present:
	 *   - MUST set `invoice_amount` to `invreq_amount`
	 * - otherwise:
	 *   - MUST set `invoice_amount` to the *expected amount*.
	 */
	if (!msat)
		sent->inv->invoice_amount = tal_dup(sent->inv, u64,
						    sent->invreq->invreq_amount);
	else
		sent->inv->invoice_amount = tal_dup(sent->inv, u64,
						    &msat->millisatoshis); /* Raw: tlv */

	/* BOLT-offers #12:
	 *   - MUST set `invoice_created_at` to the number of seconds since Midnight 1
	 *      January 1970, UTC when the invoice was created.
	 *    - MUST set `invoice_amount` to the minimum amount it will accept, in units of
	 *      the minimal lightning-payable unit (e.g. milli-satoshis for bitcoin) for
	 *      `invreq_chain`.
	 */
	sent->inv->invoice_created_at = tal(sent->inv, u64);
	*sent->inv->invoice_created_at = time_now().ts.tv_sec;

	/* FIXME: Support blinded paths, in which case use fake nodeid */

	/* BOLT-offers #12:
	 * - MUST set `invoice_payment_hash` to the SHA256 hash of the
	 *   `payment_preimage` that will be given in return for payment.
	 */
	randombytes_buf(&sent->inv_preimage, sizeof(sent->inv_preimage));
	sent->inv->invoice_payment_hash = tal(sent->inv, struct sha256);
	sha256(sent->inv->invoice_payment_hash,
	       &sent->inv_preimage, sizeof(sent->inv_preimage));

	/* BOLT-offers #12:
	 * - if `offer_node_id` is present:
	 *   - MUST set `invoice_node_id` to `offer_node_id`.
	 * - otherwise:
	 *   - MUST set `invoice_node_id` to a valid public key.
	 */
	/* FIXME: Use transitory id! */
	sent->inv->invoice_node_id = tal(sent->inv, struct pubkey);
	sent->inv->invoice_node_id->pubkey = id.pubkey;

	/* BOLT-offers #12:
	 * - if the expiry for accepting payment is not 7200 seconds
	 *   after `invoice_created_at`:
	 *    - MUST set `invoice_relative_expiry`.`seconds_from_creation`
	 *      to the number of seconds after `invoice_created_at` that
	 *      payment of this invoice should not be attempted.
	 */
	if (sent->wait_timeout != 7200) {
		sent->inv->invoice_relative_expiry = tal(sent->inv, u32);
		*sent->inv->invoice_relative_expiry = sent->wait_timeout;
	}

	/* FIXME: recurrence? */
	if (sent->inv->offer_recurrence)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "FIXME: handle recurring invreq?");

	sent->inv->invoice_features
		= plugin_feature_set(cmd->plugin)->bits[BOLT12_INVOICE_FEATURE];

	return sign_invoice(cmd, sent);
}

/* This version doesn't do sanity checks! */
static struct command_result *param_raw_invreq(struct command *cmd,
					       const char *name,
					       const char *buffer,
					       const jsmntok_t *tok,
					       struct tlv_invoice_request **invreq)
{
	char *fail;

	*invreq = invrequest_decode(cmd, buffer + tok->start, tok->end - tok->start,
				    plugin_feature_set(cmd->plugin), chainparams,
				    &fail);
	if (!*invreq)
		return command_fail_badparam(cmd, name, buffer, tok,
					     tal_fmt(cmd,
						     "Unparsable invreq: %s",
						     fail));
	return NULL;
}

struct command_result *json_dev_rawrequest(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *params)
{
	struct sent *sent = tal(cmd, struct sent);
	u32 *timeout;
	struct pubkey *node_id;

	if (!param(cmd, buffer, params,
		   p_req("invreq", param_raw_invreq, &sent->invreq),
		   p_req("nodeid", param_pubkey, &node_id),
		   p_opt_def("timeout", param_number, &timeout, 60),
		   NULL))
		return command_param_failed();

	/* This is how long we'll wait for a reply for. */
	sent->wait_timeout = *timeout;
	sent->cmd = cmd;
	sent->offer = NULL;
	sent->dev_path_use_scidd = NULL;
	sent->dev_reply_path = NULL;
	sent->their_paths = NULL;
	sent->direct_dest = node_id;

	return establish_onion_path(cmd, get_gossmap(cmd->plugin), &id,
				    node_id,
				    disable_connect,
				    fetchinvoice_path_done,
				    fetchinvoice_path_fail,
				    sent);
}
