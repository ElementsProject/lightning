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
#include <common/overflows.h>
#include <common/route.h>
#include <common/type_to_string.h>
#include <errno.h>
#include <plugins/libplugin.h>
#include <secp256k1_schnorrsig.h>
#include <sodium.h>

static struct gossmap *global_gossmap;
static struct pubkey local_id;
static bool disable_connect = false;
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
	/* Path to use (including self) */
	struct pubkey *path;

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

static struct command_result *recv_modern_onion_message(struct command *cmd,
							const char *buf,
							const jsmntok_t *params)
{
	const jsmntok_t *om, *secrettok;
	struct sent *sent;
	struct secret pathsecret;
	struct command_result *err;

	om = json_get_member(buf, params, "onion_message");

	secrettok = json_get_member(buf, om, "pathsecret");
	json_to_secret(buf, secrettok, &pathsecret);
	sent = find_sent_by_secret(&pathsecret);
	if (!sent) {
		plugin_log(cmd->plugin, LOG_DBG,
			   "No match for modern onion %.*s",
			   json_tok_full_len(om),
			   json_tok_full(buf, om));
		return command_hook_success(cmd);
	}

	plugin_log(cmd->plugin, LOG_DBG, "Received modern onion message: %.*s",
		   json_tok_full_len(params),
		   json_tok_full(buf, params));

	err = handle_error(cmd, sent, buf, om);
	if (err)
		return err;

	if (sent->invreq)
		return handle_invreq_response(cmd, sent, buf, om);

	return command_hook_success(cmd);
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

static void init_gossmap(struct plugin *plugin)
{
	size_t num_cupdates_rejected;
	global_gossmap
		= notleak_with_children(gossmap_load(NULL,
						     GOSSIP_STORE_FILENAME,
						     &num_cupdates_rejected));
	if (!global_gossmap)
		plugin_err(plugin, "Could not load gossmap %s: %s",
			   GOSSIP_STORE_FILENAME, strerror(errno));
	if (num_cupdates_rejected)
		plugin_log(plugin, LOG_DBG,
			   "gossmap ignored %zu channel updates",
			   num_cupdates_rejected);
}

static struct gossmap *get_gossmap(struct plugin *plugin)
{
	if (!global_gossmap)
		init_gossmap(plugin);
	else
		gossmap_refresh(global_gossmap, NULL);
	return global_gossmap;
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

static bool can_carry_onionmsg(const struct gossmap *map,
			       const struct gossmap_chan *c,
			       int dir,
			       struct amount_msat amount UNUSED,
			       void *arg UNUSED)
{
	const struct gossmap_node *n;
	/* Don't use it if either side says it's disabled */
	if (!c->half[dir].enabled || !c->half[!dir].enabled)
		return false;

	/* Check features of recipient */
	n = gossmap_nth_node(map, c, !dir);
	return gossmap_node_get_feature(map, n, OPT_ONION_MESSAGES) != -1;
}

static struct pubkey *path_to_node(const tal_t *ctx,
				   struct plugin *plugin,
				   const char *buf,
				   const jsmntok_t *listpeerchannels,
				   const struct pubkey *node_id)
{
	struct route_hop *r;
	const struct dijkstra *dij;
	const struct gossmap_node *src;
	const struct gossmap_node *dst;
	struct node_id dstid, local_nodeid;
	struct pubkey *nodes;
	struct gossmap *gossmap;
	struct gossmap_localmods *mods;

	node_id_from_pubkey(&local_nodeid, &local_id);
	node_id_from_pubkey(&dstid, node_id);

	mods = gossmods_from_listpeerchannels(tmpctx, &local_nodeid,
					      buf, listpeerchannels, false,
					      gossmod_add_localchan, NULL);

	gossmap = get_gossmap(plugin);
	gossmap_apply_localmods(gossmap, mods);
	dst = gossmap_find_node(gossmap, &dstid);
	if (!dst)
		goto fail;

	/* If we don't exist in gossip, routing can't happen. */
	src = gossmap_find_node(gossmap, &local_nodeid);
	if (!src)
		goto fail;

	dij = dijkstra(tmpctx, gossmap, dst, AMOUNT_MSAT(0), 0,
		       can_carry_onionmsg, route_score_shorter, NULL);

	r = route_from_dijkstra(tmpctx, gossmap, dij, src, AMOUNT_MSAT(0), 0);
	if (!r)
		goto fail;

	nodes = tal_arr(ctx, struct pubkey, tal_count(r) + 1);
	nodes[0] = local_id;
	for (size_t i = 0; i < tal_count(r); i++) {
		if (!pubkey_from_node_id(&nodes[i+1], &r[i].node_id)) {
			plugin_err(plugin, "Could not convert nodeid %s",
				   type_to_string(tmpctx, struct node_id,
						  &r[i].node_id));
		}
	}

	gossmap_remove_localmods(gossmap, mods);
	return nodes;

fail:
	gossmap_remove_localmods(gossmap, mods);
	return NULL;
}

/* Marshal arguments for sending onion messages */
struct sending {
	struct sent *sent;
	struct tlv_onionmsg_tlv *payload;
	struct command_result *(*done)(struct command *cmd,
				       const char *buf UNUSED,
				       const jsmntok_t *result UNUSED,
				       struct sent *sent);
};

static struct command_result *
send_modern_message(struct command *cmd,
		    struct blinded_path *reply_path,
		    struct sending *sending)
{
	struct sent *sent = sending->sent;
	struct privkey blinding_iter;
	struct pubkey fwd_blinding, *node_alias;
	size_t nhops = tal_count(sent->path);
	struct tlv_onionmsg_tlv **payloads;
	struct out_req *req;
	struct tlv_encrypted_data_tlv *tlv;

	/* Now create enctlvs for *forward* path. */
	randombytes_buf(&blinding_iter, sizeof(blinding_iter));
	if (!pubkey_from_privkey(&blinding_iter, &fwd_blinding))
		return command_fail(cmd, LIGHTNINGD,
				    "Could not convert blinding %s to pubkey!",
				    type_to_string(tmpctx, struct privkey,
						   &blinding_iter));

	/* We overallocate: this node (0) doesn't have payload or alias */
	payloads = tal_arr(cmd, struct tlv_onionmsg_tlv *, nhops);
	node_alias = tal_arr(cmd, struct pubkey, nhops);

	for (size_t i = 1; i < nhops - 1; i++) {
		payloads[i] = tlv_onionmsg_tlv_new(payloads);

		tlv = tlv_encrypted_data_tlv_new(tmpctx);
		tlv->next_node_id = &sent->path[i+1];
		/* FIXME: Pad? */

		payloads[i]->encrypted_recipient_data
			= encrypt_tlv_encrypted_data(payloads[i],
						     &blinding_iter,
						     &sent->path[i],
						     tlv,
						     &blinding_iter,
						     &node_alias[i]);
	}
	/* Final payload contains the actual data. */
	payloads[nhops-1] = sending->payload;

	/* We don't include enctlv in final, but it gives us final alias */
	tlv = tlv_encrypted_data_tlv_new(tmpctx);
	if (!encrypt_tlv_encrypted_data(tmpctx,
					&blinding_iter,
					&sent->path[nhops-1],
					tlv,
					NULL,
					&node_alias[nhops-1])) {
		/* Should not happen! */
		return command_fail(cmd, LIGHTNINGD,
				    "Could create final enctlv");
	}

	payloads[nhops-1]->reply_path = reply_path;

	req = jsonrpc_request_start(cmd->plugin, cmd, "sendonionmessage",
				    sending->done,
				    forward_error,
				    sending->sent);
	json_add_pubkey(req->js, "first_id", &sent->path[1]);
	json_add_pubkey(req->js, "blinding", &fwd_blinding);
	json_array_start(req->js, "hops");
	for (size_t i = 1; i < nhops; i++) {
		u8 *tlvbin;
		json_object_start(req->js, NULL);
		json_add_pubkey(req->js, "id", &node_alias[i]);
		tlvbin = tal_arr(tmpctx, u8, 0);
		towire_tlv_onionmsg_tlv(&tlvbin, payloads[i]);
		json_add_hex_talarr(req->js, "tlv", tlvbin);
		json_object_end(req->js);
	}
	json_array_end(req->js);
	return send_outreq(cmd->plugin, req);
}

/* Lightningd gives us reply path, since we don't know secret to put
 * in final so it will recognize it. */
static struct command_result *use_reply_path(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *result,
					     struct sending *sending)
{
	struct blinded_path *rpath;

	rpath = json_to_blinded_path(cmd, buf,
				     json_get_member(buf, result, "blindedpath"));
	if (!rpath)
		plugin_err(cmd->plugin,
			   "could not parse reply path %.*s?",
			   json_tok_full_len(result),
			   json_tok_full(buf, result));

	return send_modern_message(cmd, rpath, sending);
}

static struct command_result *make_reply_path(struct command *cmd,
					      struct sending *sending)
{
	struct out_req *req;
	size_t nhops = tal_count(sending->sent->path);

	/* FIXME: Maybe we should allow this? */
	if (tal_count(sending->sent->path) == 1)
		return command_fail(cmd, PAY_ROUTE_NOT_FOUND,
				    "Refusing to talk to ourselves");

	/* Create transient secret so we can validate reply! */
	sending->sent->reply_secret = tal(sending->sent, struct secret);
	randombytes_buf(sending->sent->reply_secret, sizeof(struct secret));

	req = jsonrpc_request_start(cmd->plugin, cmd, "blindedpath",
				    use_reply_path,
				    forward_error,
				    sending);

	/* FIXME: Could create an independent reply path, not just
	 * reverse existing. */
	json_array_start(req->js, "ids");
	for (int i = nhops - 2; i >= 0; i--)
		json_add_pubkey(req->js, NULL, &sending->sent->path[i]);
	json_array_end(req->js);
	json_add_secret(req->js, "pathsecret", sending->sent->reply_secret);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *send_message(struct command *cmd,
					   struct sent *sent,
					   struct tlv_onionmsg_tlv *payload STEALS,
					   struct command_result *(*done)
					   (struct command *cmd,
					    const char *buf UNUSED,
					    const jsmntok_t *result UNUSED,
					    struct sent *sent))
{
	struct sending *sending = tal(cmd, struct sending);
	sending->sent = sent;
	sending->payload = tal_steal(sending, payload);
	sending->done = done;

	return make_reply_path(cmd, sending);
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

/* We've connected (if we tried), so send the invreq. */
static struct command_result *
sendinvreq_after_connect(struct command *cmd,
			 const char *buf UNUSED,
			 const jsmntok_t *result UNUSED,
			 struct sent *sent)
{
	struct tlv_onionmsg_tlv *payload = tlv_onionmsg_tlv_new(sent);

	payload->invoice_request = tal_arr(payload, u8, 0);
	towire_tlv_invoice_request(&payload->invoice_request, sent->invreq);

	return send_message(cmd, sent, payload, sendonionmsg_done);
}

struct connect_attempt {
	struct node_id node_id;
	struct command_result *(*cb)(struct command *command,
				     const char *buf,
				     const jsmntok_t *result,
				     struct sent *sent);
	struct sent *sent;
};

static struct command_result *connected(struct command *command,
					const char *buf,
					const jsmntok_t *result,
					struct connect_attempt *ca)
{
	return ca->cb(command, buf, result, ca->sent);
}

static struct command_result *connect_failed(struct command *command,
					     const char *buf,
					     const jsmntok_t *result,
					     struct connect_attempt *ca)
{
	return command_done_err(command, OFFER_ROUTE_NOT_FOUND,
				"Failed: could not route, could not connect",
				NULL);
}

/* We can't find a route, so we're going to try to connect, then just blast it
 * to them. */
static struct command_result *
connect_direct(struct command *cmd,
	       const struct pubkey *dst,
	       struct command_result *(*cb)(struct command *command,
					    const char *buf,
					    const jsmntok_t *result,
					    struct sent *sent),
	       struct sent *sent)
{
	struct out_req *req;
	struct connect_attempt *ca = tal(cmd, struct connect_attempt);

	ca->cb = cb;
	ca->sent = sent;
	node_id_from_pubkey(&ca->node_id, dst);

	/* Make a direct path -> dst. */
	sent->path = tal_arr(sent, struct pubkey, 2);
	sent->path[0] = local_id;
	if (!pubkey_from_node_id(&sent->path[1], &ca->node_id)) {
		/* Should not happen! */
		return command_done_err(cmd, LIGHTNINGD,
					"Failed: could not convert to pubkey?",
					NULL);
	}

	if (disable_connect) {
		/* FIXME: This means we will fail if parity is wrong! */
		plugin_notify_message(cmd, LOG_UNUSUAL,
				      "Cannot find route, but"
				      " fetchplugin-noconnect set:"
				      " trying direct anyway to %s",
				      type_to_string(tmpctx, struct pubkey,
						     dst));
		return cb(cmd, NULL, NULL, sent);
	}

	req = jsonrpc_request_start(cmd->plugin, cmd, "connect", connected,
				    connect_failed, ca);
	json_add_node_id(req->js, "id", &ca->node_id);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *fetchinvoice_listpeerchannels_done(struct command *cmd,
								 const char *buf,
								 const jsmntok_t *result,
								 struct sent *sent)
{
	sent->path = path_to_node(sent, cmd->plugin, buf, result,
				  sent->invreq->offer_node_id);
	if (!sent->path)
		return connect_direct(cmd, sent->invreq->offer_node_id,
				      sendinvreq_after_connect, sent);

	return sendinvreq_after_connect(cmd, NULL, NULL, sent);
}

static struct command_result *invreq_done(struct command *cmd,
					  const char *buf,
					  const jsmntok_t *result,
					  struct sent *sent)
{
	const jsmntok_t *t;
	char *fail;
	struct out_req *req;

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

	req = jsonrpc_request_start(cmd->plugin, cmd, "listpeerchannels",
				    fetchinvoice_listpeerchannels_done,
				    &forward_error,
				    sent);
	return send_outreq(cmd->plugin, req);
}

/* Fetches an invoice for this offer, and makes sure it corresponds. */
static struct command_result *json_fetchinvoice(struct command *cmd,
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
		   NULL))
		return command_param_failed();

	sent->wait_timeout = *timeout;

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
static struct command_result *invoice_payment(struct command *cmd,
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

/* We've connected (if we tried), so send the invoice. */
static struct command_result *
sendinvoice_after_connect(struct command *cmd,
			  const char *buf UNUSED,
			  const jsmntok_t *result UNUSED,
			  struct sent *sent)
{
	struct tlv_onionmsg_tlv *payload = tlv_onionmsg_tlv_new(sent);

	payload->invoice = tal_arr(payload, u8, 0);
	towire_tlv_invoice(&payload->invoice, sent->inv);

	return send_message(cmd, sent, payload, prepare_inv_timeout);
}

static struct command_result *sendinvoice_listpeerchannels_done(struct command *cmd,
								const char *buf,
								const jsmntok_t *result,
								struct sent *sent)
{

	sent->path = path_to_node(sent, cmd->plugin, buf, result,
				  sent->invreq->invreq_payer_id);
	if (!sent->path)
		return connect_direct(cmd, sent->invreq->invreq_payer_id,
				      sendinvoice_after_connect, sent);

	return sendinvoice_after_connect(cmd, NULL, NULL, sent);
}

static struct command_result *createinvoice_done(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *result,
						 struct sent *sent)
{
	const jsmntok_t *invtok = json_get_member(buf, result, "bolt12");
	struct out_req *req;
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
	/* FIXME! */
	if (sent->invreq->offer_paths) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "FIXME: support blinded paths!");
	}

	req = jsonrpc_request_start(cmd->plugin, cmd, "listpeerchannels",
				    sendinvoice_listpeerchannels_done,
				    &forward_error,
				    sent);
	return send_outreq(cmd->plugin, req);
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

static struct command_result *json_sendinvoice(struct command *cmd,
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
	sent->inv->invoice_node_id->pubkey = local_id.pubkey;

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

static struct command_result *rawrequest_listpeerchannels_done(struct command *cmd,
							       const char *buf,
							       const jsmntok_t *result,
							       struct sent *sent)
{
	struct pubkey node_id;
	/* Hack to store node_id from cmd */
	node_id = *sent->path;
	sent->path = path_to_node(sent, cmd->plugin, buf, result, &node_id);
	if (!sent->path) {
		return connect_direct(cmd, &node_id,
				      sendinvreq_after_connect, sent);
	}

	return sendinvreq_after_connect(cmd, NULL, NULL, sent);
}

static struct command_result *json_dev_rawrequest(struct command *cmd,
						  const char *buffer,
						  const jsmntok_t *params)
{
	struct sent *sent = tal(cmd, struct sent);
	u32 *timeout;
	struct pubkey *node_id;
	struct out_req *req;

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

	/* We temporarily abuse ->path to store nodeid! */
	sent->path = node_id;
	req = jsonrpc_request_start(cmd->plugin, cmd, "listpeerchannels",
				    rawrequest_listpeerchannels_done,
				    &forward_error,
				    sent);
	return send_outreq(cmd->plugin, req);
}

static const struct plugin_command commands[] = {
	{
		"fetchinvoice",
		"payment",
		"Request remote node for an invoice for this {offer}, with {amount}, {quanitity}, {recurrence_counter}, {recurrence_start} and {recurrence_label} iff required.",
		NULL,
		json_fetchinvoice,
	},
	{
		"sendinvoice",
		"payment",
		"Request remote node for to pay this {invreq}, with {label}, optional {amount_msat}, and {timeout} (default 90 seconds).",
		NULL,
		json_sendinvoice,
	},
	{
		"dev-rawrequest",
		"util",
		"Send {invreq} to {nodeid}, wait {timeout} (60 seconds by default)",
		NULL,
		json_dev_rawrequest,
		.dev_only = true,
	},
};

static const char *init(struct plugin *p, const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	bool exp_offers;

	rpc_scan(p, "getinfo",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%}", JSON_SCAN(json_to_pubkey, &local_id));

	rpc_scan(p, "listconfigs",
		 take(json_out_obj(NULL, "config", "experimental-offers")),
		 "{configs:{experimental-offers:{set:%}}}",
		 JSON_SCAN(json_to_bool, &exp_offers));

	if (!exp_offers)
		return "offers not enabled in config";
	return NULL;
}

static const struct plugin_hook hooks[] = {
	{
		"onion_message_recv_secret",
		recv_modern_onion_message
	},
	{
		"invoice_payment",
		invoice_payment,
	},
};

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_RESTARTABLE, true, NULL,
		    commands, ARRAY_SIZE(commands),
		    /* No notifications */
	            NULL, 0,
		    hooks, ARRAY_SIZE(hooks),
		    NULL, 0,
		    plugin_option("fetchinvoice-noconnect", "flag",
				  "Don't try to connect directly to fetch an invoice.",
				  flag_option, &disable_connect),
		    NULL);
}
