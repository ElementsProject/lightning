#include <bitcoin/chainparams.h>
#include <bitcoin/preimage.h>
#include <ccan/array_size/array_size.h>
#include <ccan/json_out/json_out.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <ccan/utf8/utf8.h>
#include <common/blindedpath.h>
#include <common/bolt11.h>
#include <common/bolt12.h>
#include <common/bolt12_merkle.h>
#include <common/dijkstra.h>
#include <common/gossmap.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/overflows.h>
#include <common/route.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <errno.h>
#include <inttypes.h>
#include <plugins/libplugin.h>
#include <secp256k1_schnorrsig.h>

static struct gossmap *global_gossmap;
static struct node_id local_id;
static bool disable_connect = false;
static LIST_HEAD(sent_list);

struct sent {
	/* We're in sent_invreqs, awaiting reply. */
	struct list_node list;
	/* The blinding factor used by reply. */
	struct pubkey reply_blinding;
	/* The command which sent us. */
	struct command *cmd;
	/* The offer we are trying to get an invoice/payment for. */
	struct tlv_offer *offer;
	/* Path to use. */
	struct node_id *path;

	/* The invreq we sent, OR the invoice we sent */
	struct tlv_invoice_request *invreq;

	struct tlv_invoice *inv;
	struct preimage inv_preimage;
	struct json_escape *inv_label;
	/* How long to wait for response before giving up. */
	u32 wait_timeout;
};

static struct sent *find_sent(const struct pubkey *blinding)
{
	struct sent *i;

	list_for_each(&sent_list, i, list) {
		if (pubkey_eq(&i->reply_blinding, blinding))
			return i;
	}
	return NULL;
}

static const char *field_diff_(struct plugin *plugin,
			       const tal_t *a, const tal_t *b,
			       const char *fieldname)
{
	/* One is set and the other isn't? */
	if ((a == NULL) != (b == NULL)) {
		plugin_log(plugin, LOG_DBG, "field_diff %s: a is %s, b is %s",
			   fieldname, a ? "set": "unset", b ? "set": "unset");
		return fieldname;
	}
	if (!memeq(a, tal_bytelen(a), b, tal_bytelen(b))) {
		plugin_log(plugin, LOG_DBG, "field_diff %s: a=%s, b=%s",
			   fieldname, tal_hex(tmpctx, a), tal_hex(tmpctx, b));
		return fieldname;
	}
	return NULL;
}

#define field_diff(a, b, fieldname)		\
	field_diff_((cmd)->plugin, a->fieldname, b->fieldname, #fieldname)

/* Returns true if b is a with something appended. */
static bool description_is_appended(const char *a, const char *b)
{
	if (!a || !b)
		return false;
	if (tal_bytelen(b) < tal_bytelen(a))
		return false;
	return memeq(a, tal_bytelen(a), b, tal_bytelen(a));
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
	err = tlv_invoice_error_new(cmd);
	details = json_out_new(cmd);

	plugin_log(cmd->plugin, LOG_DBG, "errtok = %.*s",
		   json_tok_full_len(errtok),
		   json_tok_full(buf, errtok));
	json_out_start(details, NULL, '{');
	if (!fromwire_invoice_error(&data, &dlen, err)) {
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

static struct command_result *handle_invreq_response(struct command *cmd,
						     struct sent *sent,
						     const char *buf,
						     const jsmntok_t *om)
{
	const u8 *invbin;
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
	len = tal_bytelen(invbin);
	inv = tlv_invoice_new(cmd);
 	if (!fromwire_invoice(&invbin, &len, inv)) {
		badfield = "invoice";
		goto badinv;
	}

	/* BOLT-offers #12:
	 * - MUST reject the invoice unless `node_id` is equal to the offer.
	 */
	if (!pubkey32_eq(sent->offer->node_id, inv->node_id)) {
		badfield = "node_id";
		goto badinv;
	}

	/* BOLT-offers #12:
	 *   - MUST reject the invoice if `signature` is not a valid signature
	 *      using `node_id` as described in [Signature Calculation]
	 */
	merkle_tlv(inv->fields, &merkle);
	sighash_from_merkle("invoice", "signature", &merkle, &sighash);

	if (!inv->signature
	    || secp256k1_schnorrsig_verify(secp256k1_ctx, inv->signature->u8,
					   sighash.u.u8, &inv->node_id->pubkey) != 1) {
		badfield = "signature";
		goto badinv;
	}

	/* BOLT-offers #12:
	 * - MUST reject the invoice if `msat` is not present.
	 */
	if (!inv->amount) {
		badfield = "amount";
		goto badinv;
	}

	/* BOLT-offers #12:
	 * - MUST reject the invoice unless `offer_id` is equal to the id of the
	 *   offer.
	 */
	if ((badfield = field_diff(sent->invreq, inv, offer_id)))
		goto badinv;

	/* BOLT-offers #12:
	 * - if the invoice is a reply to an `invoice_request`:
	 *...
	 *   - MUST reject the invoice unless the following fields are equal or
	 *     unset exactly as they are in the `invoice_request:`
	 *     - `quantity`
	 *     - `recurrence_counter`
	 *     - `recurrence_start`
	 *     - `payer_key`
	 *     - `payer_info`
	 */
	if ((badfield = field_diff(sent->invreq, inv, quantity)))
		goto badinv;
	if ((badfield = field_diff(sent->invreq, inv, recurrence_counter)))
		goto badinv;
	if ((badfield = field_diff(sent->invreq, inv, recurrence_start)))
		goto badinv;
	if ((badfield = field_diff(sent->invreq, inv, payer_key)))
		goto badinv;
	if ((badfield = field_diff(sent->invreq, inv, payer_info)))
		goto badinv;

	/* Get the amount we expected. */
	if (sent->offer->amount && !sent->offer->currency) {
		expected_amount = tal(tmpctx, u64);

		*expected_amount = *sent->offer->amount;
		if (sent->invreq->quantity) {
			/* We should never have sent this! */
			if (mul_overflows_u64(*expected_amount,
					      *sent->invreq->quantity)) {
				badfield = "quantity overflow";
				goto badinv;
			}
			*expected_amount *= *sent->invreq->quantity;
		}
	} else
		expected_amount = NULL;

	/* BOLT-offers #12:
	 * - if the offer contained `recurrence`:
	 *   - MUST reject the invoice if `recurrence_basetime` is not set.
	 */
	if (sent->invreq->recurrence_counter && !inv->recurrence_basetime) {
		badfield = "recurrence_basetime";
		goto badinv;
	}

	/* BOLT-offers #12:
	 * - SHOULD confirm authorization if the `description` does not exactly
	 *   match the `offer`
	 *   - MAY highlight if `description` has simply had a change appended.
	 */
	/* We highlight these changes to the caller, for them to handle */
	out = jsonrpc_stream_success(sent->cmd);
	json_add_string(out, "invoice", invoice_encode(tmpctx, inv));
	json_object_start(out, "changes");
	if (field_diff(sent->offer, inv, description)) {
		/* Did they simply append? */
		if (description_is_appended(sent->offer->description,
					    inv->description)) {
			size_t off = tal_bytelen(sent->offer->description);
			json_add_stringn(out, "description_appended",
					 inv->description + off,
					 tal_bytelen(inv->description) - off);
		} else if (!inv->description)
			json_add_stringn(out, "description_removed",
					 sent->offer->description,
					 tal_bytelen(sent->offer->description));
		else
			json_add_stringn(out, "description",
					 inv->description,
					 tal_bytelen(inv->description));
	}

	/* BOLT-offers #12:
	 * - SHOULD confirm authorization if `vendor` does not exactly
	 *   match the `offer`
	 */
	if (field_diff(sent->offer, inv, vendor)) {
		if (!inv->vendor)
			json_add_stringn(out, "vendor_removed",
					 sent->offer->vendor,
					 tal_bytelen(sent->offer->vendor));
		else
			json_add_stringn(out, "vendor",
					 inv->vendor,
					 tal_bytelen(inv->vendor));
	}
	/* BOLT-offers #12:
	 *   - SHOULD confirm authorization if `msat` is not within the amount
	 *     range authorized.
	 */
	/* We always tell them this unless it's trivial to calc and
	 * exactly as expected. */
	if (!expected_amount || *inv->amount != *expected_amount)
		json_add_amount_msat_only(out, "msat",
					  amount_msat(*inv->amount));
	json_object_end(out);

	/* We tell them about next period at this point, if any. */
	if (sent->offer->recurrence) {
		u64 next_counter, next_period_idx;
		u64 paywindow_start, paywindow_end;

		next_counter = *sent->invreq->recurrence_counter + 1;
		if (sent->invreq->recurrence_start)
			next_period_idx = *sent->invreq->recurrence_start
				+ next_counter;
		else
			next_period_idx = next_counter;

		/* If this was the last, don't tell them about a next! */
		if (!sent->offer->recurrence_limit
		    || next_period_idx <= *sent->offer->recurrence_limit) {
			json_object_start(out, "next_period");
			json_add_u64(out, "counter", next_counter);
			json_add_u64(out, "starttime",
				     offer_period_start(*inv->recurrence_basetime,
							next_period_idx,
							sent->offer->recurrence));
			json_add_u64(out, "endtime",
				     offer_period_start(*inv->recurrence_basetime,
							next_period_idx + 1,
							sent->offer->recurrence) - 1);

			offer_period_paywindow(sent->offer->recurrence,
					       sent->offer->recurrence_paywindow,
					       sent->offer->recurrence_base,
					       *inv->recurrence_basetime,
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

static struct command_result *recv_onion_message(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params)
{
	const jsmntok_t *om, *blindingtok;
	struct sent *sent;
	struct pubkey blinding;
	struct command_result *err;

	om = json_get_member(buf, params, "onion_message");
	blindingtok = json_get_member(buf, om, "blinding_in");
	if (!blindingtok || !json_to_pubkey(buf, blindingtok, &blinding))
		return command_hook_success(cmd);

	sent = find_sent(&blinding);
	if (!sent) {
		plugin_log(cmd->plugin, LOG_DBG,
			   "No match for onion %.*s",
			   json_tok_full_len(om),
			   json_tok_full(buf, om));
		return command_hook_success(cmd);
	}

	plugin_log(cmd->plugin, LOG_DBG, "Received onion message: %.*s",
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
	global_gossmap
		= notleak_with_children(gossmap_load(NULL,
						     GOSSIP_STORE_FILENAME));
	if (!global_gossmap)
		plugin_err(plugin, "Could not load gossmap %s: %s",
			   GOSSIP_STORE_FILENAME, strerror(errno));
}

static struct gossmap *get_gossmap(struct plugin *plugin)
{
	if (!global_gossmap)
		init_gossmap(plugin);
	else
		gossmap_refresh(global_gossmap);
	return global_gossmap;
}

static struct command_result *param_offer(struct command *cmd,
					  const char *name,
					  const char *buffer,
					  const jsmntok_t *tok,
					  struct tlv_offer **offer)
{
	char *fail;

	/* BOLT-offers #12:
	 * - if `features` contains unknown _odd_ bits that are non-zero:
	 *  - MUST ignore the bit.
	 * - if `features` contains unknown _even_ bits that are non-zero:
	 *  - MUST NOT respond to the offer.
	 *  - SHOULD indicate the unknown bit to the user.
	 */
	/* BOLT-offers #12:
	 *   - MUST NOT set or imply any `chain_hash` not set or implied by
	 *     the offer.
	 */
	*offer = offer_decode(cmd, buffer + tok->start, tok->end - tok->start,
			      plugin_feature_set(cmd->plugin), chainparams,
			      &fail);
	if (!*offer)
		return command_fail_badparam(cmd, name, buffer, tok,
					     tal_fmt(cmd,
						     "Unparsable offer: %s",
						     fail));

	/* BOLT-offers #12:
	 *
	 *  - if `node_id` or `description` is not set:
	 *    - MUST NOT respond to the offer.
	 */
	if (!(*offer)->node_id)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Offer does not contain a node_id");

	if (!(*offer)->description)
		return command_fail_badparam(cmd, name, buffer, tok,
					     "Offer does not contain a description");
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
	/* 102/103 was the old EXPERIMENTAL feature bit: remove soon! */
	return gossmap_node_get_feature(map, n, OPT_ONION_MESSAGES) != -1
		|| gossmap_node_get_feature(map, n, 102) != -1;
}

/* Create path to node which can carry onion messages; if it can't find
 * one, create singleton path and sets @try_connect.  */
static struct node_id *path_to_node(const tal_t *ctx,
				    struct gossmap *gossmap,
				    const struct pubkey32 *node32_id,
				    bool *try_connect)
{
	const struct gossmap_node *dst;
	struct node_id *nodes, dstid;

	/* FIXME: Use blinded path if avail. */
	gossmap_guess_node_id(gossmap, node32_id, &dstid);
	dst = gossmap_find_node(gossmap, &dstid);
	if (!dst) {
		nodes = tal_arr(ctx, struct node_id, 1);
		/* We don't know the pubkey y-sign, but sendonionmessage will
		 * fix it up if we guess wrong. */
		nodes[0].k[0] = SECP256K1_TAG_PUBKEY_EVEN;
		secp256k1_xonly_pubkey_serialize(secp256k1_ctx,
						 nodes[0].k+1,
						 &node32_id->pubkey);
		/* Since it's not it gossmap, we don't know how to connect,
		 * so don't try. */
		*try_connect = false;
		return nodes;
	} else {
		struct route_hop *r;
		const struct dijkstra *dij;
		const struct gossmap_node *src;

		/* If we don't exist in gossip, routing can't happen. */
		src = gossmap_find_node(gossmap, &local_id);
		if (!src)
			goto go_direct_dst;

		dij = dijkstra(tmpctx, gossmap, dst, AMOUNT_MSAT(0), 0,
			       can_carry_onionmsg, route_score_shorter, NULL);

		r = route_from_dijkstra(tmpctx, gossmap, dij, src, AMOUNT_MSAT(0), 0);
		if (!r)
			goto go_direct_dst;

		*try_connect = false;
		nodes = tal_arr(ctx, struct node_id, tal_count(r));
		for (size_t i = 0; i < tal_count(r); i++)
			nodes[i] = r[i].node_id;
		return nodes;
	}

go_direct_dst:
	/* Try direct route, maybe it's connected? */
	nodes = tal_arr(ctx, struct node_id, 1);
	gossmap_node_get_id(gossmap, dst, &nodes[0]);
	*try_connect = true;
	return nodes;
}

/* Send this message down this path, with blinded reply path */
static struct command_result *send_message(struct command *cmd,
					   struct sent *sent,
					   const char *msgfield,
					   const u8 *msgval,
					   struct command_result *(*done)
					   (struct command *cmd,
					    const char *buf UNUSED,
					    const jsmntok_t *result UNUSED,
					    struct sent *sent))
{
	struct pubkey *backwards;
	struct onionmsg_path **path;
	struct pubkey blinding;
	struct out_req *req;

	/* FIXME: Maybe we should allow this? */
	if (tal_bytelen(sent->path) == 0)
		return command_fail(cmd, PAY_ROUTE_NOT_FOUND,
				    "Refusing to talk to ourselves");

	/* Reverse path is offset by one: we are the final node. */
	backwards = tal_arr(tmpctx, struct pubkey, tal_count(sent->path));
	for (size_t i = 0; i < tal_count(sent->path) - 1; i++) {
		if (!pubkey_from_node_id(&backwards[tal_count(sent->path)-2-i],
					 &sent->path[i]))
			abort();
	}
	if (!pubkey_from_node_id(&backwards[tal_count(sent->path)-1], &local_id))
		abort();

	/* Ok, now make reply for onion_message */
	path = make_blindedpath(tmpctx, backwards, &blinding,
				&sent->reply_blinding);

	req = jsonrpc_request_start(cmd->plugin, cmd, "sendonionmessage",
				    done,
				    forward_error,
				    sent);
	json_array_start(req->js, "hops");
	for (size_t i = 0; i < tal_count(sent->path); i++) {
		json_object_start(req->js, NULL);
		json_add_node_id(req->js, "id", &sent->path[i]);
		if (i == tal_count(sent->path) - 1)
			json_add_hex_talarr(req->js, msgfield, msgval);
		json_object_end(req->js);
	}
	json_array_end(req->js);

	json_object_start(req->js, "reply_path");
	json_add_pubkey(req->js, "blinding", &blinding);
	json_array_start(req->js, "path");
	for (size_t i = 0; i < tal_count(path); i++) {
		json_object_start(req->js, NULL);
		json_add_pubkey(req->js, "id", &path[i]->node_id);
		if (path[i]->enctlv)
			json_add_hex_talarr(req->js, "enctlv", path[i]->enctlv);
		json_object_end(req->js);
	}
	json_array_end(req->js);
	json_object_end(req->js);
	return send_outreq(cmd->plugin, req);
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
	u8 *rawinvreq = tal_arr(tmpctx, u8, 0);
	towire_invoice_request(&rawinvreq, sent->invreq);

	return send_message(cmd, sent, "invoice_request", rawinvreq,
			    sendonionmsg_done);
}

/* We can't find a route, so we're going to try to connect, then just blast it
 * to them. */
static struct command_result *
connect_direct(struct command *cmd,
	       const struct node_id *dst,
	       struct command_result *(*cb)(struct command *command,
					    const char *buf,
					    const jsmntok_t *result,
					    struct sent *sent),
	       struct sent *sent)
{
	struct out_req *req;

	if (disable_connect) {
		plugin_notify_message(cmd, LOG_UNUSUAL,
				      "Cannot find route, but"
				      " fetchplugin-noconnect set:"
				      " trying direct anyway to %s",
				      type_to_string(tmpctx, struct node_id,
						     dst));
		return cb(cmd, NULL, NULL, sent);
	}

	plugin_notify_message(cmd, LOG_INFORM,
			      "Cannot find route, trying connect to %s directly",
			      type_to_string(tmpctx, struct node_id, dst));

	req = jsonrpc_request_start(cmd->plugin, cmd, "connect", cb, cb, sent);
	json_add_node_id(req->js, "id", dst);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *invreq_done(struct command *cmd,
					  const char *buf,
					  const jsmntok_t *result,
					  struct sent *sent)
{
	const jsmntok_t *t;
	char *fail;
	bool try_connect;

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
	if (sent->invreq->recurrence_counter) {
		u64 *base;
		const jsmntok_t *pbtok;
		u64 period_idx = *sent->invreq->recurrence_counter;

		if (sent->invreq->recurrence_start)
			period_idx += *sent->invreq->recurrence_start;

		/* BOLT-offers #12:
		 * - if the offer contained `recurrence_limit`:
		 *   - MUST NOT send an `invoice_request` for a period greater
		 *     than `max_period`
		 */
		if (sent->offer->recurrence_limit
		    && period_idx > *sent->offer->recurrence_limit)
			return command_fail(cmd, LIGHTNINGD,
					    "Can't send invreq for period %"
					    PRIu64" (limit %u)",
					    period_idx,
					    *sent->offer->recurrence_limit);

		/* BOLT-offers #12:
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
		} else if (sent->offer->recurrence_base)
			base = &sent->offer->recurrence_base->basetime;
		else {
			/* happens with *recurrence_base == 0 */
			assert(*sent->invreq->recurrence_counter == 0);
			base = NULL;
		}

		if (base) {
			u64 period_start, period_end, now = time_now().ts.tv_sec;
			offer_period_paywindow(sent->offer->recurrence,
					       sent->offer->recurrence_paywindow,
					       sent->offer->recurrence_base,
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

	sent->path = path_to_node(sent, get_gossmap(cmd->plugin),
				  sent->offer->node_id,
				  &try_connect);
	if (try_connect)
		return connect_direct(cmd, &sent->path[0],
				      sendinvreq_after_connect, sent);

	return sendinvreq_after_connect(cmd, NULL, NULL, sent);
}

/* If they hand us the payer secret, we sign it directly, bypassing checks
 * about periods etc. */
static struct command_result *
force_payer_secret(struct command *cmd,
		   struct sent *sent,
		   struct tlv_invoice_request *invreq,
		   const struct secret *payer_secret)
{
	struct sha256 merkle, sha;
	bool try_connect;
	secp256k1_keypair kp;
	u8 *msg;
	const u8 *p;
	size_t len;

	if (secp256k1_keypair_create(secp256k1_ctx, &kp, payer_secret->data) != 1)
		return command_fail(cmd, LIGHTNINGD, "Bad payer_secret");

	invreq->payer_key = tal(invreq, struct pubkey32);
	/* Docs say this only happens if arguments are invalid! */
	if (secp256k1_keypair_xonly_pub(secp256k1_ctx,
					&invreq->payer_key->pubkey, NULL,
					&kp) != 1)
		plugin_err(cmd->plugin,
			   "secp256k1_keypair_pub failed on %s?",
			   type_to_string(tmpctx, struct secret, payer_secret));

	/* Linearize populates ->fields */
	msg = tal_arr(tmpctx, u8, 0);
	towire_invoice_request(&msg, invreq);
	p = msg;
	len = tal_bytelen(msg);
	sent->invreq = tlv_invoice_request_new(cmd);
	if (!fromwire_invoice_request(&p, &len, sent->invreq))
		plugin_err(cmd->plugin,
			   "Could not remarshall invreq %s", tal_hex(tmpctx, msg));

	merkle_tlv(sent->invreq->fields, &merkle);
	sighash_from_merkle("invoice_request", "payer_signature", &merkle, &sha);

	sent->invreq->payer_signature = tal(invreq, struct bip340sig);
	if (!secp256k1_schnorrsig_sign(secp256k1_ctx,
				       sent->invreq->payer_signature->u8,
				       sha.u.u8,
				       &kp,
				       NULL, NULL)) {
		return command_fail(cmd, LIGHTNINGD,
				    "Failed to sign with payer_secret");
	}

	sent->path = path_to_node(sent, get_gossmap(cmd->plugin),
				  sent->offer->node_id,
				  &try_connect);
	if (try_connect)
		return connect_direct(cmd, &sent->path[0],
				      sendinvreq_after_connect, sent);

	return sendinvreq_after_connect(cmd, NULL, NULL, sent);
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
	struct secret *payer_secret = NULL;
	u32 *timeout;

	invreq = tlv_invoice_request_new(sent);
	if (!param(cmd, buffer, params,
		   p_req("offer", param_offer, &sent->offer),
		   p_opt("msatoshi", param_msat, &msat),
		   p_opt("quantity", param_u64, &invreq->quantity),
		   p_opt("recurrence_counter", param_number,
			 &invreq->recurrence_counter),
		   p_opt("recurrence_start", param_number,
			 &invreq->recurrence_start),
		   p_opt("recurrence_label", param_string, &rec_label),
		   p_opt_def("timeout", param_number, &timeout, 60),
		   p_opt("payer_note", param_string, &payer_note),
#if DEVELOPER
		   p_opt("payer_secret", param_secret, &payer_secret),
#endif
		   NULL))
		return command_param_failed();

	sent->wait_timeout = *timeout;

	/* BOLT-offers #12:
	 *  - MUST set `offer_id` to the Merkle root of the offer as described
	 *    in [Signature Calculation](#signature-calculation).
	 */
	invreq->offer_id = tal(invreq, struct sha256);
	merkle_tlv(sent->offer->fields, invreq->offer_id);

	/* Check if they are trying to send us money. */
	if (sent->offer->send_invoice)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Offer wants an invoice, not invoice_request");

	/* BOLT-offers #12:
	 * - SHOULD not respond to an offer if the current time is after
	 *   `absolute_expiry`.
	 */
	if (sent->offer->absolute_expiry
	    && time_now().ts.tv_sec > *sent->offer->absolute_expiry)
		return command_fail(cmd, OFFER_EXPIRED, "Offer expired");

	/* BOLT-offers #12:
	 * - if the offer did not specify `amount`:
	 *   - MUST specify `amount`.`msat` in multiples of the minimum
	 *     lightning-payable unit (e.g. milli-satoshis for bitcoin) for the
	 *     first `chains` entry.
	 * - otherwise:
	 *   - MAY omit `amount`.
	 *     - if it sets `amount`:
	 *       - MUST specify `amount`.`msat` as greater or equal to amount
	 *         expected by the offer (before any proportional period amount).
	 */
	if (sent->offer->amount) {
		/* FIXME: Check after quantity? */
		if (msat) {
			invreq->amount = tal_dup(invreq, u64,
						 &msat->millisatoshis); /* Raw: tu64 */
		}
	} else {
		if (!msat)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "msatoshi parameter required");
		invreq->amount = tal_dup(invreq, u64,
					 &msat->millisatoshis); /* Raw: tu64 */
	}

	/* BOLT-offers #12:
	 *   - if the offer had a `quantity_min` or `quantity_max` field:
	 *     - MUST set `quantity`
	 *     - MUST set it within that (inclusive) range.
	 *   - otherwise:
	 *     - MUST NOT set `quantity`
	 */
	if (sent->offer->quantity_min || sent->offer->quantity_max) {
		if (!invreq->quantity)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "quantity parameter required");
		if (sent->offer->quantity_min
		    && *invreq->quantity < *sent->offer->quantity_min)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "quantity must be >= %"PRIu64,
					    *sent->offer->quantity_min);
		if (sent->offer->quantity_max
		    && *invreq->quantity > *sent->offer->quantity_max)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "quantity must be <= %"PRIu64,
					    *sent->offer->quantity_max);
	} else {
		if (invreq->quantity)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "quantity parameter unnecessary");
	}

	/* BOLT-offers #12:
	 * - if the offer contained `recurrence`:
	 */
	if (sent->offer->recurrence) {
		/* BOLT-offers #12:
		 *    - for the initial request:
		 *...
		 *      - MUST set `recurrence_counter` `counter` to 0.
		 */
		/* BOLT-offers #12:
		 *    - for any successive requests:
		 *...
		 *      - MUST set `recurrence_counter` `counter` to one greater
		 *        than the highest-paid invoice.
		 */
		if (!invreq->recurrence_counter)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "needs recurrence_counter");

		/* BOLT-offers #12:
		 *    - if the offer contained `recurrence_base` with
		 *      `start_any_period` non-zero:
		 *      - MUST include `recurrence_start`
		 *...
		 *    - otherwise:
		 *      - MUST NOT include `recurrence_start`
		 */
		if (sent->offer->recurrence_base
		    && sent->offer->recurrence_base->start_any_period) {
			if (!invreq->recurrence_start)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "needs recurrence_start");
		} else {
			if (invreq->recurrence_start)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "unnecessary recurrence_start");
		}

		/* recurrence_label uniquely identifies this series of
		 * payments (unless they supply secret themselves)! */
		if (!rec_label && !payer_secret)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "needs recurrence_label");
	} else {
		/* BOLT-offers #12:
		 * - otherwise:
		 *   - MUST NOT set `recurrence_counter`.
		 *   - MUST NOT set `recurrence_start`
		 */
		if (invreq->recurrence_counter)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "unnecessary recurrence_counter");
		if (invreq->recurrence_start)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "unnecessary recurrence_start");
	}

	/* BOLT-offers #12:
	 *
	 * - if the chain for the invoice is not solely bitcoin:
	 *   - MUST specify `chains` the offer is valid for.
	 * - otherwise:
	 *   - the bitcoin chain is implied as the first and only entry.
	 */
	if (!streq(chainparams->network_name, "bitcoin")) {
		invreq->chains = tal_arr(invreq, struct bitcoin_blkid, 1);
		invreq->chains[0] = chainparams->genesis_blockhash;
	}

	invreq->features
		= plugin_feature_set(cmd->plugin)->bits[BOLT11_FEATURE];

	/* invreq->payer_note is not a nul-terminated string! */
	if (payer_note)
		invreq->payer_note = tal_dup_arr(invreq, utf8,
						 payer_note, strlen(payer_note),
						 0);

	/* They can provide a secret, and we don't assume it's our job
	 * to pay. */
	if (payer_secret)
		return force_payer_secret(cmd, sent, invreq, payer_secret);

	/* Make the invoice request (fills in payer_key and payer_info) */
	req = jsonrpc_request_start(cmd->plugin, cmd, "createinvoicerequest",
				    &invreq_done,
				    &forward_error,
				    sent);
	json_add_string(req->js, "bolt12", invrequest_encode(tmpctx, invreq));
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
	u8 *rawinv = tal_arr(tmpctx, u8, 0);
	towire_invoice(&rawinv, sent->inv);
	return send_message(cmd, sent, "invoice", rawinv, prepare_inv_timeout);
}

static struct command_result *createinvoice_done(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *result,
						 struct sent *sent)
{
	const jsmntok_t *invtok = json_get_member(buf, result, "bolt12");
	char *fail;
	bool try_connect;

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

	sent->path = path_to_node(sent, get_gossmap(cmd->plugin),
				  sent->offer->node_id,
				  &try_connect);
	if (try_connect)
		return connect_direct(cmd, &sent->path[0],
				      sendinvoice_after_connect, sent);

	return sendinvoice_after_connect(cmd, NULL, NULL, sent);
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

static bool json_to_bip340sig(const char *buffer, const jsmntok_t *tok,
			      struct bip340sig *sig)
{
	return hex_decode(buffer + tok->start, tok->end - tok->start,
			  sig->u8, sizeof(sig->u8));
}

static struct command_result *payersign_done(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *result,
					     struct sent *sent)
{
	const jsmntok_t *sig;

	sent->inv->refund_signature = tal(sent->inv, struct bip340sig);
	sig = json_get_member(buf, result, "signature");
	json_to_bip340sig(buf, sig, sent->inv->refund_signature);

	return sign_invoice(cmd, sent);
}

/* They're offering a refund, so we need to sign with same key as used
 * in initial payment. */
static struct command_result *listsendpays_done(struct command *cmd,
						const char *buf,
						const jsmntok_t *result,
						struct sent *sent)
{
	const jsmntok_t *t, *arr = json_get_member(buf, result, "payments");
	size_t i;
	const u8 *public_tweak = NULL, *p;
	u8 *msg;
	size_t len;
	struct sha256 merkle;
	struct out_req *req;

	/* Linearize populates ->fields */
	msg = tal_arr(tmpctx, u8, 0);
	towire_invoice(&msg, sent->inv);
	p = msg;
	len = tal_bytelen(msg);
	sent->inv = tlv_invoice_new(cmd);
	if (!fromwire_invoice(&p, &len, sent->inv))
		plugin_err(cmd->plugin,
			   "Could not remarshall %s", tal_hex(tmpctx, msg));

	merkle_tlv(sent->inv->fields, &merkle);

	json_for_each_arr(i, t, arr) {
		const jsmntok_t *b12tok;
		struct tlv_invoice *inv;
		char *fail;

		b12tok = json_get_member(buf, t, "bolt12");
		if (!b12tok) {
			/* This could happen if they try to refund a bolt11 */
			plugin_log(cmd->plugin, LOG_UNUSUAL,
				   "Not bolt12 string in %.*s?",
				   json_tok_full_len(t),
				   json_tok_full(buf, t));
			continue;
		}

		inv = invoice_decode(tmpctx, buf + b12tok->start,
				     b12tok->end - b12tok->start,
				     plugin_feature_set(cmd->plugin),
				     chainparams,
				     &fail);
		if (!inv) {
			plugin_log(cmd->plugin, LOG_BROKEN,
				   "Bad bolt12 string in %.*s?",
				   json_tok_full_len(t),
				   json_tok_full(buf, t));
			continue;
		}

		public_tweak = inv->payer_info;
		break;
	}

	if (!public_tweak)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Cannot find invoice %s for refund",
				    type_to_string(tmpctx, struct sha256,
						   sent->offer->refund_for));

	/* BOLT-offers #12:
	 * - MUST set `refund_signature` to the signature of the
	 *   `refunded_payment_hash` using prefix `refund_signature` and the
	 *   `payer_key` from the to-be-refunded invoice.
	 */
	req = jsonrpc_request_start(cmd->plugin, cmd, "payersign",
				    &payersign_done,
				    &forward_error,
				    sent);
	json_add_string(req->js, "messagename", "invoice");
	json_add_string(req->js, "fieldname", "refund_signature");
	json_add_sha256(req->js, "merkle", &merkle);
	json_add_hex_talarr(req->js, "tweak", public_tweak);
	return send_outreq(cmd->plugin, req);
}

static struct command_result *json_sendinvoice(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *params)
{
	struct amount_msat *msat;
	struct out_req *req;
	u32 *timeout;
	struct sent *sent = tal(cmd, struct sent);

	sent->inv = tlv_invoice_new(cmd);
	sent->invreq = NULL;
	sent->cmd = cmd;

	/* FIXME: Support recurring send_invoice offers? */
	if (!param(cmd, buffer, params,
		   p_req("offer", param_offer, &sent->offer),
		   p_req("label", param_label, &sent->inv_label),
		   p_opt("msatoshi", param_msat, &msat),
		   p_opt_def("timeout", param_number, &timeout, 90),
		   p_opt("quantity", param_u64, &sent->inv->quantity),
		   NULL))
		return command_param_failed();

	/* This is how long we'll wait for a reply for. */
	sent->wait_timeout = *timeout;

	/* Check they are really trying to send us money. */
	if (!sent->offer->send_invoice)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Offer wants an invoice_request, not invoice");

	/* If they don't tell us how much, base it on offer. */
	if (!msat) {
		if (sent->offer->currency)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Offer in different currency: need amount");
		if (!sent->offer->amount)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Offer did not specify: need amount");
		sent->inv->amount = tal_dup(sent->inv, u64, sent->offer->amount);
		if (sent->inv->quantity)
			*sent->inv->amount *= *sent->inv->quantity;
	} else
		sent->inv->amount = tal_dup(sent->inv, u64,
					    &msat->millisatoshis); /* Raw: tlv */

	/* FIXME: Support blinded paths, in which case use fake nodeid */

	/* BOLT-offers #12:
	 * - otherwise (responding to a `send_invoice` offer):
	 *   - MUST set `node_id` to the id of the node to send payment to.
	 *   - MUST set `description` the same as the offer.
	 */
	sent->inv->node_id = tal(sent->inv, struct pubkey32);
	if (!pubkey32_from_node_id(sent->inv->node_id, &local_id))
		plugin_err(cmd->plugin, "Invalid local_id %s?",
			   type_to_string(tmpctx, struct node_id, &local_id));

	sent->inv->description
		= tal_dup_talarr(sent->inv, char, sent->offer->description);

	/* BOLT-offers #12:
	 *   - MUST set (or not set) `send_invoice` the same as the offer.
	 */
	sent->inv->send_invoice = tal(sent->inv, struct tlv_invoice_send_invoice);

	/* BOLT-offers #12:
	 * - MUST set `offer_id` to the id of the offer.
	 */
	sent->inv->offer_id = tal(sent->inv, struct sha256);
	merkle_tlv(sent->offer->fields, sent->inv->offer_id);

	/* BOLT-offers #12:
	 * - SHOULD not respond to an offer if the current time is after
	 *   `absolute_expiry`.
	 */
	if (sent->offer->absolute_expiry
	    && time_now().ts.tv_sec > *sent->offer->absolute_expiry)
		return command_fail(cmd, OFFER_EXPIRED, "Offer expired");

	/* BOLT-offers #12:
	 * - otherwise (responding to a `send_invoice` offer):
	 *...
	 *   - if the offer had a `quantity_min` or `quantity_max` field:
	 *     - MUST set `quantity`
	 *     - MUST set it within that (inclusive) range.
	 *   - otherwise:
	 *     - MUST NOT set `quantity`
	 */
	if (sent->offer->quantity_min || sent->offer->quantity_max) {
		if (!sent->inv->quantity)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "quantity parameter required");
		if (sent->offer->quantity_min
		    && *sent->inv->quantity < *sent->offer->quantity_min)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "quantity must be >= %"PRIu64,
					    *sent->offer->quantity_min);
		if (sent->offer->quantity_max
		    && *sent->inv->quantity > *sent->offer->quantity_max)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "quantity must be <= %"PRIu64,
					    *sent->offer->quantity_max);
	} else {
		if (sent->inv->quantity)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "quantity parameter unnecessary");
	}

	/* BOLT-offers #12:
	 *   - MUST set `timestamp` to the number of seconds since Midnight 1
	 *    January 1970, UTC.
	 */
	sent->inv->timestamp = tal(sent->inv, u64);
	*sent->inv->timestamp = time_now().ts.tv_sec;

	/* BOLT-offers #12:
	 * - if the expiry for accepting payment is not 7200 seconds after
	 *   `timestamp`:
	 *   - MUST set `relative_expiry` `seconds_from_timestamp` to the number
	 *     of seconds after `timestamp` that payment of this invoice should
	 *     not be attempted.
	 */
	if (sent->wait_timeout != 7200) {
		sent->inv->relative_expiry = tal(sent->inv, u32);
		*sent->inv->relative_expiry = sent->wait_timeout;
	}

	/* BOLT-offers #12:
	 * - MUST set `payer_key` to the `node_id` of the offer.
	 */
	sent->inv->payer_key = sent->offer->node_id;

	/* BOLT-offers #12:
	 *     - FIXME: recurrence!
	 */
	if (sent->offer->recurrence)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "FIXME: handle recurring send_invoice offer!");

	/* BOLT-offers #12:
	 *
	 * - if the chain for the invoice is not solely bitcoin:
	 *   - MUST specify `chains` the offer is valid for.
	 * - otherwise:
	 *   - the bitcoin chain is implied as the first and only entry.
	 */
	if (!streq(chainparams->network_name, "bitcoin")) {
		sent->inv->chains = tal_arr(sent->inv, struct bitcoin_blkid, 1);
		sent->inv->chains[0] = chainparams->genesis_blockhash;
	}

	sent->inv->features
		= plugin_feature_set(cmd->plugin)->bits[BOLT11_FEATURE];

	randombytes_buf(&sent->inv_preimage, sizeof(sent->inv_preimage));
	sent->inv->payment_hash = tal(sent->inv, struct sha256);
	sha256(sent->inv->payment_hash,
	       &sent->inv_preimage, sizeof(sent->inv_preimage));

	/* BOLT-offers #12:
	 * - MUST set (or not set) `refund_for` exactly as the offer did.
	 *   - if it sets `refund_for`:
	 *      - MUST set `refund_signature` to the signature of the
	 *        `refunded_payment_hash` using prefix `refund_signature` and
	 *         the `payer_key` from the to-be-refunded invoice.
	 *    - otherwise:
	 *      - MUST NOT set `refund_signature`
	 */
	if (sent->offer->refund_for) {
		sent->inv->refund_for = sent->offer->refund_for;
		/* Find original payment invoice */
		req = jsonrpc_request_start(cmd->plugin, cmd, "listsendpays",
					    &listsendpays_done,
					    &forward_error,
					    sent);
		json_add_sha256(req->js, "payment_hash",
				sent->offer->refund_for);
		return send_outreq(cmd->plugin, req);
	}

	return sign_invoice(cmd, sent);
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
		"Request remote node for to pay this send_invoice {offer}, with {amount}, {quanitity}, {recurrence_counter}, {recurrence_start} and {recurrence_label} iff required.",
		NULL,
		json_sendinvoice,
	},
};

static const char *init(struct plugin *p, const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	bool exp_offers;

	rpc_scan(p, "getinfo",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%}", JSON_SCAN(json_to_node_id, &local_id));

	rpc_scan(p, "listconfigs",
		 take(json_out_obj(NULL, "config", "experimental-offers")),
		 "{experimental-offers:%}",
		 JSON_SCAN(json_to_bool, &exp_offers));

	if (!exp_offers)
		return "offers not enabled in config";
	return NULL;
}

static const struct plugin_hook hooks[] = {
	{
		"onion_message_blinded",
		recv_onion_message
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
