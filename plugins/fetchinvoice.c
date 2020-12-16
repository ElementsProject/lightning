#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/json_out/json_out.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/blindedpath.h>
#include <common/bolt11.h>
#include <common/bolt12.h>
#include <common/bolt12_merkle.h>
#include <common/dijkstra.h>
#include <common/gossmap.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/route.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <errno.h>
#include <inttypes.h>
#include <plugins/libplugin.h>

static struct gossmap *global_gossmap;
static struct node_id local_id;

struct sent {
	/* The offer we are trying to get an invoice for. */
	struct tlv_offer *offer;
	/* The invreq we sent. */
	struct tlv_invoice_request *invreq;
};

static struct command_result *sendonionmsg_done(struct command *cmd,
						const char *buf UNUSED,
						const jsmntok_t *result UNUSED,
						struct sent *sent)
{
	/* FIXME: Now wait for reply. */
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
	 *  - if `node_id`, `description` or `signature` is not set:
	 *    - MUST NOT respond to the offer.
	 */
	/* Note: offer_decode checks `signature` */
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
	return n && gossmap_node_get_feature(map, n, OPT_ONION_MESSAGES) != -1;
}

/* make_blindedpath only needs pubkeys */
static const struct pubkey *route_backwards(const tal_t *ctx,
					    const struct gossmap *gossmap,
					    struct route **r)
{
	struct pubkey *rarr;

	rarr = tal_arr(ctx, struct pubkey, tal_count(r));
	for (size_t i = 0; i < tal_count(r); i++) {
		const struct gossmap_node *dst;
		struct node_id id;

		dst = gossmap_nth_node(gossmap, r[i]->c, r[i]->dir);
		gossmap_node_get_id(gossmap, dst, &id);
		/* We're going backwards */
		if (!pubkey_from_node_id(&rarr[tal_count(rarr) - 1 - i], &id))
			abort();
	}

	return rarr;
}

static struct command_result *send_message(struct command *cmd,
					   struct sent *sent,
					   const char *msgfield,
					   const u8 *msgval)
{
	const struct dijkstra *dij;
	const struct gossmap_node *dst, *src;
	struct route **r;
	struct gossmap *gossmap = get_gossmap(cmd->plugin);
	const struct pubkey *backwards;
	struct onionmsg_path **path;
	struct pubkey blinding, reply_blinding;
	struct out_req *req;
	struct node_id dstid;

	/* FIXME: Use blinded path if avail. */
	gossmap_guess_node_id(gossmap, sent->offer->node_id, &dstid);
	dst = gossmap_find_node(gossmap, &dstid);
	if (!dst)
		return command_fail(cmd, LIGHTNINGD,
				    "Unknown destination %s",
				    type_to_string(tmpctx, struct node_id,
						   &dstid));

	/* If we don't exist in gossip, routing can't happen. */
	src = gossmap_find_node(gossmap, &local_id);
	if (!src)
		return command_fail(cmd, PAY_ROUTE_NOT_FOUND,
				    "We don't have any channels");

	dij = dijkstra(tmpctx, gossmap, dst, AMOUNT_MSAT(0), 0,
		       can_carry_onionmsg, route_score_shorter, NULL);

	r = route_from_dijkstra(tmpctx, gossmap, dij, src);
	if (!r)
		/* FIXME: We need to retry kind of like keysend here... */
		return command_fail(cmd, OFFER_ROUTE_NOT_FOUND,
				    "Can't find route");

	/* Ok, now make reply for onion_message */
	backwards = route_backwards(tmpctx, gossmap, r);
	path = make_blindedpath(tmpctx, backwards, &blinding, &reply_blinding);

	req = jsonrpc_request_start(cmd->plugin, cmd, "sendonionmessage",
				    &sendonionmsg_done,
				    &forward_error,
				    sent);
	json_array_start(req->js, "hops");
	for (size_t i = 0; i < tal_count(r); i++) {
		struct node_id id;

		json_object_start(req->js, NULL);
		gossmap_node_get_id(gossmap,
				    gossmap_nth_node(gossmap, r[i]->c, !r[i]->dir),
				    &id);
		json_add_node_id(req->js, "id", &id);
		if (i == tal_count(r) - 1)
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

static struct command_result *invreq_done(struct command *cmd,
					  const char *buf,
					  const jsmntok_t *result,
					  struct tlv_offer *offer)
{
	const jsmntok_t *t;
	struct sent *sent;
	char *fail;
	u8 *rawinvreq;

	/* We need to remember both offer and invreq to check reply. */
	sent = tal(cmd, struct sent);
	sent->offer = tal_steal(sent, offer);

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

	rawinvreq = tal_arr(tmpctx, u8, 0);
	towire_invoice_request(&rawinvreq, sent->invreq);
	return send_message(cmd, sent, "invoice_request", rawinvreq);
}

/* Fetches an invoice for this offer, and makes sure it corresponds. */
static struct command_result *json_fetchinvoice(struct command *cmd,
						const char *buffer,
						const jsmntok_t *params)
{
	struct tlv_offer *offer;
	struct amount_msat *msat;
	const char *rec_label;
	struct out_req *req;
	struct tlv_invoice_request *invreq;

	invreq = tlv_invoice_request_new(cmd);

	if (!param(cmd, buffer, params,
		   p_req("offer", param_offer, &offer),
		   p_opt("msatoshi", param_msat, &msat),
		   p_opt("quantity", param_u64, &invreq->quantity),
		   p_opt("recurrence_counter", param_number,
			 &invreq->recurrence_counter),
		   p_opt("recurrence_start", param_number,
			 &invreq->recurrence_start),
		   p_opt("recurrence_label", param_string, &rec_label),
		   NULL))
		return command_param_failed();

	/* BOLT-offers #12:
	 *  - MUST set `offer_id` to the merkle root of the offer as described
	 *    in [Signature Calculation](#signature-calculation).
	 */
	invreq->offer_id = tal(invreq, struct sha256);
	merkle_tlv(offer->fields, invreq->offer_id);

	/* Check if they are trying to send us money. */
	if (offer->send_invoice)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Offer wants an invoice, not invoice_request");

	/* BOLT-offers #12:
	 * - SHOULD not respond to an offer if the current time is after
	 *   `absolute_expiry`.
	 */
	if (offer->absolute_expiry
	    && time_now().ts.tv_sec > *offer->absolute_expiry)
		return command_fail(cmd, OFFER_EXPIRED, "Offer expired");

	/* BOLT-offers #12:
	 * - if the offer did not specify `amount`:
	 *   - MUST specify `amount`.`msat` in multiples of the minimum
	 *     lightning-payable unit (e.g. milli-satoshis for bitcoin) for the
	 *     first `chains` entry.
	 * - otherwise:
	 *   - MUST NOT set `amount`
	 */
	if (offer->amount) {
		if (msat)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "msatoshi parameter unnecessary");
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
	if (offer->quantity_min || offer->quantity_max) {
		if (!invreq->quantity)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "quantity parameter required");
		if (offer->quantity_min
		    && *invreq->quantity < *offer->quantity_min)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "quantity must be >= %"PRIu64,
					    *offer->quantity_min);
		if (offer->quantity_max
		    && *invreq->quantity > *offer->quantity_max)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "quantity must be <= %"PRIu64,
					    *offer->quantity_max);
	} else {
		if (invreq->quantity)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "quantity parameter unnecessary");
	}

	/* BOLT-offers #12:
	 * - if the offer contained `recurrence`:
	 */
	if (offer->recurrence) {
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
		if (offer->recurrence_base
		    && offer->recurrence_base->start_any_period) {
			if (!invreq->recurrence_start)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "needs recurrence_start");
		} else {
			if (invreq->recurrence_start)
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "unnecessary recurrence_start");
		}

		/* recurrence_label uniquely identifies this series of
		 * payments. */
		if (!rec_label)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "needs recurrence_label");

		/* FIXME! */
		/* BOLT-offers #12:
		 * - SHOULD NOT send an `invoice_request` for a period which has
		 *   already passed.
		 */
		/* If there's no recurrence_base, we need the initial payment
		 * for this... */
	} else {
		/* BOLT-offers #12:
		 * - otherwise:
		 *   - MUST NOT set `recurrence_counter`.
		 *...
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

	/* Make the invoice request (fills in payer_key and payer_info) */
	req = jsonrpc_request_start(cmd->plugin, cmd, "createinvoicerequest",
				    &invreq_done,
				    &forward_error,
				    offer);
	json_add_string(req->js, "bolt12", invrequest_encode(tmpctx, invreq));
	if (rec_label)
		json_add_string(req->js, "recurrence_label", rec_label);
	return send_outreq(cmd->plugin, req);
}

static const struct plugin_command commands[] = { {
	"fetchinvoice",
	"payment",
	"Request remote node for an invoice for this {offer}, with {amount}, {quanitity}, {recurrence_counter}, {recurrence_start} and {recurrence_label} iff required.",
	NULL,
	json_fetchinvoice,
	}
};

static void init(struct plugin *p, const char *buf UNUSED,
		 const jsmntok_t *config UNUSED)
{
	const char *field;

	field = rpc_delve(tmpctx, p, "getinfo",
			  take(json_out_obj(NULL, NULL, NULL)), ".id");
	if (!node_id_from_hexstr(field, strlen(field), &local_id))
		plugin_err(p, "getinfo didn't contain valid id: '%s'", field);
}

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_RESTARTABLE, true, NULL,
		    commands, ARRAY_SIZE(commands),
		    /* No notifications */
	            NULL, 0,
		    /* No hooks */
		    NULL, 0,
		    /* No options */
		    NULL);
}
