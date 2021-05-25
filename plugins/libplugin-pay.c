#include <bitcoin/preimage.h>
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/dijkstra.h>
#include <common/gossmap.h>
#include <common/json_helpers.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <common/pseudorand.h>
#include <common/random_select.h>
#include <common/type_to_string.h>
#include <errno.h>
#include <plugins/libplugin-pay.h>
#include <wire/peer_wire.h>

static struct gossmap *global_gossmap;

static void init_gossmap(struct plugin *plugin)
{
	global_gossmap
		= notleak_with_children(gossmap_load(NULL,
						     GOSSIP_STORE_FILENAME));
	if (!global_gossmap)
		plugin_err(plugin, "Could not load gossmap %s: %s",
			   GOSSIP_STORE_FILENAME, strerror(errno));
}

struct gossmap *get_gossmap(struct plugin *plugin)
{
	if (!global_gossmap)
		init_gossmap(plugin);
	else
		gossmap_refresh(global_gossmap);
	return global_gossmap;
}

struct payment *payment_new(tal_t *ctx, struct command *cmd,
			    struct payment *parent,
			    struct payment_modifier **mods)
{
	struct payment *p = tal(ctx, struct payment);

	static u64 next_id = 0;

	p->children = tal_arr(p, struct payment *, 0);
	p->parent = parent;
	p->modifiers = mods;
	p->cmd = cmd;
	p->start_time = time_now();
	p->result = NULL;
	p->why = NULL;
	p->getroute = tal(p, struct getroute_request);
	p->label = NULL;
	p->failreason = NULL;
	p->getroute->riskfactorppm = 10000000;
	p->abort = false;
	p->route = NULL;
	p->temp_exclusion = NULL;
	p->failroute_retry = false;
	p->invstring = NULL;
	p->routetxt = NULL;
	p->max_htlcs = UINT32_MAX;
	p->aborterror = NULL;

	/* Copy over the relevant pieces of information. */
	if (parent != NULL) {
		assert(cmd == NULL);
		tal_arr_expand(&parent->children, p);
		p->destination = parent->destination;
		p->destination_has_tlv = parent->destination_has_tlv;
		p->amount = parent->amount;
		p->label = parent->label;
		p->payment_hash = parent->payment_hash;
		p->partid = payment_root(p->parent)->next_partid++;
		p->plugin = parent->plugin;

		/* Re-establish the unmodified constraints for our sub-payment. */
		p->constraints = *parent->start_constraints;
		p->deadline = parent->deadline;

		p->min_final_cltv_expiry = parent->min_final_cltv_expiry;
		p->routes = parent->routes;
		p->features = parent->features;
		p->id = parent->id;
		p->local_id = parent->local_id;
		p->local_offer_id = parent->local_offer_id;
	} else {
		assert(cmd != NULL);
		p->partid = 0;
		p->next_partid = 1;
		p->plugin = cmd->plugin;
		p->channel_hints = tal_arr(p, struct channel_hint, 0);
		p->excluded_nodes = tal_arr(p, struct node_id, 0);
		p->id = next_id++;
		/* Caller must set this.  */
		p->local_id = NULL;
		p->local_offer_id = NULL;
	}

	/* Initialize all modifier data so we can point to the fields when
	 * wiring into the param() call in a JSON-RPC handler. The callback
	 * can also just `memcpy` the parent if this outside access is not
	 * required. */
	p->modifier_data = tal_arr(p, void *, 0);
	for (size_t i=0; mods[i] != NULL; i++) {
		if (mods[i]->data_init != NULL)
			tal_arr_expand(&p->modifier_data,
				       mods[i]->data_init(p));
		else
			tal_arr_expand(&p->modifier_data, NULL);
	}

	return p;
}

struct payment *payment_root(struct payment *p)
{
	if (p->parent == NULL)
		return p;
	else
		return payment_root(p->parent);
}

static void
paymod_log_header(struct payment *p, const char **type, u64 *id)
{
	struct payment *root = payment_root(p);
	/* We prefer to show the command ID here since it is also known
	 * by `lightningd`, so in theory it can be used to correlate
	 * debugging logs between the main `lightningd` and whatever
	 * plugin is using the paymod system.
	 * We only fall back to a unique id per root payment if there
	 * is no command with an id associated with this payment.
	 */
	if (root->cmd && root->cmd->id) {
		*type = "cmd";
		*id = *root->cmd->id;
	} else {
		*type = "id";
		*id = root->id;
	}
}

static void
paymod_log(struct payment *p, enum log_level l, const char *fmt, ...)
{
	const char *type;
	u64 id;
	char *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	paymod_log_header(p, &type, &id);
	plugin_log(p->plugin, l, "%s %"PRIu64" partid %"PRIu32": %s",
		   type, id, p->partid, txt);
}
static void
paymod_err(struct payment *p, const char *fmt, ...)
{
	const char *type;
	u64 id;
	char *txt;
	va_list ap;

	va_start(ap, fmt);
	txt = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	paymod_log_header(p, &type, &id);
	plugin_err(p->plugin, "%s %"PRIu64" partid %"PRIu32": %s",
		   type, id, p->partid, txt);
}

/* Generic handler for RPC failures that should end up failing the payment. */
static struct command_result *payment_rpc_failure(struct command *cmd,
						  const char *buffer,
						  const jsmntok_t *toks,
						  struct payment *p)
{
	payment_fail(p,
		     "Failing a partial payment due to a failed RPC call: %.*s",
		     toks->end - toks->start, buffer + toks->start);
	return command_still_pending(cmd);
}

struct payment_tree_result payment_collect_result(struct payment *p)
{
	struct payment_tree_result res;
	size_t numchildren = tal_count(p->children);
	res.sent = AMOUNT_MSAT(0);
	res.attempts = 1;
	res.treestates = p->step;
	res.leafstates = 0;
	res.preimage = NULL;
	res.failure = NULL;
	if (p->step == PAYMENT_STEP_FAILED && p->result != NULL)
		res.failure = p->result;

	if (numchildren == 0) {
		res.leafstates |= p->step;
		if (p->result && p->result->state == PAYMENT_COMPLETE) {
			res.sent = p->result->amount_sent;
			res.preimage = p->result->payment_preimage;
		}
	}

	for (size_t i = 0; i < numchildren; i++) {
		struct payment_tree_result cres =
		    payment_collect_result(p->children[i]);

		/* Some of our subpayments have succeeded, aggregate how much
		 * we sent in total. */
		if (!amount_msat_add(&res.sent, res.sent, cres.sent))
			paymod_err(
			    p,
			    "Number overflow summing partial payments: %s + %s",
			    type_to_string(tmpctx, struct amount_msat,
					   &res.sent),
			    type_to_string(tmpctx, struct amount_msat,
					   &cres.sent));

		/* Bubble up the first preimage we see. */
		if (res.preimage == NULL && cres.preimage != NULL)
			res.preimage = cres.preimage;

		res.leafstates |= cres.leafstates;
		res.treestates |= cres.treestates;
		res.attempts += cres.attempts;

		/* We bubble the failure result with the highest failcode up
		 * to the root. */
		if (res.failure == NULL ||
		    (cres.failure != NULL &&
		     cres.failure->failcode > res.failure->failcode)) {
			res.failure = cres.failure;
		}
	}
	return res;
}

static struct command_result *
payment_getblockheight_success(struct command *cmd,
			       const char *buffer,
			       const jsmntok_t *toks,
			       struct payment *p)
{
	const jsmntok_t *blockheighttok =
	    json_get_member(buffer, toks, "blockheight");
	json_to_number(buffer, blockheighttok, &p->start_block);
	payment_continue(p);
	return command_still_pending(cmd);
}

#define INVALID_BLOCKHEIGHT UINT32_MAX

static
void payment_start_at_blockheight(struct payment *p, u32 blockheight)
{
	struct payment *root = payment_root(p);

	/* Should have been set in root payment, or propagated from root
	 * payment to all child payments.  */
	assert(p->local_id);

	p->step = PAYMENT_STEP_INITIALIZED;
	p->current_modifier = -1;

	/* Pre-generate the getroute request, so modifiers can have their say,
	 * before we actually call `getroute` */
	p->getroute->destination = p->destination;
	p->getroute->max_hops = ROUTING_MAX_HOPS;
	p->getroute->cltv = root->min_final_cltv_expiry;
	p->getroute->amount = p->amount;

	p->start_constraints = tal_dup(p, struct payment_constraints, &p->constraints);

	if (blockheight != INVALID_BLOCKHEIGHT) {
		/* The caller knows the actual blockheight.  */
		p->start_block = blockheight;
		return payment_continue(p);
	}
	if (p->parent) {
		/* The parent should have a start block.  */
		p->start_block = p->parent->start_block;
		return payment_continue(p);
	}

	/* `waitblockheight 0` can be used as a query for the current
	 * block height.
	 * This is slightly better than `getinfo` since `getinfo`
	 * counts the channels and addresses and pushes more data
	 * onto the RPC but all we care about is the blockheight.
	 */
	struct out_req *req;
	req = jsonrpc_request_start(p->plugin, NULL, "waitblockheight",
				    &payment_getblockheight_success,
				    &payment_rpc_failure, p);
	json_add_u32(req->js, "blockheight", 0);
	send_outreq(p->plugin, req);
}
void payment_start(struct payment *p)
{
	payment_start_at_blockheight(p, INVALID_BLOCKHEIGHT);
}

static void channel_hints_update(struct payment *p,
				 const struct short_channel_id scid,
				 int direction, bool enabled, bool local,
				 const struct amount_msat *estimated_capacity,
				 u16 *htlc_budget)
{
	struct payment *root = payment_root(p);
	struct channel_hint hint;

	/* If the channel is marked as enabled it must have an estimate. */
	assert(!enabled || estimated_capacity != NULL);

	/* Try and look for an existing hint: */
	for (size_t i=0; i<tal_count(root->channel_hints); i++) {
		struct channel_hint *hint = &root->channel_hints[i];
		if (short_channel_id_eq(&hint->scid.scid, &scid) &&
		    hint->scid.dir == direction) {
			bool modified = false;
			/* Prefer to disable a channel. */
			if (!enabled && hint->enabled) {
				hint->enabled = false;
				modified = true;
			}

			/* Prefer the more conservative estimate. */
			if (estimated_capacity != NULL &&
			    amount_msat_greater(hint->estimated_capacity,
						*estimated_capacity)) {
				hint->estimated_capacity = *estimated_capacity;
				modified = true;
			}
			if (htlc_budget != NULL && *htlc_budget < hint->htlc_budget) {
				hint->htlc_budget = *htlc_budget;
				modified = true;
			}

			if (modified)
				paymod_log(p, LOG_DBG,
					   "Updated a channel hint for %s: "
					   "enabled %s, "
					   "estimated capacity %s",
					   type_to_string(tmpctx,
						struct short_channel_id_dir,
						&hint->scid),
					   hint->enabled ? "true" : "false",
					   type_to_string(tmpctx,
						struct amount_msat,
						&hint->estimated_capacity));
			return;
		}
	}

	/* No hint found, create one. */
	hint.enabled = enabled;
	hint.scid.scid = scid;
	hint.scid.dir = direction;
	hint.local = local;
	if (estimated_capacity != NULL)
		hint.estimated_capacity = *estimated_capacity;

	if (htlc_budget != NULL)
		hint.htlc_budget = *htlc_budget;

	tal_arr_expand(&root->channel_hints, hint);

	paymod_log(
	    p, LOG_DBG,
	    "Added a channel hint for %s: enabled %s, estimated capacity %s",
	    type_to_string(tmpctx, struct short_channel_id_dir, &hint.scid),
	    hint.enabled ? "true" : "false",
	    type_to_string(tmpctx, struct amount_msat,
			   &hint.estimated_capacity));
}

static void payment_exclude_most_expensive(struct payment *p)
{
	struct route_hop *e = &p->route[0];
	struct amount_msat fee, worst = AMOUNT_MSAT(0);

	for (size_t i = 0; i < tal_count(p->route)-1; i++) {
		if (!amount_msat_sub(&fee, p->route[i].amount, p->route[i+1].amount))
			paymod_err(p, "Negative fee in a route.");

		if (amount_msat_greater_eq(fee, worst)) {
			e = &p->route[i];
			worst = fee;
		}
	}
	channel_hints_update(p, e->scid, e->direction, false, false,
			     NULL, NULL);
}

static void payment_exclude_longest_delay(struct payment *p)
{
	struct route_hop *e = &p->route[0];
	u32 delay, worst = 0;

	for (size_t i = 0; i < tal_count(p->route)-1; i++) {
		delay = p->route[i].delay - p->route[i+1].delay;
		if (delay >= worst) {
			e = &p->route[i];
			worst = delay;
		}
	}
	channel_hints_update(p, e->scid, e->direction, false, false,
			     NULL, NULL);
}

static struct amount_msat payment_route_fee(struct payment *p)
{
	struct amount_msat fee;
	if (!amount_msat_sub(&fee, p->route[0].amount, p->amount)) {
		paymod_log(
		    p,
		    LOG_BROKEN,
		    "gossipd returned a route with a negative fee: sending %s "
		    "to deliver %s",
		    type_to_string(tmpctx, struct amount_msat,
				   &p->route[0].amount),
		    type_to_string(tmpctx, struct amount_msat, &p->amount));
		abort();
	}
	return fee;
}

/* Update the constraints by subtracting the delta_fee and delta_cltv if the
 * result is positive. Returns whether or not the update has been applied. */
static WARN_UNUSED_RESULT bool
payment_constraints_update(struct payment_constraints *cons,
			   const struct amount_msat delta_fee,
			   const u32 delta_cltv)
{
	if (delta_cltv > cons->cltv_budget)
		return false;

	/* amount_msat_sub performs a check before actually subtracting. */
	if (!amount_msat_sub(&cons->fee_budget, cons->fee_budget, delta_fee))
		return false;

	cons->cltv_budget -= delta_cltv;
	return true;
}

static struct channel_hint *payment_chanhints_get(struct payment *p,
						  struct route_hop *h)
{
	struct payment *root = payment_root(p);
	struct channel_hint *curhint;
	for (size_t j = 0; j < tal_count(root->channel_hints); j++) {
		curhint = &root->channel_hints[j];
		if (short_channel_id_eq(&curhint->scid.scid, &h->scid) &&
		    curhint->scid.dir == h->direction) {
			return curhint;
		}
	}
	return NULL;
}

/* Given a route and a couple of channel hints, apply the route to the channel
 * hints, so we have a better estimation of channel's capacity. We apply a
 * route to a channel hint before calling `sendonion` so subsequent `route`
 * calls don't accidentally try to use those out-of-date estimates. We unapply
 * if the payment failed, i.e., all HTLCs we might have added have been torn
 * down again. Finally we leave the update in place if the payment went
 * through, since the balances really changed in that case. The `remove`
 * argument indicates whether we want to apply (`remove=false`), or clear a
 * prior application (`remove=true`). */
static bool payment_chanhints_apply_route(struct payment *p, bool remove)
{
	bool apply;
	struct route_hop *curhop;
	struct channel_hint *curhint;
	struct payment *root = payment_root(p);
	assert(p->route != NULL);

	/* No need to check for applicability if we increase
	 * capacity and budgets. */
	if (remove)
		goto apply_changes;

	/* First round: make sure we can cleanly apply the update. */
	for (size_t i = 0; i < tal_count(p->route); i++) {
		curhop = &p->route[i];
		curhint = payment_chanhints_get(root, curhop);

		/* If we don't have a hint we can't fail updating it. */
		if (!curhint)
			continue;

		/* For local channels we check that we don't overwhelm
		 * them with too many HTLCs. */
		apply = (!curhint->local) || curhint->htlc_budget > 0;

		/* For all channels we check that they have a
		 * sufficiently large estimated capacity to have some
		 * chance of succeeding. */
		apply &= amount_msat_greater(curhint->estimated_capacity,
					     curhop->amount);

		if (!apply) {
			/* This can happen in case of multiple
			 * concurrent getroute calls using the
			 * same channel_hints, no biggy, it's
			 * an estimation anyway. */
			paymod_log(p, LOG_DBG,
				   "Could not update the channel hint "
				   "for %s. Could be a concurrent "
				   "`getroute` call.",
				   type_to_string(tmpctx,
						  struct short_channel_id_dir,
						  &curhint->scid));
			return false;
		}
	}

apply_changes:
	/* Second round: apply the changes, now that we know they'll succeed. */
	for (size_t i = 0; i < tal_count(p->route); i++) {
		curhop = &p->route[i];
		curhint = payment_chanhints_get(root, curhop);
		if (!curhint)
			continue;

		/* Update the number of htlcs for any local
		 * channel in the route */
		if (curhint->local && remove)
			curhint->htlc_budget++;
		else if (curhint->local)
			curhint->htlc_budget--;

		if (remove && !amount_msat_add(
			    &curhint->estimated_capacity,
			    curhint->estimated_capacity,
			    curhop->amount)) {
			/* This should never happen, it'd mean
			 * that we unapply a route that would
			 * result in a msatoshi
			 * wrap-around. */
			abort();
		} else if (!amount_msat_sub(
				   &curhint->estimated_capacity,
				   curhint->estimated_capacity,
				   curhop->amount)) {
			/* Given our preemptive test
			 * above, this should never
			 * happen either. */
			abort();
		}
	}
	return true;
}

static const struct short_channel_id_dir *
payment_get_excluded_channels(const tal_t *ctx, struct payment *p)
{
	struct payment *root = payment_root(p);
	struct channel_hint *hint;
	struct short_channel_id_dir *res =
	    tal_arr(ctx, struct short_channel_id_dir, 0);
	for (size_t i = 0; i < tal_count(root->channel_hints); i++) {
		hint = &root->channel_hints[i];

		if (!hint->enabled)
			tal_arr_expand(&res, hint->scid);

		else if (amount_msat_greater_eq(p->amount,
						hint->estimated_capacity))
			/* We exclude on equality because we've set the
			 * estimate to the smallest failed attempt. */
			tal_arr_expand(&res, hint->scid);

		else if (hint->local && hint->htlc_budget == 0)
			/* If we cannot add any HTLCs to the channel we
			 * shouldn't look for a route through that channel */
			tal_arr_expand(&res, hint->scid);
	}
	return res;
}

static const struct node_id *payment_get_excluded_nodes(const tal_t *ctx,
						  struct payment *p)
{
	struct payment *root = payment_root(p);
	return root->excluded_nodes;
}

/* FIXME: This is slow! */
static const struct channel_hint *find_hint(const struct channel_hint *hints,
					    const struct short_channel_id *scid,
					    int dir)
{
	for (size_t i = 0; i < tal_count(hints); i++) {
		if (short_channel_id_eq(scid, &hints[i].scid.scid)
		    && dir == hints[i].scid.dir)
			return &hints[i];
	}
	return NULL;
}

/* FIXME: This is slow! */
static bool dst_is_excluded(const struct gossmap *gossmap,
			    const struct gossmap_chan *c,
			    int dir,
			    const struct node_id *nodes)
{
	struct node_id dstid;

	/* Premature optimization */
	if (!tal_count(nodes))
		return false;

	gossmap_node_get_id(gossmap, gossmap_nth_node(gossmap, c, !dir),
			    &dstid);
	for (size_t i = 0; i < tal_count(nodes); i++) {
		if (node_id_eq(&dstid, &nodes[i]))
			return true;
	}
	return false;
}

static bool payment_route_check(const struct gossmap *gossmap,
				const struct gossmap_chan *c,
				int dir,
				struct amount_msat amount,
				struct payment *p)
{
	struct short_channel_id scid;
	const struct channel_hint *hint;

	if (dst_is_excluded(gossmap, c, dir, payment_root(p)->excluded_nodes))
		return false;

	if (dst_is_excluded(gossmap, c, dir, p->temp_exclusion))
		return false;

	scid = gossmap_chan_scid(gossmap, c);
	hint = find_hint(payment_root(p)->channel_hints, &scid, dir);
	if (!hint)
		return true;

	if (!hint->enabled)
		return false;

	if (amount_msat_greater_eq(amount, hint->estimated_capacity))
		/* We exclude on equality because we've set the
		 * estimate to the smallest failed attempt. */
		return false;

	if (hint->local && hint->htlc_budget == 0)
		/* If we cannot add any HTLCs to the channel we
		 * shouldn't look for a route through that channel */
		return false;

	return true;
}

static bool payment_route_can_carry(const struct gossmap *map,
				    const struct gossmap_chan *c,
				    int dir,
				    struct amount_msat amount,
				    struct payment *p)
{
	if (!route_can_carry(map, c, dir, amount, p))
		return false;

	return payment_route_check(map, c, dir, amount, p);
}

static bool payment_route_can_carry_even_disabled(const struct gossmap *map,
						  const struct gossmap_chan *c,
						  int dir,
						  struct amount_msat amount,
						  struct payment *p)
{
	if (!route_can_carry_even_disabled(map, c, dir, amount, p))
		return false;

	return payment_route_check(map, c, dir, amount, p);
}

static struct route_hop *route(const tal_t *ctx,
			       struct gossmap *gossmap,
			       const struct gossmap_node *src,
			       const struct gossmap_node *dst,
			       struct amount_msat amount,
			       u32 final_delay,
			       double riskfactor,
			       size_t max_hops,
			       struct payment *p,
			       const char **errmsg)
{
	const struct dijkstra *dij;
	struct route_hop *r;
	bool (*can_carry)(const struct gossmap *,
			  const struct gossmap_chan *,
			  int,
			  struct amount_msat,
			  struct payment *);

	can_carry = payment_route_can_carry;
	dij = dijkstra(tmpctx, gossmap, dst, amount, riskfactor,
		       can_carry, route_score_cheaper, p);
	r = route_from_dijkstra(ctx, gossmap, dij, src, amount, final_delay);
	if (!r) {
		/* Try using disabled channels too */
		/* FIXME: is there somewhere we can annotate this for paystatus? */
		can_carry = payment_route_can_carry_even_disabled;
		dij = dijkstra(ctx, gossmap, dst, amount, riskfactor,
			       can_carry, route_score_cheaper, p);
		r = route_from_dijkstra(ctx, gossmap, dij, src,
					amount, final_delay);
		if (!r) {
			*errmsg = "No path found";
			return NULL;
		}
	}

	/* If it's too far, fall back to using shortest path. */
	if (tal_count(r) > max_hops) {
		tal_free(r);
		/* FIXME: is there somewhere we can annotate this for paystatus? */
		dij = dijkstra(tmpctx, gossmap, dst, amount, riskfactor,
			       can_carry, route_score_shorter, p);
		r = route_from_dijkstra(ctx, gossmap, dij, src,
					amount, final_delay);
		if (!r) {
			*errmsg = "No path found";
			return NULL;
		}

		/* If it's still too far, fail. */
		if (tal_count(r) > max_hops) {
			*errmsg = tal_fmt(ctx, "Shortest path found was length %zu",
					  tal_count(r));
			return tal_free(r);
		}
	}

	return r;
}

static struct command_result *payment_getroute(struct payment *p)
{
	const struct gossmap_node *dst, *src;
	struct amount_msat fee;
	const char *errstr;
	struct gossmap *gossmap;

	gossmap = get_gossmap(p->plugin);

	dst = gossmap_find_node(gossmap, p->getroute->destination);
	if (!dst) {
		payment_fail(
			p, "Unknown destination %s",
			type_to_string(tmpctx, struct node_id,
				       p->getroute->destination));

		/* Let payment_finished_ handle this, so we mark it as pending */
		return command_still_pending(p->cmd);
	}

	/* If we don't exist in gossip, routing can't happen. */
	src = gossmap_find_node(gossmap, p->local_id);
	if (!src) {
		payment_fail(p, "We don't have any channels");

		/* Let payment_finished_ handle this, so we mark it as pending */
		return command_still_pending(p->cmd);
	}

	p->route = route(p, gossmap, src, dst, p->getroute->amount, p->getroute->cltv,
			 p->getroute->riskfactorppm / 1000000.0, p->getroute->max_hops,
			 p, &errstr);
	if (!p->route) {
		payment_fail(p, "%s", errstr);
		/* Let payment_finished_ handle this, so we mark it as pending */
		return command_still_pending(p->cmd);
	}

	/* OK, now we *have* a route */
	p->step = PAYMENT_STEP_GOT_ROUTE;

	if (tal_count(p->route) == 0) {
		payment_root(p)->abort = true;
		payment_fail(p, "Empty route returned by getroute, are you "
				"trying to pay yourself?");
	}

	fee = payment_route_fee(p);

	/* Ensure that our fee and CLTV budgets are respected. */
	if (amount_msat_greater(fee, p->constraints.fee_budget)) {
		payment_exclude_most_expensive(p);
		p->route = tal_free(p->route);
		payment_fail(
		    p, "Fee exceeds our fee budget: %s > %s, discarding route",
		    type_to_string(tmpctx, struct amount_msat, &fee),
		    type_to_string(tmpctx, struct amount_msat,
				   &p->constraints.fee_budget));
		return command_still_pending(p->cmd);
	}

	if (p->route[0].delay > p->constraints.cltv_budget) {
		u32 delay = p->route[0].delay;
		payment_exclude_longest_delay(p);
		p->route = tal_free(p->route);
		payment_fail(p, "CLTV delay exceeds our CLTV budget: %d > %d",
			     delay, p->constraints.cltv_budget);
		return command_still_pending(p->cmd);
	}

	/* Now update the constraints in fee_budget and cltv_budget so
	 * modifiers know what constraints they need to adhere to. */
	if (!payment_constraints_update(&p->constraints, fee, p->route[0].delay)) {
		paymod_log(p, LOG_BROKEN,
			   "Could not update constraints.");
		abort();
	}

	/* Allow modifiers to modify the route, before
	 * payment_compute_onion_payloads uses the route to generate the
	 * onion_payloads */
	payment_continue(p);
	return command_still_pending(p->cmd);
}

static u8 *tal_towire_legacy_payload(const tal_t *ctx, const struct legacy_payload *payload)
{
	const u8 padding[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			      0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	/* Prepend 0 byte for realm */
	u8 *buf = tal_arrz(ctx, u8, 1);
	towire_short_channel_id(&buf, &payload->scid);
	towire_amount_msat(&buf, payload->forward_amt);
	towire_u32(&buf, payload->outgoing_cltv);
	towire(&buf, padding, ARRAY_SIZE(padding));
	assert(tal_bytelen(buf) == 1 + 32);
	return buf;
}

static struct payment_result *tal_sendpay_result_from_json(const tal_t *ctx,
						    const char *buffer,
						    const jsmntok_t *toks)
{
	const jsmntok_t *idtok = json_get_member(buffer, toks, "id");
	const jsmntok_t *hashtok = json_get_member(buffer, toks, "payment_hash");
	const jsmntok_t *partidtok = json_get_member(buffer, toks, "partid");
	const jsmntok_t *senttok = json_get_member(buffer, toks, "amount_sent_msat");
	const jsmntok_t *statustok = json_get_member(buffer, toks, "status");
	const jsmntok_t *preimagetok = json_get_member(buffer, toks, "payment_preimage");
	const jsmntok_t *codetok = json_get_member(buffer, toks, "code");
	const jsmntok_t *datatok = json_get_member(buffer, toks, "data");
	const jsmntok_t *erridxtok, *msgtok, *failcodetok, *rawmsgtok,
		*failcodenametok, *errchantok, *errnodetok, *errdirtok;
	struct payment_result *result;

	/* Check if we have an error and need to descend into data to get
	 * details. */
	if (codetok != NULL && datatok != NULL) {
		idtok = json_get_member(buffer, datatok, "id");
		hashtok = json_get_member(buffer, datatok, "payment_hash");
		partidtok = json_get_member(buffer, datatok, "partid");
		senttok = json_get_member(buffer, datatok, "amount_sent_msat");
		statustok = json_get_member(buffer, datatok, "status");
	}

	/* Initial sanity checks, all these fields must exist. */
	if (idtok == NULL || idtok->type != JSMN_PRIMITIVE ||
	    hashtok == NULL || hashtok->type != JSMN_STRING ||
	    senttok == NULL || senttok->type != JSMN_STRING ||
	    statustok == NULL || statustok->type != JSMN_STRING) {
		return NULL;
	}

	result = tal(ctx, struct payment_result);

	if (codetok != NULL)
		json_to_u32(buffer, codetok, &result->code);
	else
		result->code = 0;

	/* If the partid is 0 it'd be omitted in waitsendpay, fix this here. */
	if (partidtok != NULL)
		json_to_u32(buffer, partidtok, &result->partid);
	else
		result->partid = 0;

	json_to_u64(buffer, idtok, &result->id);
	json_to_msat(buffer, senttok, &result->amount_sent);
	if (json_tok_streq(buffer, statustok, "pending")) {
		result->state = PAYMENT_PENDING;
	} else if (json_tok_streq(buffer, statustok, "complete")) {
		result->state = PAYMENT_COMPLETE;
	} else if (json_tok_streq(buffer, statustok, "failed")) {
		result->state = PAYMENT_FAILED;
	} else {
		goto fail;
	}

	if (preimagetok != NULL) {
		result->payment_preimage = tal(result, struct preimage);
		json_to_preimage(buffer, preimagetok, result->payment_preimage);
	}

	/* Now extract the error details if the error code is not 0 */
	if (result->code != 0) {
		erridxtok = json_get_member(buffer, datatok, "erring_index");
		errnodetok = json_get_member(buffer, datatok, "erring_node");
		errchantok = json_get_member(buffer, datatok, "erring_channel");
		errdirtok = json_get_member(buffer, datatok, "erring_direction");
		failcodetok = json_get_member(buffer, datatok, "failcode");
		failcodenametok =json_get_member(buffer, datatok, "failcodename");
		msgtok = json_get_member(buffer, toks, "message");
		rawmsgtok = json_get_member(buffer, datatok, "raw_message");
		if (failcodetok == NULL || failcodetok->type != JSMN_PRIMITIVE ||
		    (failcodenametok != NULL && failcodenametok->type != JSMN_STRING) ||
		    (erridxtok != NULL && erridxtok->type != JSMN_PRIMITIVE) ||
		    (errnodetok != NULL && errnodetok->type != JSMN_STRING) ||
		    (errchantok != NULL && errchantok->type != JSMN_STRING) ||
		    (errdirtok != NULL && errdirtok->type != JSMN_PRIMITIVE) ||
		    msgtok == NULL || msgtok->type != JSMN_STRING ||
		    (rawmsgtok != NULL && rawmsgtok->type != JSMN_STRING))
			goto fail;

		if (rawmsgtok != NULL)
			result->raw_message = json_tok_bin_from_hex(result, buffer, rawmsgtok);
		else
			result->raw_message = NULL;

		if (failcodenametok != NULL)
			result->failcodename = json_strdup(result, buffer, failcodenametok);
		else
			result->failcodename = NULL;

		json_to_u32(buffer, failcodetok, &result->failcode);
		result->message = json_strdup(result, buffer, msgtok);

		if (erridxtok != NULL) {
			result->erring_index = tal(result, u32);
			json_to_u32(buffer, erridxtok, result->erring_index);
		} else {
			result->erring_index = NULL;
		}

		if (errdirtok != NULL) {
			result->erring_direction = tal(result, int);
			json_to_int(buffer, errdirtok, result->erring_direction);
		} else {
			result->erring_direction = NULL;
		}

		if (errnodetok != NULL) {
			result->erring_node = tal(result, struct node_id);
			json_to_node_id(buffer, errnodetok,
					result->erring_node);
		} else {
			result->erring_node = NULL;
		}

		if (errchantok != NULL) {
			result->erring_channel =
			    tal(result, struct short_channel_id);
			json_to_short_channel_id(buffer, errchantok,
						 result->erring_channel);
		} else {
			result->erring_channel = NULL;
		}
	}

	return result;
fail:
	return tal_free(result);
}

/* Try to infer the erring_node, erring_channel and erring_direction from what
 * we know, but don't override the values that are returned by `waitsendpay`.  */
static void payment_result_infer(struct route_hop *route,
				 struct payment_result *r)
{
	int i, len;
	assert(r != NULL);

	if (r->code == 0 || r->erring_index == NULL || route == NULL)
		return;

	len = tal_count(route);
	i = *r->erring_index;
	assert(i <= len);

	if (r->erring_node == NULL)
		r->erring_node = &route[i-1].node_id;

	/* The above assert was enough for the erring_node, but might be off
	 * by one on channel and direction, in case the destination failed on
	 * us. */
	if (i == len)
		return;

	if (r->erring_channel == NULL)
		r->erring_channel = &route[i].scid;

	if (r->erring_direction == NULL)
		r->erring_direction = &route[i].direction;
}

/* If a node takes too much fee or cltv, the next one reports it.  We don't
 * know who to believe, but log it */
static void report_tampering(struct payment *p,
			     size_t report_pos,
			     const char *style)
{
	const struct node_id *id = &p->route[report_pos].node_id;

	if (report_pos == 0) {
		paymod_log(p, LOG_UNUSUAL,
			   "Node #%zu (%s) claimed we sent them invalid %s",
			   report_pos + 1,
			   type_to_string(tmpctx, struct node_id, id),
			   style);
	} else {
		paymod_log(p, LOG_UNUSUAL,
			   "Node #%zu (%s) claimed #%zu (%s) sent them invalid %s",
			   report_pos + 1,
			   type_to_string(tmpctx, struct node_id, id),
			   report_pos,
			   type_to_string(tmpctx, struct node_id,
					  &p->route[report_pos-1].node_id),
			   style);
	}
}

static bool
failure_is_blockheight_disagreement(const struct payment *p,
				    u32 *blockheight)
{
	struct amount_msat unused;

	assert(p && p->result);

	if (p->result->failcode == 17 /* Former final_expiry_too_soon */)
		*blockheight = p->start_block + 1;
	else if (!fromwire_incorrect_or_unknown_payment_details(
			p->result->raw_message,
			&unused, blockheight))
		/* If it's incorrect_or_unknown_payment_details, that tells us
		 * what height they're at */
		return false;

	/* If we are already at the desired blockheight there is no point in
	 * waiting, and it is likely just some other error. Notice that
	 * start_block gets set by the initial getinfo call for each
	 * attempt.*/
	if (*blockheight <= p->start_block)
		return false;

	return true;
}

static char *describe_failcode(const tal_t *ctx, enum onion_wire failcode)
{
	char *rv = tal_strdup(ctx, "");
	if (failcode & BADONION) {
		tal_append_fmt(&rv, "BADONION|");
		failcode &= ~BADONION;
	}
	if (failcode & PERM) {
		tal_append_fmt(&rv, "PERM|");
		failcode &= ~PERM;
	}
	if (failcode & NODE) {
		tal_append_fmt(&rv, "NODE|");
		failcode &= ~NODE;
	}
	if (failcode & UPDATE) {
		tal_append_fmt(&rv, "UPDATE|");
		failcode &= ~UPDATE;
	}
	tal_append_fmt(&rv, "%u", failcode);
	return rv;
}

static struct command_result *
handle_final_failure(struct command *cmd,
		     struct payment *p,
		     const struct node_id *final_id,
		     enum onion_wire failcode)
{
	u32 unused;

	/* Need to check for blockheight disagreement case here,
	 * otherwise we would set the abort flag too eagerly.
	 */
	if (failure_is_blockheight_disagreement(p, &unused)) {
		paymod_log(p, LOG_DBG,
			   "Blockheight disagreement, not aborting.");
		goto nonerror;
	}

	paymod_log(p, LOG_DBG,
		   "Final node %s reported %04x (%s) on route %s",
		   type_to_string(tmpctx, struct node_id, final_id),
		   failcode, onion_wire_name(failcode),
		   p->routetxt);

	/* We use an exhaustive switch statement here so you get a compile
	 * warning when new ones are added, and can think about where they go */
	switch (failcode) {
	case WIRE_FINAL_INCORRECT_CLTV_EXPIRY:
		report_tampering(p, tal_count(p->route)-1, "cltv");
		goto error;
	case WIRE_FINAL_INCORRECT_HTLC_AMOUNT:
		report_tampering(p, tal_count(p->route)-1, "amount");
		goto error;

	/* BOLT #4:
	 *
	 * A _forwarding node_ MAY, but a _final node_ MUST NOT:
	 *...
	 *     - return an `invalid_onion_version` error.
	 *...
	 *     - return an `invalid_onion_hmac` error.
	 *...
	 *     - return an `invalid_onion_key` error.
	 *...
	 *     - return a `temporary_channel_failure` error.
	 *...
	 *     - return a `permanent_channel_failure` error.
	 *...
	 *     - return a `required_channel_feature_missing` error.
	 *...
	 *     - return an `unknown_next_peer` error.
	 *...
	 *     - return an `amount_below_minimum` error.
	 *...
	 *     - return a `fee_insufficient` error.
	 *...
	 *     - return an `incorrect_cltv_expiry` error.
	 *...
	 *     - return an `expiry_too_soon` error.
	 *...
	 *     - return an `expiry_too_far` error.
	 *...
	 *     - return a `channel_disabled` error.
	 */
	case WIRE_INVALID_ONION_VERSION:
	case WIRE_INVALID_ONION_HMAC:
	case WIRE_INVALID_ONION_KEY:
	case WIRE_TEMPORARY_CHANNEL_FAILURE:
	case WIRE_PERMANENT_CHANNEL_FAILURE:
	case WIRE_REQUIRED_CHANNEL_FEATURE_MISSING:
	case WIRE_UNKNOWN_NEXT_PEER:
	case WIRE_AMOUNT_BELOW_MINIMUM:
	case WIRE_FEE_INSUFFICIENT:
	case WIRE_INCORRECT_CLTV_EXPIRY:
	case WIRE_EXPIRY_TOO_FAR:
	case WIRE_EXPIRY_TOO_SOON:
	case WIRE_CHANNEL_DISABLED:
		goto strange_error;

	case WIRE_INVALID_ONION_PAYLOAD:
	case WIRE_INVALID_REALM:
	case WIRE_PERMANENT_NODE_FAILURE:
	case WIRE_TEMPORARY_NODE_FAILURE:
	case WIRE_REQUIRED_NODE_FEATURE_MISSING:
#if EXPERIMENTAL_FEATURES
	case WIRE_INVALID_ONION_BLINDING:
#endif
 	case WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS:
	case WIRE_MPP_TIMEOUT:
		goto error;
	}

strange_error:
	paymod_log(p, LOG_UNUSUAL,
		   "Final node %s reported strange error code %04x (%s)",
		   type_to_string(tmpctx, struct node_id, final_id),
		   failcode, describe_failcode(tmpctx, failcode));

error:
	p->result->code = PAY_DESTINATION_PERM_FAIL;
	payment_root(p)->abort = true;

nonerror:
	payment_fail(p, "%s", p->result->message);
	return command_still_pending(cmd);

}


static struct command_result *
handle_intermediate_failure(struct command *cmd,
			    struct payment *p,
			    const struct node_id *errnode,
			    const struct route_hop *errchan,
			    enum onion_wire failcode)
{
	struct payment *root = payment_root(p);

	paymod_log(p, LOG_DBG,
		   "Intermediate node %s reported %04x (%s) at %s on route %s",
		   type_to_string(tmpctx, struct node_id, errnode),
		   failcode, onion_wire_name(failcode),
		   type_to_string(tmpctx, struct short_channel_id,
				  &errchan->scid),
		   p->routetxt);

	/* We use an exhaustive switch statement here so you get a compile
	 * warning when new ones are added, and can think about where they go */
	switch (failcode) {
	/* BOLT #4:
	 *
	 * An _intermediate hop_ MUST NOT, but the _final node_:
	 *...
	 *     - MUST return an `incorrect_or_unknown_payment_details` error.
	 *...
	 *     - MUST return `final_incorrect_cltv_expiry` error.
	 *...
	 *     - MUST return a `final_incorrect_htlc_amount` error.
	 */
 	case WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS:
 	case WIRE_FINAL_INCORRECT_CLTV_EXPIRY:
 	case WIRE_FINAL_INCORRECT_HTLC_AMOUNT:
	/* FIXME: Document in BOLT that intermediates must not return this! */
	case WIRE_MPP_TIMEOUT:
		goto strange_error;

	case WIRE_PERMANENT_CHANNEL_FAILURE:
	case WIRE_CHANNEL_DISABLED:
	case WIRE_UNKNOWN_NEXT_PEER:
	case WIRE_REQUIRED_CHANNEL_FEATURE_MISSING:
		/* All of these result in the channel being marked as disabled. */
		channel_hints_update(root, errchan->scid,
				     errchan->direction, false, false, NULL,
				     NULL);
		break;

	case WIRE_TEMPORARY_CHANNEL_FAILURE: {
		/* These are an indication that the capacity was insufficient,
		 * remember the amount we tried as an estimate. */
		channel_hints_update(root, errchan->scid,
				     errchan->direction, true, false,
				     &errchan->amount, NULL);
		goto error;
	}

	case WIRE_INCORRECT_CLTV_EXPIRY:
		report_tampering(p, errchan - p->route, "cltv");
		goto error;

	case WIRE_INVALID_ONION_VERSION:
	case WIRE_INVALID_ONION_HMAC:
	case WIRE_INVALID_ONION_KEY:
	case WIRE_PERMANENT_NODE_FAILURE:
	case WIRE_TEMPORARY_NODE_FAILURE:
	case WIRE_REQUIRED_NODE_FEATURE_MISSING:
	case WIRE_INVALID_ONION_PAYLOAD:
	case WIRE_INVALID_REALM:
#if EXPERIMENTAL_FEATURES
	case WIRE_INVALID_ONION_BLINDING:
#endif
		tal_arr_expand(&root->excluded_nodes, *errnode);
		goto error;

	case WIRE_AMOUNT_BELOW_MINIMUM:
	case WIRE_FEE_INSUFFICIENT:
	case WIRE_EXPIRY_TOO_FAR:
	case WIRE_EXPIRY_TOO_SOON:
		goto error;
	}

strange_error:
	paymod_log(p, LOG_UNUSUAL,
		   "Intermediate node %s reported strange error code %04x (%s)",
		   type_to_string(tmpctx, struct node_id, errnode),
		   failcode, describe_failcode(tmpctx, failcode));

error:
	payment_fail(p, "%s", p->result->message);
	return command_still_pending(cmd);
}

/* From the docs:
 *
 * - *erring_index*: The index of the node along the route that
 *   reported the error. 0 for the local node, 1 for the first hop,
 *   and so on.
 *
 * The only difficulty is mapping the erring_index to the correct hop.
 * We split into the erring node, and the error channel, since they're
 * used in different contexts. NULL error_channel means it's the final
 * node, whose errors are treated differently.
 */
static bool assign_blame(const struct payment *p,
			 const struct node_id **errnode,
			 const struct route_hop **errchan)
{
	int index;

	if (p->result->erring_index == NULL)
		return false;

	index = *p->result->erring_index;

	/* BADONION errors are reported on behalf of the next node. */
	if (p->result->failcode & BADONION)
		index++;

	/* Final node *shouldn't* report BADONION, but don't assume. */
	if (index >= tal_count(p->route)) {
		*errchan = NULL;
		*errnode = &p->route[tal_count(p->route) - 1].node_id;
		return true;
	}

	*errchan = &p->route[index];
	if (index == 0)
		*errnode = p->local_id;
	else
		*errnode = &p->route[index - 1].node_id;
	return true;
}

/* Fix up the channel_update to include the type if it doesn't currently have
 * one. See ElementsProject/lightning#1730 and lightningnetwork/lnd#1599 for the
 * in-depth discussion on why we break message parsing here... */
static u8 *patch_channel_update(const tal_t *ctx, u8 *channel_update TAKES)
{
	u8 *fixed;
	if (channel_update != NULL &&
	    fromwire_peektype(channel_update) != WIRE_CHANNEL_UPDATE) {
		/* This should be a channel_update, prefix with the
		 * WIRE_CHANNEL_UPDATE type, but isn't. Let's prefix it. */
		fixed = tal_arr(ctx, u8, 0);
		towire_u16(&fixed, WIRE_CHANNEL_UPDATE);
		towire(&fixed, channel_update, tal_bytelen(channel_update));
		if (taken(channel_update))
			tal_free(channel_update);
		return fixed;
	} else {
		return tal_dup_talarr(ctx, u8, channel_update);
	}
}

/* Return NULL if the wrapped onion error message has no channel_update field,
 * or return the embedded channel_update message otherwise. */
static u8 *channel_update_from_onion_error(const tal_t *ctx,
					   const u8 *onion_message)
{
	u8 *channel_update = NULL;
	struct amount_msat unused_msat;
	u32 unused32;

	/* Identify failcodes that have some channel_update.
	 *
	 * TODO > BOLT 1.0: Add new failcodes when updating to a
	 * new BOLT version. */
	if (!fromwire_temporary_channel_failure(ctx,
						onion_message,
						&channel_update) &&
	    !fromwire_amount_below_minimum(ctx,
					   onion_message, &unused_msat,
					   &channel_update) &&
	    !fromwire_fee_insufficient(ctx,
		    		       onion_message, &unused_msat,
				       &channel_update) &&
	    !fromwire_incorrect_cltv_expiry(ctx,
		    			    onion_message, &unused32,
					    &channel_update) &&
	    !fromwire_expiry_too_soon(ctx,
		    		      onion_message,
				      &channel_update))
		/* No channel update. */
		return NULL;

	return patch_channel_update(ctx, take(channel_update));
}


static struct command_result *
payment_addgossip_success(struct command *cmd, const char *buffer,
			  const jsmntok_t *toks, struct payment *p)
{
	const struct node_id *errnode;
	const struct route_hop *errchan;

	if (!assign_blame(p, &errnode, &errchan)) {
		paymod_log(p, LOG_UNUSUAL,
			   "No erring_index set in `waitsendpay` result: %.*s",
			   json_tok_full_len(toks),
			   json_tok_full(buffer, toks));
		/* FIXME: Pick a random channel to fail? */
		payment_set_step(p, PAYMENT_STEP_FAILED);
		payment_continue(p);
		return command_still_pending(cmd);
	}

	if (!errchan)
		return handle_final_failure(cmd, p, errnode,
					    p->result->failcode);

	return handle_intermediate_failure(cmd, p, errnode, errchan,
					   p->result->failcode);
}

/* If someone gives us an invalid update, all we can do is log it */
static struct command_result *
payment_addgossip_failure(struct command *cmd, const char *buffer,
			  const jsmntok_t *toks, struct payment *p)
{
	paymod_log(p, LOG_DBG, "Invalid channel_update: %.*s",
		   json_tok_full_len(toks),
		   json_tok_full(buffer, toks));

	return payment_addgossip_success(cmd, NULL, NULL, p);
}

static struct command_result *
payment_waitsendpay_finished(struct command *cmd, const char *buffer,
			     const jsmntok_t *toks, struct payment *p)
{
	u8 *update;

	assert(p->route != NULL);

	p->end_time = time_now();
	p->result = tal_sendpay_result_from_json(p, buffer, toks);

	if (p->result == NULL) {
		paymod_log(p, LOG_UNUSUAL,
			   "Unable to parse `waitsendpay` result: %.*s",
			   json_tok_full_len(toks),
			   json_tok_full(buffer, toks));
		payment_set_step(p, PAYMENT_STEP_FAILED);
		payment_continue(p);
		return command_still_pending(cmd);
	}

	payment_result_infer(p->route, p->result);

	if (p->result->state == PAYMENT_COMPLETE) {
		payment_set_step(p, PAYMENT_STEP_SUCCESS);
		payment_continue(p);
		return command_still_pending(cmd);
	}

	payment_chanhints_apply_route(p, true);

	/* Tell gossipd, if we received an update */
	update = channel_update_from_onion_error(tmpctx, p->result->raw_message);
	if (update) {
		struct out_req *req;
		paymod_log(p, LOG_DBG,
			   "Extracted channel_update %s from onionreply %s",
			   tal_hex(tmpctx, update),
			   tal_hex(tmpctx, p->result->raw_message));
		req = jsonrpc_request_start(p->plugin, NULL, "addgossip",
					    payment_addgossip_success,
					    payment_addgossip_failure, p);
		json_add_hex_talarr(req->js, "message", update);
		send_outreq(p->plugin, req);
		return command_still_pending(cmd);
	}

	return payment_addgossip_success(cmd, NULL, NULL, p);
}

static struct command_result *payment_sendonion_success(struct command *cmd,
							  const char *buffer,
							  const jsmntok_t *toks,
							  struct payment *p)
{
	struct out_req *req;
	req = jsonrpc_request_start(p->plugin, NULL, "waitsendpay",
				    payment_waitsendpay_finished,
				    payment_waitsendpay_finished, p);
	json_add_sha256(req->js, "payment_hash", p->payment_hash);
	json_add_num(req->js, "partid", p->partid);
	send_outreq(p->plugin, req);

	return command_still_pending(cmd);
}

static struct command_result *payment_createonion_success(struct command *cmd,
							  const char *buffer,
							  const jsmntok_t *toks,
							  struct payment *p)
{
	struct out_req *req;
	struct route_hop *first = &p->route[0];
	struct secret *secrets;

	p->createonion_response = json_to_createonion_response(p, buffer, toks);

	req = jsonrpc_request_start(p->plugin, NULL, "sendonion",
				    payment_sendonion_success,
				    payment_rpc_failure, p);
	json_add_hex_talarr(req->js, "onion", p->createonion_response->onion);

	json_object_start(req->js, "first_hop");
	json_add_short_channel_id(req->js, "channel", &first->scid);
	json_add_num(req->js, "direction", first->direction);
	json_add_amount_msat_only(req->js, "amount_msat", first->amount);
	json_add_num(req->js, "delay", first->delay);
	json_add_node_id(req->js, "id", &first->node_id);
	json_object_end(req->js);

	json_add_sha256(req->js, "payment_hash", p->payment_hash);
	json_add_amount_msat_only(req->js, "msatoshi", p->amount);

	json_array_start(req->js, "shared_secrets");
	secrets = p->createonion_response->shared_secrets;
	for(size_t i=0; i<tal_count(secrets); i++)
		json_add_secret(req->js, NULL, &secrets[i]);
	json_array_end(req->js);

	json_add_num(req->js, "partid", p->partid);

	if (p->label)
		json_add_string(req->js, "label", p->label);

	if (p->invstring)
		/* FIXME: rename parameter to invstring */
		json_add_string(req->js, "bolt11", p->invstring);

	if (p->destination)
		json_add_node_id(req->js, "destination", p->destination);

	if (p->local_offer_id)
		json_add_sha256(req->js, "localofferid", p->local_offer_id);

	send_outreq(p->plugin, req);
	return command_still_pending(cmd);
}

/* Temporary serialization method for the tlv_payload.data until we rework the
 * API that is generated from the specs to use the setter/getter interface. */
static void tlvstream_set_tlv_payload_data(struct tlv_field **stream,
					   struct secret *payment_secret,
					   u64 total_msat)
{
	u8 *ser = tal_arr(NULL, u8, 0);
	towire_secret(&ser, payment_secret);
	towire_tu64(&ser, total_msat);
	tlvstream_set_raw(stream, TLV_TLV_PAYLOAD_PAYMENT_DATA, ser, tal_bytelen(ser));
	tal_free(ser);
}

static void payment_add_hop_onion_payload(struct payment *p,
					  struct createonion_hop *dst,
					  struct route_hop *node,
					  struct route_hop *next,
					  bool final,
					  bool force_tlv,
					  struct secret *payment_secret)
{
	struct createonion_request *cr = p->createonion_request;
	u32 cltv = p->start_block + next->delay + 1;
	u64 msat = next->amount.millisatoshis; /* Raw: TLV payload generation*/
	struct tlv_field **fields;
	struct payment *root = payment_root(p);
	static struct short_channel_id all_zero_scid = {.u64 = 0};

	/* This is the information of the node processing this payload, while
	 * `next` are the instructions to include in the payload, which is
	 * basically the channel going to the next node. */
	dst->style = node->style;
	if (force_tlv)
		dst->style = ROUTE_HOP_TLV;
	dst->pubkey = node->node_id;

	switch (dst->style) {
	case ROUTE_HOP_LEGACY:
		dst->legacy_payload = tal(cr->hops, struct legacy_payload);
		dst->legacy_payload->forward_amt = next->amount;

		if (!final)
			dst->legacy_payload->scid = next->scid;
		else
			dst->legacy_payload->scid = all_zero_scid;

		dst->legacy_payload->outgoing_cltv = cltv;
		break;
	case ROUTE_HOP_TLV:
		dst->tlv_payload = tlv_tlv_payload_new(cr->hops);
		fields = &dst->tlv_payload->fields;
		tlvstream_set_tu64(fields, TLV_TLV_PAYLOAD_AMT_TO_FORWARD,
				   msat);
		tlvstream_set_tu32(fields, TLV_TLV_PAYLOAD_OUTGOING_CLTV_VALUE,
				   cltv);

		if (!final)
			tlvstream_set_short_channel_id(fields,
						       TLV_TLV_PAYLOAD_SHORT_CHANNEL_ID,
						       &next->scid);

		if (payment_secret != NULL) {
			assert(final);
			tlvstream_set_tlv_payload_data(
			    fields, payment_secret,
			    root->amount.millisatoshis); /* Raw: TLV payload generation*/
		}
		break;
	}
}

static void payment_compute_onion_payloads(struct payment *p)
{
	struct createonion_request *cr;
	size_t hopcount;
	struct payment *root = payment_root(p);
	char *routetxt = tal_strdup(tmpctx, "");

	p->step = PAYMENT_STEP_ONION_PAYLOAD;
	hopcount = tal_count(p->route);

	/* Now that we are about to fix the route parameters by
	 * encoding them in an onion is the right time to update the
	 * channel hints. */
	if (!payment_chanhints_apply_route(p, false)) {
		/* We can still end up with a failed channel_hints
		 * update, either because a plugin changed the route,
		 * or because a modifier was not synchronous, allowing
		 * for multiple concurrent routes being built. If that
		 * is the case, discard this route and retry. */
		payment_set_step(p, PAYMENT_STEP_RETRY_GETROUTE);
		return payment_continue(p);
	}

	/* Now compute the payload we're about to pass to `createonion` */
	cr = p->createonion_request = tal(p, struct createonion_request);
	cr->assocdata = tal_arr(cr, u8, 0);
	towire_sha256(&cr->assocdata, p->payment_hash);
	cr->session_key = NULL;
	cr->hops = tal_arr(cr, struct createonion_hop, tal_count(p->route));

	/* Non-final hops */
	for (size_t i = 0; i < hopcount - 1; i++) {
		/* The message is destined for hop i, but contains fields for
		 * i+1 */
		payment_add_hop_onion_payload(p, &cr->hops[i], &p->route[i],
					      &p->route[i + 1], false, false,
					      NULL);
		tal_append_fmt(&routetxt, "%s -> ",
			       type_to_string(tmpctx, struct short_channel_id,
					      &p->route[i].scid));
	}

	/* Final hop */
	payment_add_hop_onion_payload(
	    p, &cr->hops[hopcount - 1], &p->route[hopcount - 1],
	    &p->route[hopcount - 1], true, root->destination_has_tlv,
	    root->payment_secret);
	tal_append_fmt(&routetxt, "%s",
		       type_to_string(tmpctx, struct short_channel_id,
				      &p->route[hopcount - 1].scid));

	paymod_log(p, LOG_DBG,
		   "Created outgoing onion for route: %s", routetxt);

	p->routetxt = tal_steal(p, routetxt);

	/* Now allow all the modifiers to mess with the payloads, before we
	 * serialize via a call to createonion in the next step. */
	payment_continue(p);
}

static void payment_sendonion(struct payment *p)
{
	struct out_req *req;
	u8 *payload, *tlv;
	req = jsonrpc_request_start(p->plugin, NULL, "createonion",
				    payment_createonion_success,
				    payment_rpc_failure, p);

	json_array_start(req->js, "hops");
	for (size_t i = 0; i < tal_count(p->createonion_request->hops); i++) {
		json_object_start(req->js, NULL);
		struct createonion_hop *hop = &p->createonion_request->hops[i];
		json_add_node_id(req->js, "pubkey", &hop->pubkey);
		if (hop->style == ROUTE_HOP_LEGACY) {
			payload = tal_towire_legacy_payload(tmpctx, hop->legacy_payload);
			json_add_hex_talarr(req->js, "payload", payload);
		}else {
			tlv = tal_arr(tmpctx, u8, 0);
			towire_tlvstream_raw(&tlv, hop->tlv_payload->fields);
			payload = tal_arr(tmpctx, u8, 0);
			towire_bigsize(&payload, tal_bytelen(tlv));
			towire(&payload, tlv, tal_bytelen(tlv));
			json_add_hex_talarr(req->js, "payload", payload);
			tal_free(tlv);
		}
		tal_free(payload);
		json_object_end(req->js);
	}
	json_array_end(req->js);

	json_add_hex_talarr(req->js, "assocdata",
			    p->createonion_request->assocdata);

	if (p->createonion_request->session_key)
		json_add_secret(req->js, "sessionkey",
				p->createonion_request->session_key);

	send_outreq(p->plugin, req);
}

/* Mutual recursion. */
static void payment_finished(struct payment *p);

/* A payment is finished if a) it is in a final state, of b) it's in a
 * child-spawning state and all of its children are in a final state. */
static bool payment_is_finished(const struct payment *p)
{
top:
	if (p->step == PAYMENT_STEP_FAILED || p->step == PAYMENT_STEP_SUCCESS || p->abort)
		return true;
	else if (p->step == PAYMENT_STEP_SPLIT || p->step == PAYMENT_STEP_RETRY) {
		size_t num_children = tal_count(p->children);

		/* Retry case will almost always have just one child, so avoid
		 * the overhead of pushing and popping off the C stack and
		 * tail-recurse manually.  */
		if (num_children == 1) {
			p = p->children[0];
			goto top;
		}

		for (size_t i = 0; i < num_children; i++)
			/* In other words: if any child is unfinished,
			 * we are unfinished.  */
			if (!payment_is_finished(p->children[i]))
				return false;
		return true;
	} else {
		return false;
	}
}

static enum payment_step payment_aggregate_states(struct payment *p)
{
	enum payment_step agg = p->step;

	for (size_t i=0; i<tal_count(p->children); i++)
		agg |= payment_aggregate_states(p->children[i]);

	return agg;
}

/* A payment is finished if a) it is in a final state, of b) it's in a
 * child-spawning state and all of its children are in a final state. */
static bool payment_is_success(struct payment *p)
{
	return (payment_aggregate_states(p) & PAYMENT_STEP_SUCCESS) != 0;
}

/* Function to bubble up completions to the root, which actually holds on to
 * the command that initiated the flow. */
static void payment_child_finished(struct payment *p,
						     struct payment *child)
{
	if (!payment_is_finished(p))
		return;

	/* Should we continue bubbling up? */
	payment_finished(p);
}

static void payment_add_attempt(struct json_stream *s, const char *fieldname, struct payment *p, bool recurse)
{
	bool finished = p->step >= PAYMENT_STEP_RETRY,
	     success = p->step == PAYMENT_STEP_SUCCESS;

	/* A fieldname is only reasonable if we're not recursing. Otherwise the
	 * fieldname would be reused for all attempts. */
	assert(!recurse || fieldname == NULL);

	json_object_start(s, fieldname);

	if (!finished)
		json_add_string(s, "status", "pending");
	else if (success)
		json_add_string(s, "status", "success");
	else
		json_add_string(s, "status", "failed");

	if (p->failreason != NULL)
		json_add_string(s, "failreason", p->failreason);

	json_add_u64(s, "partid", p->partid);
	json_add_amount_msat_only(s, "amount", p->amount);
	if (p->parent != NULL)
		json_add_u64(s, "parent_partid", p->parent->partid);

	json_object_end(s);
	for (size_t i=0; i<tal_count(p->children); i++) {
		payment_add_attempt(s, fieldname, p->children[i], recurse);
	}
}

static void payment_json_add_attempts(struct json_stream *s,
				      const char *fieldname, struct payment *p)
{
	assert(p == payment_root(p));
	json_array_start(s, fieldname);
	payment_add_attempt(s, NULL, p, true);
	json_array_end(s);
}

static void payment_notify_failure(struct payment *p, const char *error_message)
{
	struct payment *root = payment_root(p);
	struct json_stream *n;

	n = plugin_notification_start(p->plugin, "pay_failure");
	json_add_sha256(n, "payment_hash", p->payment_hash);
	if (root->invstring != NULL)
		json_add_string(n, "bolt11", root->invstring);

	json_object_start(n, "error");
	json_add_string(n, "message", error_message);
	json_object_end(n); /* .error */

	plugin_notification_end(p->plugin, n);
}

/* This function is called whenever a payment ends up in a final state, or all
 * leafs in the subtree rooted in the payment are all in a final state. It is
 * called only once, and it is guaranteed to be called in post-order
 * traversal, i.e., all children are finished before the parent is called. */
static void payment_finished(struct payment *p)
{
	struct payment_tree_result result = payment_collect_result(p);
	struct json_stream *ret;
	struct command *cmd = p->cmd;
	const char *msg;
	struct json_stream *n;
	struct payment *root = payment_root(p);

	/* Either none of the leaf attempts succeeded yet, or we have a
	 * preimage. */
	assert((result.leafstates & PAYMENT_STEP_SUCCESS) == 0 ||
	       result.preimage != NULL);

	if (p->parent == NULL) {
		/* We are about to reply, unset the pointer to the cmd so we
		 * don't attempt to return a response twice. */
		p->cmd = NULL;
		if (cmd == NULL) {
			/* This is the tree root, but we already reported
			 * success or failure, so noop. */
			return;
		} else if (payment_is_success(p)) {
			assert(result.treestates & PAYMENT_STEP_SUCCESS);
			assert(result.leafstates & PAYMENT_STEP_SUCCESS);
			assert(result.preimage != NULL);

			ret = jsonrpc_stream_success(cmd);
			json_add_node_id(ret, "destination", p->destination);
			json_add_sha256(ret, "payment_hash", p->payment_hash);
			json_add_timeabs(ret, "created_at", p->start_time);
			json_add_num(ret, "parts", result.attempts);

			json_add_amount_msat_compat(ret, p->amount, "msatoshi",
						    "amount_msat");
			json_add_amount_msat_compat(ret, result.sent,
						    "msatoshi_sent",
						    "amount_sent_msat");

			if (result.leafstates != PAYMENT_STEP_SUCCESS)
				json_add_string(
				    ret, "warning_partial_completion",
				    "Some parts of the payment are not yet "
				    "completed, but we have the confirmation "
				    "from the recipient.");
			json_add_preimage(ret, "payment_preimage", result.preimage);

			json_add_string(ret, "status", "complete");

			n = plugin_notification_start(p->plugin, "pay_success");
			json_add_sha256(n, "payment_hash", p->payment_hash);
			if (root->invstring != NULL)
				json_add_string(n, "bolt11", root->invstring);
			plugin_notification_end(p->plugin, n);

			if (command_finished(cmd, ret)) {/* Ignore result. */}
			return;
		} else if (p->aborterror != NULL) {
			/* We set an explicit toplevel error message,
			 * so let's report that. */
			ret = jsonrpc_stream_fail(cmd, PAY_STOPPED_RETRYING,
						  p->aborterror);
			payment_json_add_attempts(ret, "attempts", p);

			payment_notify_failure(p, p->aborterror);

			if (command_finished(cmd, ret)) {/* Ignore result. */}
			return;
		} else if (result.failure == NULL || result.failure->failcode < NODE) {
			/* This is failing because we have no more routes to try */
			msg = tal_fmt(cmd,
				      "Ran out of routes to try after "
				      "%d attempt%s: see `paystatus`",
				      result.attempts,
				      result.attempts == 1 ? "" : "s");
			ret = jsonrpc_stream_fail(cmd, PAY_STOPPED_RETRYING,
						  msg);
			payment_json_add_attempts(ret, "attempts", p);

			payment_notify_failure(p, msg);

			if (command_finished(cmd, ret)) {/* Ignore result. */}
			return;

		}  else {
			struct payment_result *failure = result.failure;
			assert(failure!= NULL);
			ret = jsonrpc_stream_fail(cmd, failure->code,
						  failure->message);

			json_add_u64(ret, "id", failure->id);

			json_add_u32(ret, "failcode", failure->failcode);
			json_add_string(ret, "failcodename",
					failure->failcodename);

			if (p->invstring)
				json_add_invstring(ret, p->invstring);

			json_add_hex_talarr(ret, "raw_message",
					    result.failure->raw_message);
			json_add_num(ret, "created_at", p->start_time.ts.tv_sec);
			json_add_node_id(ret, "destination", p->destination);
			json_add_sha256(ret, "payment_hash", p->payment_hash);

			if (result.leafstates & PAYMENT_STEP_SUCCESS) {
				/* If one sub-payment succeeded then we have
				 * proof of payment, and the payment is a
				 * success. */
				json_add_string(ret, "status", "complete");

			} else if (result.leafstates & ~PAYMENT_FAILED) {
				/* If there are non-failed leafs we are still trying. */
				json_add_string(ret, "status", "pending");

			} else {
				json_add_string(ret, "status", "failed");
			}

			json_add_amount_msat_compat(ret, p->amount, "msatoshi",
						    "amount_msat");

			json_add_amount_msat_compat(ret, result.sent,
						    "msatoshi_sent",
						    "amount_sent_msat");

			if (failure != NULL) {
				if (failure->erring_index)
					json_add_num(ret, "erring_index",
						     *failure->erring_index);

				if (failure->erring_node)
					json_add_node_id(ret, "erring_node",
							 failure->erring_node);

				if (failure->erring_channel)
					json_add_short_channel_id(
					    ret, "erring_channel",
					    failure->erring_channel);

				if (failure->erring_direction)
					json_add_num(
					    ret, "erring_direction",
					    *failure->erring_direction);
			}

			payment_notify_failure(p, failure->message);

			if (command_finished(cmd, ret)) { /* Ignore result. */}
			return;
		}
	} else {
		payment_child_finished(p->parent, p);
		return;
	}
}

void payment_set_step(struct payment *p, enum payment_step newstep)
{
	p->current_modifier = -1;
	p->step = newstep;

	/* Any final state needs an end_time */
	if (p->step >= PAYMENT_STEP_SPLIT)
		p->end_time = time_now();
}

void payment_continue(struct payment *p)
{
	struct payment_modifier *mod;
	void *moddata;
	/* If we are in the middle of calling the modifiers, continue calling
	 * them, otherwise we can continue with the payment state-machine. */
	p->current_modifier++;
	mod = p->modifiers[p->current_modifier];

	if (mod != NULL) {
		/* There is another modifier, so call it. */
		moddata = p->modifier_data[p->current_modifier];
		return mod->post_step_cb(moddata, p);
	} else {
		/* There are no more modifiers, so reset the call chain and
		 * proceed to the next state. */
		p->current_modifier = -1;
		switch (p->step) {
		case PAYMENT_STEP_INITIALIZED:
		case PAYMENT_STEP_RETRY_GETROUTE:
			payment_getroute(p);
			return;

		case PAYMENT_STEP_GOT_ROUTE:
			payment_compute_onion_payloads(p);
			return;

		case PAYMENT_STEP_ONION_PAYLOAD:
			payment_sendonion(p);
			return;

		case PAYMENT_STEP_SUCCESS:
		case PAYMENT_STEP_FAILED:
			payment_finished(p);
			return;

		case PAYMENT_STEP_RETRY:
		case PAYMENT_STEP_SPLIT:
			/* Do nothing, we'll get pinged by a child succeeding
			 * or failing. */
			return;
		}
	}
	/* We should never get here, it'd mean one of the state machine called
	 * `payment_continue` after the final state. */
	abort();
}

void payment_abort(struct payment *p, const char *fmt, ...) {
	va_list ap;
	struct payment *root = payment_root(p);
	payment_set_step(p, PAYMENT_STEP_FAILED);
	p->end_time = time_now();

	va_start(ap, fmt);
	p->failreason = tal_vfmt(p, fmt, ap);
	va_end(ap);

	root->abort = true;

	/* Only set the abort error if it's not yet set, otherwise we
	 * might end up clobbering the earliest and decisive failure
	 * with less relevant ones. */
	if (root->aborterror == NULL)
		root->aborterror = tal_dup_talarr(root, char, p->failreason);

	paymod_log(p, LOG_INFORM, "%s", p->failreason);

	/* Do not use payment_continue, because that'd continue
	 * applying the modifiers before calling
	 * payment_finished(). */
	payment_finished(p);
}

void payment_fail(struct payment *p, const char *fmt, ...)
{
	va_list ap;
	p->end_time = time_now();
	payment_set_step(p, PAYMENT_STEP_FAILED);
	va_start(ap, fmt);
	p->failreason = tal_vfmt(p, fmt, ap);
	va_end(ap);

	paymod_log(p, LOG_INFORM, "%s", p->failreason);

	payment_continue(p);
}

void *payment_mod_get_data(const struct payment *p,
			   const struct payment_modifier *mod)
{
	for (size_t i = 0; p->modifiers[i] != NULL; i++)
		if (p->modifiers[i] == mod)
			return p->modifier_data[i];

	/* If we ever get here it means that we asked for the data for a
	 * non-existent modifier. This is a compile-time/wiring issue, so we
	 * better check that modifiers match the data we ask for. */
	abort();
}

static struct retry_mod_data *retry_data_init(struct payment *p);

static inline void retry_step_cb(struct retry_mod_data *rd,
				 struct payment *p);

static struct retry_mod_data *
retry_data_init(struct payment *p)
{
	struct retry_mod_data *rdata = tal(p, struct retry_mod_data);
	struct retry_mod_data *parent_rdata;

	/* We start the retry counter from scratch for the root payment, or if
	 * the parent was split, meaning this is a new attempt with new
	 * amounts. */
	if (p->parent == NULL || p->parent->step == PAYMENT_STEP_SPLIT) {
		rdata->retries = 10;
	} else {
		parent_rdata = payment_mod_retry_get_data(p->parent);
		rdata->retries = parent_rdata->retries - 1;
	}
	return rdata;
}

/* Determine whether retrying could possibly succeed. Retrying in this case
 * means that we repeat the entire flow, including computing a new route, new
 * payload and a new sendonion call. It does not mean we retry the exact same
 * attempt that just failed. */
static bool payment_can_retry(struct payment *p)
{
	struct payment_result *res = p->result;
	u32 idx;
	bool is_final;

	if (p->result == NULL)
		return p->failroute_retry;

	idx = res->erring_index != NULL ? *res->erring_index : 0;
	is_final = (idx == tal_count(p->route));

	/* Full matrix of failure code x is_final. Prefer to retry once too
	 * often over eagerly failing. */
	switch (res->failcode) {
	case WIRE_EXPIRY_TOO_FAR:
	case WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS:
	case WIRE_INVALID_ONION_PAYLOAD:
	case WIRE_INVALID_ONION_VERSION:
	case WIRE_INVALID_REALM:
	case WIRE_MPP_TIMEOUT:
	case WIRE_PERMANENT_NODE_FAILURE:
	case WIRE_REQUIRED_NODE_FEATURE_MISSING:
	case WIRE_TEMPORARY_NODE_FAILURE:
	case WIRE_UNKNOWN_NEXT_PEER:
		return !is_final;

	case WIRE_AMOUNT_BELOW_MINIMUM:
	case WIRE_CHANNEL_DISABLED:
	case WIRE_EXPIRY_TOO_SOON:
	case WIRE_FEE_INSUFFICIENT:
	case WIRE_FINAL_INCORRECT_CLTV_EXPIRY:
	case WIRE_FINAL_INCORRECT_HTLC_AMOUNT:
	case WIRE_INCORRECT_CLTV_EXPIRY:
	case WIRE_INVALID_ONION_HMAC:
	case WIRE_INVALID_ONION_KEY:
	case WIRE_PERMANENT_CHANNEL_FAILURE:
	case WIRE_REQUIRED_CHANNEL_FEATURE_MISSING:
	case WIRE_TEMPORARY_CHANNEL_FAILURE:
#if EXPERIMENTAL_FEATURES
	case WIRE_INVALID_ONION_BLINDING:
#endif
		return true;
	}

	/* We should never get here, otherwise the above `switch` isn't
	 * exhaustive. Nevertheless the failcode is provided by the erring
	 * node, so retry anyway. `abort()`ing on externally supplied info is
	 * not a good idea. */
	return true;
}

static inline void retry_step_cb(struct retry_mod_data *rd,
				 struct payment *p)
{
	struct payment *subpayment, *root = payment_root(p);
	struct retry_mod_data *rdata = payment_mod_retry_get_data(p);
	struct timeabs now = time_now();

	if (p->step != PAYMENT_STEP_FAILED)
		return payment_continue(p);

	if (time_after(now, p->deadline)) {
		paymod_log(
		    p, LOG_INFORM,
		    "Payment deadline expired, not retrying (partial-)payment "
		    "%s/%d",
		    type_to_string(tmpctx, struct sha256, p->payment_hash),
		    p->partid);
		root->abort = true;
		return payment_continue(p);
	}

	/* If we failed to find a route, it's unlikely we can suddenly find a
	 * new one without any other changes, so it's time to give up. */
	if (p->route == NULL && !p->failroute_retry)
		return payment_continue(p);

	/* If the root is marked as abort, we do not retry anymore */
	if (payment_root(p)->abort)
		return payment_continue(p);

	if (!payment_can_retry(p))
		return payment_continue(p);

	/* If the failure was not final, and we tried a route, try again. */
	if (rdata->retries > 0) {
		payment_set_step(p, PAYMENT_STEP_RETRY);
		subpayment = payment_new(p, NULL, p, p->modifiers);
		payment_start(subpayment);
		subpayment->why =
		    tal_fmt(subpayment, "Still have %d attempts left",
			    rdata->retries - 1);
		paymod_log(
		    p, LOG_DBG,
		    "Retrying %s/%d (%s), new partid %d. %d attempts left\n",
		    type_to_string(tmpctx, struct sha256, p->payment_hash),
		    p->partid,
		    type_to_string(tmpctx, struct amount_msat, &p->amount),
		    subpayment->partid,
		    rdata->retries - 1);
	}

	payment_continue(p);
}

REGISTER_PAYMENT_MODIFIER(retry, struct retry_mod_data *, retry_data_init,
			  retry_step_cb);

static struct command_result *
local_channel_hints_listpeers(struct command *cmd, const char *buffer,
			      const jsmntok_t *toks, struct payment *p)
{
	const jsmntok_t *peers, *peer, *channels, *channel, *spendsats, *scid,
	    *dir, *connected, *max_htlc, *htlcs;
	size_t i, j;
	peers = json_get_member(buffer, toks, "peers");

	if (peers == NULL)
		goto done;
        /* cppcheck-suppress uninitvar - cppcheck can't undestand these macros. */
	json_for_each_arr(i, peer, peers) {
		channels = json_get_member(buffer, peer, "channels");
		if (channels == NULL)
			continue;

		connected = json_get_member(buffer, peer, "connected");

		json_for_each_arr(j, channel, channels) {
			struct channel_hint h;
			spendsats = json_get_member(buffer, channel, "spendable_msat");
			scid = json_get_member(buffer, channel, "short_channel_id");
			dir = json_get_member(buffer, channel, "direction");
			max_htlc = json_get_member(buffer, channel, "max_accepted_htlcs");
			htlcs = json_get_member(buffer, channel, "htlcs");
			if (spendsats == NULL || scid == NULL || dir == NULL ||
			    max_htlc == NULL ||
			    max_htlc->type != JSMN_PRIMITIVE || htlcs == NULL ||
			    htlcs->type != JSMN_ARRAY)
				continue;

			json_to_bool(buffer, connected, &h.enabled);
			json_to_short_channel_id(buffer, scid, &h.scid.scid);
			json_to_int(buffer, dir, &h.scid.dir);

			json_to_msat(buffer, spendsats, &h.estimated_capacity);

			/* Take the configured number of max_htlcs and
			 * subtract any HTLCs that might already be added to
			 * the channel. This is a best effort estimate and
			 * mostly considers stuck htlcs, concurrent payments
			 * may throw us off a bit. */
			json_to_u16(buffer, max_htlc, &h.htlc_budget);
			h.htlc_budget -= htlcs->size;
			h.local = true;

			channel_hints_update(p, h.scid.scid, h.scid.dir,
					     h.enabled, true, &h.estimated_capacity, &h.htlc_budget);
		}
	}

done:
	payment_continue(p);
	return command_still_pending(cmd);
}

static void local_channel_hints_cb(void *d UNUSED, struct payment *p)
{
	struct out_req *req;
	/* If we are not the root we don't look up the channel balances since
	 * it is unlikely that the capacities have changed much since the root
	 * payment looked at them. We also only call `listpeers` when the
	 * payment is in state PAYMENT_STEP_INITIALIZED, right before calling
	 * `getroute`. */
	if (p->parent != NULL || p->step != PAYMENT_STEP_INITIALIZED)
		return payment_continue(p);

	req = jsonrpc_request_start(p->plugin, NULL, "listpeers",
				    local_channel_hints_listpeers,
				    local_channel_hints_listpeers, p);
	send_outreq(p->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(local_channel_hints, void *, NULL, local_channel_hints_cb);

/* Trim route to this length by taking from the *front* of route
 * (end points to destination, so we need that bit!) */
static void trim_route(struct route_info **route, size_t n)
{
	size_t remove = tal_count(*route) - n;
	memmove(*route, *route + remove, sizeof(**route) * n);
	tal_resize(route, n);
}

/* Make sure routehints are reasonable length, and (since we assume we
 * can append), not directly to us.  Note: untrusted data! */
static struct route_info **filter_routehints(struct gossmap *map,
					     struct payment *p,
					     struct routehints_data *d,
					     struct node_id *myid,
					     struct route_info **hints)
{
	const size_t max_hops = ROUTING_MAX_HOPS / 2;
	char *mods = tal_strdup(tmpctx, "");
	for (size_t i = 0; i < tal_count(hints); i++) {
		struct gossmap_node *entrynode, *src;
		u32 distance;

		/* Trim any routehint > 10 hops */
		if (tal_count(hints[i]) > max_hops) {
			tal_append_fmt(&mods,
				       "Trimmed routehint %zu (%zu hops) to %zu. ",
				       i, tal_count(hints[i]), max_hops);
			trim_route(&hints[i], max_hops);
		}

		/* If we are first hop, trim. */
		if (tal_count(hints[i]) > 0
		    && node_id_eq(&hints[i][0].pubkey, myid)) {
			tal_append_fmt(&mods,
				       "Removed ourselves from routehint %zu. ",
				       i);
			trim_route(&hints[i], tal_count(hints[i])-1);
		}

		/* If route is empty, remove altogether. */
		if (tal_count(hints[i]) == 0) {
			tal_append_fmt(&mods,
				       "Removed empty routehint %zu. ", i);
			tal_arr_remove(&hints, i);
			i--;
			continue;
		}

		/* If routehint entrypoint is unreachable there's no
		 * point in keeping it. */
		entrynode = gossmap_find_node(map, &hints[i][0].pubkey);
		src = gossmap_find_node(map, p->local_id);

		if (entrynode == NULL) {
			tal_append_fmt(&mods,
				       "Removed routehint %zu because "
				       "entrypoint %s is unknown. ",
				       i,
				       type_to_string(tmpctx, struct node_id,
						      &hints[i][0].pubkey));
			plugin_log(p->plugin, LOG_DBG,
				   "Removed routehint %zu because "
				   "entrypoint %s is unknown. ",
				   i,
				   type_to_string(tmpctx, struct node_id,
						  &hints[i][0].pubkey));
			tal_arr_remove(&hints, i);
			i--;
			continue;
		}

		distance = dijkstra_distance(
		    dijkstra(tmpctx, map, entrynode, AMOUNT_MSAT(1), 1,
			     payment_route_can_carry_even_disabled,
			     route_score_cheaper, p),
		    gossmap_node_idx(map, src));

		if (distance == UINT_MAX) {
			tal_append_fmt(&mods,
				       "Removed routehint %zu because "
				       "entrypoint %s is unreachable. ",
				       i,
				       type_to_string(tmpctx, struct node_id,
						      &hints[i][0].pubkey));
			plugin_log(p->plugin, LOG_DBG,
				       "Removed routehint %zu because "
				       "entrypoint %s is unreachable. ",
				       i,
				       type_to_string(tmpctx, struct node_id,
						      &hints[i][0].pubkey));
			tal_arr_remove(&hints, i);
			i--;
		}
	}

	if (!streq(mods, ""))
		d->routehint_modifications = tal_steal(d, mods);

	return tal_steal(d, hints);
}

static bool route_msatoshi(struct amount_msat *total,
			   const struct amount_msat msat,
			   const struct route_info *route, size_t num_route);

static bool routehint_excluded(struct payment *p,
			       const struct route_info *routehint)
{
	const struct node_id *nodes = payment_get_excluded_nodes(tmpctx, p);
	const struct short_channel_id_dir *chans =
	    payment_get_excluded_channels(tmpctx, p);
	const struct channel_hint *hints = payment_root(p)->channel_hints;

	/* Note that we ignore direction here: in theory, we could have
	 * found that one direction of a channel is unavailable, but they
	 * are suggesting we use it the other way.  Very unlikely though! */
	for (size_t i = 0; i < tal_count(routehint); i++) {
		const struct route_info *r = &routehint[i];
		for (size_t j = 0; j < tal_count(nodes); j++)
			if (node_id_eq(&r->pubkey, &nodes[j]))
			    return true;

		for (size_t j = 0; j < tal_count(chans); j++)
			if (short_channel_id_eq(&chans[j].scid, &r->short_channel_id))
				return true;

		/* Skip the capacity check if this is the last hop
		 * in the routehint.
		 * The last hop in the routehint delivers the exact
		 * final amount to the destination, which
		 * payment_get_excluded_channels uses for excluding
		 * already.
		 * Thus, the capacity check below only really matters
		 * for multi-hop routehints.
		 */
		if (i == tal_count(routehint) - 1)
			continue;

		/* Check our capacity fits.  */
		struct amount_msat needed_capacity;
		if (!route_msatoshi(&needed_capacity, p->amount,
				    r + 1, tal_count(routehint) - i - 1))
			return true;
		/* Why do we scan the hints again if
		 * payment_get_excluded_channels already does?
		 * Because payment_get_excluded_channels checks the
		 * amount at destination, but we know that we are
		 * a specific distance from the destination and we
		 * know the exact capacity we need to send via this
		 * channel, which is greater than the destination.
		 */
		for (size_t j = 0; j < tal_count(hints); j++) {
			if (!short_channel_id_eq(&hints[j].scid.scid, &r->short_channel_id))
				continue;
			/* We exclude on equality because we set the estimate
			 * to the smallest failed attempt.  */
			if (amount_msat_greater_eq(needed_capacity,
						   hints[j].estimated_capacity))
				return true;
		}
	}
	return false;
}

static struct route_info *next_routehint(struct routehints_data *d,
					     struct payment *p)
{
	size_t numhints = tal_count(d->routehints);
	struct route_info *curr;

	if (d->routehints == NULL || numhints == 0)
		return NULL;

	/* BOLT #11:
	 *
	 *   - if a writer offers more than one of any field type, it:
	 *     - MUST specify the most-preferred field first, followed
	 *       by less-preferred fields, in order.
	 */
	for (; d->offset < numhints; d->offset++) {
		curr = d->routehints[(d->base + d->offset) % numhints];
		if (curr == NULL || !routehint_excluded(p, curr))
			return curr;
	}
	return NULL;
}

/* Calculate how many millisatoshi we need at the start of this route
 * to get msatoshi to the end. */
static bool route_msatoshi(struct amount_msat *total,
			   const struct amount_msat msat,
			   const struct route_info *route, size_t num_route)
{
	*total = msat;
	for (ssize_t i = num_route - 1; i >= 0; i--) {
		if (!amount_msat_add_fee(total,
					 route[i].fee_base_msat,
					 route[i].fee_proportional_millionths))
			return false;
	}
	return true;
}

/* The pubkey to use is the destination of this routehint. */
static const struct node_id *route_pubkey(const struct payment *p,
					  const struct route_info *routehint,
					  size_t n)
{
	if (n == tal_count(routehint))
		return p->destination;
	return &routehint[n].pubkey;
}

static u32 route_cltv(u32 cltv,
		      const struct route_info *route, size_t num_route)
{
	for (size_t i = 0; i < num_route; i++)
		cltv += route[i].cltv_expiry_delta;
	return cltv;
}

/** routehint_generate_exclusion_list
 *
 * @brief generate a list of items to append to `excludes`
 * parameter of `getroute`.
 *
 * @param ctx - the context to allocate off of.
 * @param routehint - the actual routehint, a `tal` array.
 * @param payment - the payment that we will create an
 * exclusion list for.
 *
 * @return an array of strings that will be appended to the
 * `excludes` parameter of `getroute`.
 */
static
struct node_id *routehint_generate_exclusion_list(const tal_t *ctx,
						  struct route_info *routehint,
						  struct payment *payment)
{
	struct node_id *exc;

	if (!routehint || tal_count(routehint) == 0)
		/* Nothing to exclude.  */
		return NULL;

	exc = tal_arr(ctx, struct node_id, tal_count(routehint));
	/* Exclude every node except the first, because the first is
	 * the entry point to the routehint.  */
	for (size_t i = 1 /* Skip the first! */; i < tal_count(routehint); ++i)
		exc[i-1] = routehint[i].pubkey;

	/* Also exclude the destination, because it would be foolish to
	 * pass through it and *then* go to the routehint entry point.  */
	exc[tal_count(routehint)-1] = *payment->destination;
	return exc;
}

/* Change the destination and compute the final msatoshi amount to send to the
 * routehint entry point. */
static void routehint_pre_getroute(struct routehints_data *d, struct payment *p)
{
	bool have_more;
	d->current_routehint = next_routehint(d, p);

	/* Signal that we could retry with another routehint even if getroute
	 * fails. */
	have_more = (d->offset < tal_count(d->routehints) - 1);
	p->failroute_retry = have_more;

	p->temp_exclusion = tal_free(p->temp_exclusion);

	if (d->current_routehint != NULL) {
		if (!route_msatoshi(&p->getroute->amount, p->amount,
				    d->current_routehint,
				    tal_count(d->current_routehint))) {
		}
		d->final_cltv = p->getroute->cltv;
		p->getroute->destination = &d->current_routehint[0].pubkey;
		p->getroute->cltv =
		    route_cltv(p->getroute->cltv, d->current_routehint,
			       tal_count(d->current_routehint));
		paymod_log(
		    p, LOG_DBG, "Using routehint %s (%s) cltv_delta=%d",
		    type_to_string(tmpctx, struct node_id,
				   &d->current_routehint->pubkey),
		    type_to_string(tmpctx, struct short_channel_id,
				   &d->current_routehint->short_channel_id),
		    d->current_routehint->cltv_expiry_delta);

		/* Exclude the entrypoint to the routehint, so we don't end up
		 * going through the destination to the entrypoint. */
		p->temp_exclusion = routehint_generate_exclusion_list(p, d->current_routehint, p);
	} else
		paymod_log(p, LOG_DBG, "Not using a routehint");
}

static void routehint_check_reachable(struct payment *p)
{
	const struct gossmap_node *dst, *src;
	struct gossmap *gossmap = get_gossmap(p->plugin);
	const struct dijkstra *dij;
	struct route_hop *r;
	struct payment *root = payment_root(p);
	struct routehints_data *d = payment_mod_routehints_get_data(root);

	/* Start a tiny exploratory route computation, so we know
	 * whether we stand any chance of reaching the destination
	 * without routehints. This will later be used to mix in
	 * attempts without routehints. */
	src = gossmap_find_node(gossmap, p->local_id);
	dst = gossmap_find_node(gossmap, p->destination);
	if (dst == NULL)
		d->destination_reachable = false;
	else {
		dij = dijkstra(tmpctx, gossmap, dst, AMOUNT_MSAT(1000),
			       10 / 1000000.0,
			       payment_route_can_carry_even_disabled,
			       route_score_cheaper, p);
		r = route_from_dijkstra(tmpctx, gossmap, dij, src,
					AMOUNT_MSAT(1000), 0);

		/* If there was a route the destination is reachable
		 * without routehints. */
		d->destination_reachable = r != NULL;
	}

	if (d->destination_reachable) {
		tal_arr_expand(&d->routehints, NULL);
		/* The above could trigger a realloc.
		 * However, p->routes and d->routehints are
		 * actually the same array, so we need to update the
		 * p->routes pointer, since the realloc
		 * might have changed pointer addresses, in order to
		 * ensure that the pointers are not stale.
		 */
		p->routes = d->routehints;

		/* FIXME: ***DO*** we need to add this extra routehint?
		 * Once we run out of routehints the default system will
		 * just attempt directly routing to the destination anyway.  */
	} else if (tal_count(d->routehints) == 0) {
		/* If we don't have any routehints and the destination
		 * isn't reachable, then there is no point in
		 * continuing. */

		payment_abort(
		    p,
		    "Destination %s is not reachable directly and "
		    "all routehints were unusable.",
		    type_to_string(tmpctx, struct node_id, p->destination));
		return;
	}

	routehint_pre_getroute(d, p);

	paymod_log(p, LOG_DBG,
		   "The destination is%s directly reachable %s attempts "
		   "without routehints",
		   d->destination_reachable ? "" : " not",
		   d->destination_reachable ? "including" : "excluding");

	/* Now we can continue on our merry way. */
	payment_continue(p);
}

static void routehint_step_cb(struct routehints_data *d, struct payment *p)
{
	struct route_hop hop;
	const struct payment *root = payment_root(p);
	struct gossmap *map;
	if (p->step == PAYMENT_STEP_INITIALIZED) {
		if (root->routes == NULL)
			return payment_continue(p);

		/* We filter out non-functional routehints once at the
		 * beginning, and every other payment will filter out the
		 * exluded ones on the fly. */
		if (p->parent == NULL) {
			map = get_gossmap(p->plugin);
			d->routehints = filter_routehints(
			    map, p, d, p->local_id, p->routes);
			/* filter_routehints modifies the array, but
			 * this could trigger a resize and the resize
			 * could trigger a realloc.
			 * Keep the invoice pointer up-to-date.
			 * FIXME: We should really consider that if we are
			 * mutating p->routes, maybe we should
			 * drop d->routehints and just use p->routes
			 * directly.
			 * It is probably not a good idea to *copy* the
			 * routehints: other paymods are interested in
			 * p->routes, and if the routehints system
			 * itself adds or removes routehints from its
			 * copy, the *actual* number of routehints that we
			 * end up using is the one that the routehints paymod
			 * is maintaining and traversing, and it is *that*
			 * set of routehints that is the important one.
			 * So rather than copying the array of routehints
			 * in paymod, paymod should use (and mutate) the
			 * p->routes array, and
			 */
			p->routes = d->routehints;

			paymod_log(p, LOG_DBG,
				   "After filtering routehints we're left with "
				   "%zu usable hints",
				   tal_count(d->routehints));
			    /* Do not continue normally, instead go and check if
			     * we can reach the destination directly. */
			    return routehint_check_reachable(p);
		}

		routehint_pre_getroute(d, p);
	} else if (p->step == PAYMENT_STEP_GOT_ROUTE && d->current_routehint != NULL) {
		/* Now it's time to stitch the two partial routes together. */
		struct amount_msat dest_amount;
		struct route_info *routehint = d->current_routehint;
		struct route_hop *prev_hop;
		for (ssize_t i = 0; i < tal_count(routehint); i++) {
			prev_hop = &p->route[tal_count(p->route)-1];
			if (!route_msatoshi(&dest_amount, p->amount,
				    routehint + i + 1,
					    tal_count(routehint) - i - 1)) {
				/* Just let it fail, since we couldn't stitch
				 * the routes together. */
				return payment_continue(p);
			}

			hop.node_id = *route_pubkey(p, routehint, i + 1);
			hop.style = ROUTE_HOP_LEGACY;
			hop.scid = routehint[i].short_channel_id;
			hop.amount = dest_amount;
			hop.delay = route_cltv(d->final_cltv, routehint + i + 1,
					       tal_count(routehint) - i - 1);

			/* Should we get a failure inside the routehint we'll
			 * need the direction so we can exclude it. Luckily
			 * it's rather easy to compute given the two
			 * subsequent hops. */
			hop.direction =
			    node_id_cmp(&prev_hop->node_id, &hop.node_id) > 0 ? 1
									    : 0;
			tal_arr_expand(&p->route, hop);
		}
	}

	payment_continue(p);
}

static struct routehints_data *routehint_data_init(struct payment *p)
{
	struct routehints_data *pd, *d = tal(p, struct routehints_data);
	/* If for some reason we skipped the getroute call (directpay) we'll
	 * need this to be initialized. */
	d->current_routehint = NULL;
	if (p->parent != NULL) {
		pd = payment_mod_routehints_get_data(payment_root(p));
		d->destination_reachable = pd->destination_reachable;
		d->routehints = pd->routehints;
		pd = payment_mod_routehints_get_data(p->parent);
		if (p->parent->step == PAYMENT_STEP_RETRY) {
			d->base = pd->base;
			d->offset = pd->offset;
			/* If the previous try failed to route, advance
			 * to the next routehint.  */
			if (!p->parent->route)
				++d->offset;
		} else {
			size_t num_routehints = tal_count(d->routehints);
			d->offset = 0;
			/* This used to be pseudorand.
			 *
			 * However, it turns out that using the partid for
			 * this payment has some nice properties.
			 * The partid is in general quite random, due to
			 * getting entropy from the network on the timing
			 * of when payments complete/fail, and the routehint
			 * randomization is not a privacy or security feature,
			 * only a reliability one, thus does not need a lot
			 * of entropy.
			 *
			 * But the most important bit is that *splits get
			 * contiguous partids*, e.g. a presplit into 4 will
			 * usually be numbered 2,3,4,5, and an adaptive split
			 * will get two consecutive partid.
			 * Because of the contiguity, using the partid for
			 * the base will cause the split-up payments to
			 * have fairly diverse initial routehints.
			 *
			 * The special-casing for <= 2 and the - 2 is due
			 * to the presplitter skipping over partid 1, we want
			 * the starting splits to have partid 2 start at
			 * base 0.
			 */
			if (p->partid <= 2 || num_routehints <= 1)
				d->base = 0;
			else
				d->base = (p->partid - 2) % num_routehints;
		}
		return d;
	} else {
		/* We defer the actual initialization of the routehints array to
		 * the step callback when we have the invoice attached. */
		d->routehints = NULL;
		d->base = 0;
		d->offset = 0;
		return d;
	}
	return d;
}

REGISTER_PAYMENT_MODIFIER(routehints, struct routehints_data *,
			  routehint_data_init, routehint_step_cb);

/* For tiny payments the fees incurred due to the fixed base_fee may dominate
 * the overall cost of the payment. Since these payments are often used as a
 * way to signal, rather than actually transfer the amount, we add an
 * exemption that allows tiny payments to exceed the fee allowance. This is
 * implemented by setting a larger allowance than we would normally do if the
 * payment is below the threshold. */

static struct exemptfee_data *exemptfee_data_init(struct payment *p)
{
	if (p->parent == NULL) {
		struct exemptfee_data *d = tal(p, struct exemptfee_data);
		d->amount = AMOUNT_MSAT(5000);
		return d;
	} else {
		return payment_mod_exemptfee_get_data(p->parent);
	}
}

static void exemptfee_cb(struct exemptfee_data *d, struct payment *p)
{
	if (p->step != PAYMENT_STEP_INITIALIZED || p->parent != NULL)
		return payment_continue(p);

	if (amount_msat_greater_eq(d->amount, p->constraints.fee_budget)) {
		paymod_log(
		    p, LOG_INFORM,
		    "Payment fee constraint %s is below exemption threshold, "
		    "allowing a maximum fee of %s",
		    type_to_string(tmpctx, struct amount_msat, &p->constraints.fee_budget),
		    type_to_string(tmpctx, struct amount_msat, &d->amount));
		p->constraints.fee_budget = d->amount;
		p->start_constraints->fee_budget = d->amount;
	}
	return payment_continue(p);
}

REGISTER_PAYMENT_MODIFIER(exemptfee, struct exemptfee_data *,
			  exemptfee_data_init, exemptfee_cb);

/* BOLT #7:
 *
 * If a route is computed by simply routing to the intended recipient and
 * summing the `cltv_expiry_delta`s, then it's possible for intermediate nodes
 * to guess their position in the route. Knowing the CLTV of the HTLC, the
 * surrounding network topology, and the `cltv_expiry_delta`s gives an
 * attacker a way to guess the intended recipient. Therefore, it's highly
 * desirable to add a random offset to the CLTV that the intended recipient
 * will receive, which bumps all CLTVs along the route.
 *
 * In order to create a plausible offset, the origin node MAY start a limited
 * random walk on the graph, starting from the intended recipient and summing
 * the `cltv_expiry_delta`s, and use the resulting sum as the offset.  This
 * effectively creates a _shadow route extension_ to the actual route and
 * provides better protection against this attack vector than simply picking a
 * random offset would.
 */

static struct shadow_route_data *shadow_route_init(struct payment *p)
{
	struct shadow_route_data *d = tal(p, struct shadow_route_data), *pd;

	/* If we're not the root we need to inherit the flags set only on the
	 * root payment. Since we inherit them at each step it's sufficient to
	 * do so from our direct parent. */
	if (p->parent != NULL) {
		pd = payment_mod_shadowroute_get_data(p->parent);
		d->fuzz_amount = pd->fuzz_amount;
#if DEVELOPER
		d->use_shadow = pd->use_shadow;
#endif
	} else {
		d->fuzz_amount = true;
	}
	return d;
}

/* Mutual recursion */
static struct command_result *shadow_route_listchannels(struct command *cmd,
							const char *buf,
							const jsmntok_t *result,
							struct payment *p);

static struct command_result *shadow_route_extend(struct shadow_route_data *d,
						  struct payment *p)
{
	struct out_req *req;
	req = jsonrpc_request_start(p->plugin, NULL, "listchannels",
				    shadow_route_listchannels,
				    payment_rpc_failure, p);
	json_add_string(req->js, "source",
			type_to_string(req, struct node_id, &d->destination));
	return send_outreq(p->plugin, req);
}

static struct command_result *shadow_route_listchannels(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *result,
					       struct payment *p)
{
	struct shadow_route_data *d = payment_mod_shadowroute_get_data(p);
	struct payment_constraints *cons = &d->constraints;
	struct route_info *best = NULL;
	double total_weight = 0.0;
	size_t i;
	struct amount_msat best_fee;
	const jsmntok_t *sattok, *delaytok, *basefeetok, *propfeetok, *desttok,
		*channelstok, *chan, *scidtok;

	/* Check the invariants on the constraints between payment and modifier. */
	assert(d->constraints.cltv_budget <= p->constraints.cltv_budget / 4);
	assert(amount_msat_greater_eq(p->constraints.fee_budget,
				      d->constraints.fee_budget));

	channelstok = json_get_member(buf, result, "channels");
	json_for_each_arr(i, chan, channelstok) {
		struct route_info curr;
		struct amount_sat capacity;
		struct amount_msat fee;

		sattok = json_get_member(buf, chan, "satoshis");
		delaytok = json_get_member(buf, chan, "delay");
		basefeetok = json_get_member(buf, chan, "base_fee_millisatoshi");
		propfeetok = json_get_member(buf, chan, "fee_per_millionth");
		scidtok =  json_get_member(buf, chan, "short_channel_id");
		desttok =  json_get_member(buf, chan, "destination");

		if (sattok == NULL || delaytok == NULL ||
		    delaytok->type != JSMN_PRIMITIVE || basefeetok == NULL ||
		    basefeetok->type != JSMN_PRIMITIVE || propfeetok == NULL ||
		    propfeetok->type != JSMN_PRIMITIVE || desttok == NULL ||
		    scidtok == NULL)
			continue;

		json_to_u16(buf, delaytok, &curr.cltv_expiry_delta);
		json_to_number(buf, basefeetok, &curr.fee_base_msat);
		json_to_number(buf, propfeetok,
			       &curr.fee_proportional_millionths);
		json_to_short_channel_id(buf, scidtok, &curr.short_channel_id);
		json_to_sat(buf, sattok, &capacity);
		json_to_node_id(buf, desttok, &curr.pubkey);

		/* If the capacity is insufficient to pass the amount
		 * it's not a plausible extension. */
		if (amount_msat_greater_sat(p->amount, capacity))
			continue;

		if (curr.cltv_expiry_delta > cons->cltv_budget)
			continue;

		if (!amount_msat_fee(
			    &fee, p->amount, curr.fee_base_msat,
			    curr.fee_proportional_millionths)) {
			/* Fee computation failed... */
			continue;
		}

		if (amount_msat_greater_eq(fee, cons->fee_budget))
			continue;

		if (random_select(1.0, &total_weight)) {
			best = tal_dup(tmpctx, struct route_info, &curr);
			best_fee = fee;
		}
	}

	if (best != NULL) {
		/* Check that we could apply the shadow route extension. Check
		 * against both the shadow route budget as well as the
		 * original payment's budget. */
		if (best->cltv_expiry_delta > d->constraints.cltv_budget ||
		    best->cltv_expiry_delta > p->constraints.cltv_budget) {
			best = NULL;
			goto next;
		}

		/* Check the fee budget only if we didn't opt out, since
		 * testing against a virtual budget is not useful if we do not
		 * actually use it (it could give false positives and fail
		 * attempts that might have gone through, */
		if (d->fuzz_amount &&
		    (amount_msat_greater(best_fee, d->constraints.fee_budget) ||
		     (amount_msat_greater(best_fee,
					  p->constraints.fee_budget)))) {
			best = NULL;
			goto next;
		}

		/* Now we can be sure that adding the shadow route will succeed */
		paymod_log(
		    p, LOG_DBG,
		    "Adding shadow_route hop over channel %s: adding %s "
		    "in fees and %d CLTV delta",
		    type_to_string(tmpctx, struct short_channel_id,
				   &best->short_channel_id),
		    type_to_string(tmpctx, struct amount_msat, &best_fee),
		    best->cltv_expiry_delta);

		d->destination = best->pubkey;
		d->constraints.cltv_budget -= best->cltv_expiry_delta;
		p->getroute->cltv += best->cltv_expiry_delta;

		if (!d->fuzz_amount)
			goto next;

		/* Only try to apply the fee budget changes if we want to fuzz
		 * the amount. Virtual fees that we then don't deliver to the
		 * destination could otherwise cause the route to be too
		 * expensive, while really being ok. If any of these fail then
		 * the above checks are insufficient. */
		if (!amount_msat_sub(&d->constraints.fee_budget,
				     d->constraints.fee_budget, best_fee) ||
		    !amount_msat_sub(&p->constraints.fee_budget,
				     p->constraints.fee_budget, best_fee))
			paymod_err(p,
				   "Could not update fee constraints "
				   "for shadow route extension. "
				   "payment fee budget %s, modifier "
				   "fee budget %s, shadow fee to add %s",
				   type_to_string(tmpctx, struct amount_msat,
						  &p->constraints.fee_budget),
				   type_to_string(tmpctx, struct amount_msat,
						  &d->constraints.fee_budget),
				   type_to_string(tmpctx, struct amount_msat,
						  &best_fee));
	}

next:

	/* Now it's time to decide whether we want to extend or continue. */
	if (best == NULL || pseudorand(2) == 0) {
		payment_continue(p);
		return command_still_pending(cmd);
	} else {
		return shadow_route_extend(d, p);
	}
}

static void shadow_route_cb(struct shadow_route_data *d,
					      struct payment *p)
{
#if DEVELOPER
	if (!d->use_shadow)
		return payment_continue(p);
#endif

	if (p->step != PAYMENT_STEP_INITIALIZED)
		return payment_continue(p);

	d->destination = *p->destination;

	/* Allow shadowroutes to consume up to 1/4th of our budget. */
	d->constraints.cltv_budget = p->constraints.cltv_budget / 4;
	d->constraints.fee_budget
		= amount_msat_div(p->constraints.fee_budget, 4);

	if (pseudorand(2) == 0) {
		return payment_continue(p);
	} else {
		shadow_route_extend(d, p);
	}
}

REGISTER_PAYMENT_MODIFIER(shadowroute, struct shadow_route_data *,
			  shadow_route_init, shadow_route_cb);

static void direct_pay_override(struct payment *p) {

	/* The root has performed the search for a direct channel. */
	struct payment *root = payment_root(p);
	struct direct_pay_data *d;
	struct channel_hint *hint = NULL;

	/* If we were unable to find a direct channel we don't need to do
	 * anything. */
	d = payment_mod_directpay_get_data(root);

	if (d->chan == NULL)
		return payment_continue(p);

	/* If we have a channel we need to make sure that it still has
	 * sufficient capacity. Look it up in the channel_hints. */
	for (size_t i=0; i<tal_count(root->channel_hints); i++) {
		struct short_channel_id_dir *cur = &root->channel_hints[i].scid;
		if (short_channel_id_eq(&cur->scid, &d->chan->scid) &&
		    cur->dir == d->chan->dir) {
			hint = &root->channel_hints[i];
			break;
		}
	}

	if (hint && hint->enabled &&
	    amount_msat_greater(hint->estimated_capacity, p->amount)) {
		/* Now build a route that consists only of this single hop */
		p->route = tal_arr(p, struct route_hop, 1);
		p->route[0].amount = p->amount;
		p->route[0].delay = p->getroute->cltv;
		p->route[0].scid = hint->scid.scid;
		p->route[0].direction = hint->scid.dir;
		p->route[0].node_id = *p->destination;
		p->route[0].style = p->destination_has_tlv ? ROUTE_HOP_TLV : ROUTE_HOP_LEGACY;
		paymod_log(p, LOG_DBG,
			   "Found a direct channel (%s) with sufficient "
			   "capacity, skipping route computation.",
			   type_to_string(tmpctx, struct short_channel_id_dir,
					  &hint->scid));

		payment_set_step(p, PAYMENT_STEP_GOT_ROUTE);
	}


	payment_continue(p);
}

/* Now that we have the listpeers result for the root payment, let's search
 * for a direct channel that is a) connected and b) in state normal. We will
 * check the capacity based on the channel_hints in the override. */
static struct command_result *direct_pay_listpeers(struct command *cmd,
						   const char *buffer,
						   const jsmntok_t *toks,
						   struct payment *p)
{
	struct listpeers_result *r =
	    json_to_listpeers_result(tmpctx, buffer, toks);
	struct direct_pay_data *d = payment_mod_directpay_get_data(p);

	if (tal_count(r->peers) == 1) {
		struct listpeers_peer *peer = r->peers[0];
		if (!peer->connected)
			goto cont;

		for (size_t i=0; i<tal_count(peer->channels); i++) {
			struct listpeers_channel *chan = r->peers[0]->channels[i];
			if (!streq(chan->state, "CHANNELD_NORMAL"))
			    continue;

			d->chan = tal(d, struct short_channel_id_dir);
			d->chan->scid = *chan->scid;
			d->chan->dir = *chan->direction;
		}
	}
cont:
	direct_pay_override(p);
	return command_still_pending(cmd);

}

static void direct_pay_cb(struct direct_pay_data *d, struct payment *p)
{
	struct out_req *req;

/* Look up the direct channel only on root. */
	if (p->step != PAYMENT_STEP_INITIALIZED)
		return payment_continue(p);



	req = jsonrpc_request_start(p->plugin, NULL, "listpeers",
				    direct_pay_listpeers, direct_pay_listpeers,
				    p);
	json_add_node_id(req->js, "id", p->destination);
	send_outreq(p->plugin, req);
}

static struct direct_pay_data *direct_pay_init(struct payment *p)
{
	struct direct_pay_data *d = tal(p, struct direct_pay_data);
	d->chan = NULL;
	return d;
}

REGISTER_PAYMENT_MODIFIER(directpay, struct direct_pay_data *, direct_pay_init,
			  direct_pay_cb);

static struct command_result *waitblockheight_rpc_cb(struct command *cmd,
						     const char *buffer,
						     const jsmntok_t *toks,
						     struct payment *p)
{
	const jsmntok_t *blockheighttok, *codetok;

	u32 blockheight;
	int code;
	struct payment *subpayment;

	blockheighttok = json_get_member(buffer, toks, "blockheight");

	if (!blockheighttok ||
	    !json_to_number(buffer, blockheighttok, &blockheight)) {
		codetok = json_get_member(buffer, toks, "code");
		json_to_int(buffer, codetok, &code);
		if (code == WAIT_TIMEOUT) {
			payment_fail(
			    p,
			    "Timed out while attempting to sync to blockheight "
			    "returned by destination. Please finish syncing "
			    "with the blockchain and try again.");

		} else {
			plugin_err(
			    p->plugin,
			    "Unexpected result from waitblockheight: %.*s",
			    json_tok_full_len(toks),
			    json_tok_full(buffer, toks));
		}
	} else {
		subpayment = payment_new(p, NULL, p, p->modifiers);
		payment_start_at_blockheight(subpayment, blockheight);
		payment_set_step(p, PAYMENT_STEP_RETRY);
		subpayment->why = tal_fmt(
		    subpayment, "Retrying after waiting for blockchain sync.");
		paymod_log(
		    p, LOG_DBG,
		    "Retrying after waitblockheight, new partid %" PRIu32,
		    subpayment->partid);
		payment_continue(p);
	}
	return command_still_pending(cmd);
}

static void waitblockheight_cb(void *d, struct payment *p)
{
	struct out_req *req;
	struct timeabs now = time_now();
	struct timerel remaining;
	u32 blockheight;
	if (p->step != PAYMENT_STEP_FAILED)
		return payment_continue(p);

	/* If we don't have an error message to parse we can't wait for blockheight. */
	if (p->result == NULL)
		return payment_continue(p);

	/* Check if we'd be waiting more than 0 seconds. If we have
	 * less than a second then waitblockheight would return
	 * immediately resulting in a loop. */
	if (time_after(now, p->deadline))
		return payment_continue(p);

	remaining = time_between(p->deadline, now);
	if (time_to_sec(remaining) < 1)
		return payment_continue(p);

	/* *Was* it a blockheight disagreement that caused the failure?  */
	if (!failure_is_blockheight_disagreement(p, &blockheight))
		return payment_continue(p);

	paymod_log(p, LOG_INFORM,
		   "Remote node appears to be on a longer chain, which causes "
		   "CLTV timeouts to be incorrect. Waiting up to %" PRIu64
		   " seconds to catch up to block %d before retrying.",
		   time_to_sec(remaining), blockheight);

	/* Set temporarily set the state of the payment to not failed, so
	 * interim status queries don't show this as terminally failed. We're
	 * in control for this payment so nobody else could be fooled by
	 * this. The callback will set it to retry anyway. */
	payment_set_step(p, PAYMENT_STEP_RETRY);

	req = jsonrpc_request_start(p->plugin, NULL, "waitblockheight",
				    waitblockheight_rpc_cb,
				    waitblockheight_rpc_cb, p);
	json_add_u32(req->js, "blockheight", blockheight);
	json_add_u32(req->js, "timeout", time_to_sec(remaining));
	send_outreq(p->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(waitblockheight, void *, NULL, waitblockheight_cb);

/*****************************************************************************
 * presplit -- Early MPP splitter modifier.
 *
 * This splitter modifier is applied to the root payment, and splits the
 * payment into parts that are more likely to succeed right away. The
 * parameters are derived from probing the network for channel capacities, and
 * may be adjusted in future.
 */


/*By probing the capacity from a well-connected vantage point in the network
 * we found that the 80th percentile of capacities is >= 9765 sats.
 *
 * Rounding to 10e6 msats per part there is a ~80% chance that the payment
 * will go through without requiring further splitting. The fuzzing is
 * symmetric and uniformy distributed around this value, so this should not
 * change the success rate much. For the remaining 20% of payments we might
 * require a split to make the parts succeed, so we try only a limited number
 * of times before we split adaptively.
 *
 * Notice that these numbers are based on a worst case assumption that
 * payments from any node to any other node are equally likely, which isn't
 * really the case, so this is likely a lower bound on the success rate.
 *
 * As the network evolves these numbers are also likely to change.
 *
 * Finally, if applied trivially this splitter may end up creating more splits
 * than the sum of all channels can support, i.e., each split results in an
 * HTLC, and each channel has an upper limit on the number of HTLCs it'll
 * allow us to add. If the initial split would result in more than 1/3rd of
 * the total available HTLCs we clamp the number of splits to 1/3rd. We don't
 * use 3/3rds in order to retain flexibility in the adaptive splitter.
 */
#define MPP_TARGET_SIZE (10 * 1000 * 1000)
#define PRESPLIT_MAX_HTLC_SHARE 3

/* How many parts do we split into before we increase the bucket size. This is
 * a tradeoff between the number of payments whose parts are identical and the
 * number of concurrent HTLCs. The larger this amount the more HTLCs we may
 * end up starting, but the more payments result in the same part sizes.*/
#define PRESPLIT_MAX_SPLITS 16

static struct presplit_mod_data *presplit_mod_data_init(struct payment *p)
{
	struct presplit_mod_data *d;
	if (p->parent == NULL) {
		d = tal(p, struct presplit_mod_data);
		d->disable = false;
		return d;
	} else {
		return payment_mod_presplit_get_data(p->parent);
	}
}

static u32 payment_max_htlcs(const struct payment *p)
{
	const struct payment *root;
	struct channel_hint *h;
	u32 res = 0;
	for (size_t i = 0; i < tal_count(p->channel_hints); i++) {
		h = &p->channel_hints[i];
		if (h->local && h->enabled)
			res += h->htlc_budget;
	}
	root = p;
	while (root->parent)
		root = root->parent;
	if (res > root->max_htlcs)
		res = root->max_htlcs;
	return res;
}

/** payment_lower_max_htlcs
 *
 * @brief indicates that we have a good reason to believe that
 * we should limit our number of max HTLCs.
 *
 * @desc Causes future payment_max_htlcs to have a maximum value
 * they return.
 * Can be called by multiple paymods: the lowest one any paymod
 * has given will be used.
 * If this is called with a limit higher than the existing limit,
 * it just successfully returns without doing anything.
 *
 * @param p - a payment on the payment tree we should limit.
 * @param limit - the number of max HTLCs.
 * @param why - the reason we think the given max HTLCs is
 * reasonable.
 */
static void payment_lower_max_htlcs(struct payment *p, u32 limit,
				    const char *why)
{
	struct payment *root = payment_root(p);
	if (root->max_htlcs > limit) {
		paymod_log(p, LOG_INFORM,
			   "%s limit on max HTLCs: %"PRIu32", %s",
			   root->max_htlcs == UINT32_MAX ?
				"Initial" : "Lowering",
			   limit, why);
		root->max_htlcs = limit;
	}
}

static bool payment_supports_mpp(struct payment *p)
{
	return feature_offered(p->features, OPT_BASIC_MPP);
}

/* Return fuzzed amount ~= target, but never exceeding max */
static struct amount_msat fuzzed_near(struct amount_msat target,
				      struct amount_msat max)
{
	s64 fuzz;
	struct amount_msat res = target;

	/* Somewhere within 25% of target please. */
	fuzz = pseudorand(target.millisatoshis / 2) /* Raw: fuzz */
		- target.millisatoshis / 4; /* Raw: fuzz */
	res.millisatoshis = target.millisatoshis + fuzz; /* Raw: fuzz < msat */

	if (amount_msat_greater(res, max))
		res = max;
	return res;
}

static void presplit_cb(struct presplit_mod_data *d, struct payment *p)
{
	struct payment *root = payment_root(p);

	if (d->disable || p->parent != NULL || !payment_supports_mpp(p))
		return payment_continue(p);

	if (p->step == PAYMENT_STEP_ONION_PAYLOAD) {
		/* We need to tell the last hop the total we're going to
		 * send. Presplit disables amount fuzzing, so we should always
		 * get the exact value through. */
		size_t lastidx = tal_count(p->createonion_request->hops) - 1;
		struct createonion_hop *hop = &p->createonion_request->hops[lastidx];
		if (hop->style == ROUTE_HOP_TLV) {
			struct tlv_field **fields = &hop->tlv_payload->fields;
			tlvstream_set_tlv_payload_data(
			    fields, root->payment_secret,
			    root->amount.millisatoshis); /* Raw: onion payload */
		}
	} else if (p->step == PAYMENT_STEP_INITIALIZED) {
		/* The presplitter only acts on the root and only in the first
		 * step. */
		size_t count = 0;
		u32 htlcs = payment_max_htlcs(p) / PRESPLIT_MAX_HTLC_SHARE;
		struct amount_msat target, amt = p->amount;
		char *partids = tal_strdup(tmpctx, "");
		u64 target_amount = MPP_TARGET_SIZE;

		/* We aim for at most PRESPLIT_MAX_SPLITS parts, even for
		 * large values. To achieve this we take the base amount and
		 * multiply it by the number of targetted parts until the
		 * total amount divided by part amount gives us at most that
		 * number of parts. */
		while (amount_msat_less(amount_msat(target_amount * PRESPLIT_MAX_SPLITS),
					p->amount))
			target_amount *= PRESPLIT_MAX_SPLITS;

		/* We need to opt-in to the MPP sending facility no matter
		 * what we do. That means setting all partids to a non-zero
		 * value. */
		root->partid++;

		/* Bump the next_partid as well so we don't have duplicate
		 * partids. Not really necessary since the root payment whose
		 * id could be reused will never reach the `sendonion` step,
		 * but makes debugging a bit easier. */
		root->next_partid++;

		if (htlcs == 0) {
			p->abort = true;
			return payment_fail(
			    p, "Cannot attempt payment, we have no channel to "
			       "which we can add an HTLC");
		} else if (p->amount.millisatoshis / target_amount > htlcs) /* Raw: division */
			target = amount_msat_div(p->amount, htlcs);
		else
			target = amount_msat(target_amount);

		/* If we are already below the target size don't split it
		 * either. */
		if (amount_msat_greater(target, p->amount))
			return payment_continue(p);

		payment_set_step(p, PAYMENT_STEP_SPLIT);
		/* Ok, we know we should split, so split here and then skip this
		 * payment and start the children instead. */
		while (!amount_msat_eq(amt, AMOUNT_MSAT(0))) {
			double multiplier;

			struct payment *c =
			    payment_new(p, NULL, p, p->modifiers);

			/* Annotate the subpayments with the bolt11 string,
			 * they'll be used when aggregating the payments
			 * again. */
			c->invstring = tal_strdup(c, p->invstring);

			/* Get ~ target, but don't exceed amt */
			c->amount = fuzzed_near(target, amt);

			if (!amount_msat_sub(&amt, amt, c->amount))
				paymod_err(
				    p,
				    "Cannot subtract %s from %s in splitter",
				    type_to_string(tmpctx, struct amount_msat,
						   &c->amount),
				    type_to_string(tmpctx, struct amount_msat,
						   &amt));

			/* Now adjust the constraints so we don't multiply them
			 * when splitting. */
			multiplier = amount_msat_ratio(c->amount, p->amount);
			if (!amount_msat_scale(&c->constraints.fee_budget,
					       c->constraints.fee_budget,
					       multiplier))
				abort(); /* multiplier < 1! */
			payment_start(c);
			/* Why the wordy "new partid n" that we repeat for
			 * each payment?
			 * So that you can search the logs for the
			 * creation of a partid by just "new partid n".
			 */
			if (count == 0)
				tal_append_fmt(&partids, "new partid %"PRIu32, c->partid);
			else
				tal_append_fmt(&partids, ", new partid %"PRIu32, c->partid);
			count++;
		}

		p->result = NULL;
		p->route = NULL;
		p->why = tal_fmt(
		    p,
		    "Split into %zu sub-payments due to initial size (%s > %s)",
		    count,
		    type_to_string(tmpctx, struct amount_msat, &root->amount),
		    type_to_string(tmpctx, struct amount_msat, &target));
		paymod_log(p, LOG_INFORM, "%s: %s", p->why, partids);
	}
	payment_continue(p);
}

REGISTER_PAYMENT_MODIFIER(presplit, struct presplit_mod_data *,
			  presplit_mod_data_init, presplit_cb);

/*****************************************************************************
 * Adaptive splitter -- Split payment if we can't get it through.
 *
 * The adaptive splitter splits the amount of a failed payment in half, with
 * +/- 10% randomness, and then starts two attempts, one for either side of
 * the split. The goal is to find two smaller routes, that still adhere to our
 * constraints, but that can complete the payment.
 *
 * This modifier also checks whether we can split and still have enough HTLCs
 * available on the channels and aborts if that's no longer the case.
 */

#define MPP_ADAPTIVE_LOWER_LIMIT AMOUNT_MSAT(100 * 1000)

static struct adaptive_split_mod_data *adaptive_splitter_data_init(struct payment *p)
{
	struct adaptive_split_mod_data *d;
	if (p->parent == NULL) {
		d = tal(p, struct adaptive_split_mod_data);
		d->disable = false;
		d->htlc_budget = 0;
		return d;
	} else {
		return payment_mod_adaptive_splitter_get_data(p->parent);
	}
}

static void adaptive_splitter_cb(struct adaptive_split_mod_data *d, struct payment *p)
{
	struct payment *root = payment_root(p);
	struct adaptive_split_mod_data *root_data =
	    payment_mod_adaptive_splitter_get_data(root);
	if (d->disable)
		return payment_continue(p);

	if (!payment_supports_mpp(p) || root->abort)
		return payment_continue(p);

	if (p->parent == NULL && d->htlc_budget == 0) {
		/* Now that we potentially had an early splitter run, let's
		 * update our htlc_budget that we own exclusively from now
		 * on. We do this by subtracting the number of payment
		 * attempts an eventual presplitter has already performed. */
		struct payment_tree_result res;
		res = payment_collect_result(p);
		d->htlc_budget = payment_max_htlcs(p);
		if (res.attempts > d->htlc_budget) {
			p->abort = true;
			return payment_fail(
			    p,
			    "Cannot add %d HTLCs to our channels, we "
			    "only have %d HTLCs available.",
			    res.attempts, d->htlc_budget);
		}
		d->htlc_budget -= res.attempts;
	}

	if (p->step == PAYMENT_STEP_ONION_PAYLOAD) {
		/* We need to tell the last hop the total we're going to
		 * send. Presplit disables amount fuzzing, so we should always
		 * get the exact value through. */
		size_t lastidx = tal_count(p->createonion_request->hops) - 1;
		struct createonion_hop *hop = &p->createonion_request->hops[lastidx];
		if (hop->style == ROUTE_HOP_TLV) {
			struct tlv_field **fields = &hop->tlv_payload->fields;
			tlvstream_set_tlv_payload_data(
			    fields, root->payment_secret,
			    root->amount.millisatoshis); /* Raw: onion payload */
		}
	} else if (p->step == PAYMENT_STEP_FAILED && !p->abort) {
		if (amount_msat_greater(p->amount, MPP_ADAPTIVE_LOWER_LIMIT)) {
			struct payment *a, *b;
			/* Random number in the range [90%, 110%] */
			double rand = pseudorand_double() * 0.2 + 0.9;
			u64 mid = p->amount.millisatoshis / 2 * rand; /* Raw: multiplication */
			bool ok;
			/* Use the start constraints, not the ones updated by routes and shadow-routes. */
			struct payment_constraints *pconstraints = p->start_constraints;

			/* First check that splitting doesn't exceed our HTLC budget */
			if (root_data->htlc_budget == 0) {
				root->abort = true;
				return payment_fail(
				    p,
				    "Cannot split payment any further without "
				    "exceeding the maximum number of HTLCs "
				    "allowed by our channels");
			}

			p->step = PAYMENT_STEP_SPLIT;
			a = payment_new(p, NULL, p, p->modifiers);
			b = payment_new(p, NULL, p, p->modifiers);

			a->amount.millisatoshis = mid;  /* Raw: split. */
			b->amount.millisatoshis -= mid; /* Raw: split. */

			double multiplier = amount_msat_ratio(a->amount,
							      p->amount);
			assert(multiplier >= 0.4 && multiplier < 0.6);

			/* Adjust constraints since we don't want to double our
			 * fee allowance when we split. */
			if (!amount_msat_scale(&a->constraints.fee_budget,
					       pconstraints->fee_budget,
					       multiplier))
				abort();

			ok = amount_msat_sub(&b->constraints.fee_budget,
					     pconstraints->fee_budget,
					     a->constraints.fee_budget);

			/* Should not fail, mid is less than 55% of original
			 * amount. fee_budget_a <= 55% of fee_budget_p (parent
			 * of the new payments).*/
			assert(ok);

			payment_start(a);
			payment_start(b);

			paymod_log(p, LOG_DBG,
				   "Adaptively split into 2 sub-payments: "
				   "new partid %"PRIu32" (%s), "
				   "new partid %"PRIu32" (%s)",
				   a->partid,
				   type_to_string(tmpctx, struct amount_msat,
						  &a->amount),
				   b->partid,
				   type_to_string(tmpctx, struct amount_msat,
						  &b->amount));

			/* Take note that we now have an additional split that
			 * may end up using an HTLC. */
			root_data->htlc_budget--;
		} else {
			paymod_log(p, LOG_INFORM,
				   "Lower limit of adaptive splitter reached "
				   "(%s < %s), not splitting further.",
				   type_to_string(tmpctx, struct amount_msat,
						  &p->amount),
				   type_to_string(tmpctx, struct amount_msat,
						  &MPP_ADAPTIVE_LOWER_LIMIT));
		}
	}
	payment_continue(p);
}

REGISTER_PAYMENT_MODIFIER(adaptive_splitter, struct adaptive_split_mod_data *,
			  adaptive_splitter_data_init, adaptive_splitter_cb);


/*****************************************************************************
 * payee_incoming_limit
 *
 * @desc every channel has a limit on the number of HTLCs it is willing to
 * transport.
 * This is particularly crucial for the payers and payees, as they represent
 * the bottleneck to and from the network.
 * The `payment_max_htlcs` function will, by itself, be able to count the
 * payer-side channels, but assessing the payee requires us to probe the
 * area around it.
 *
 * This paymod must be *after* `routehints` but *before* `presplit` paymods:
 *
 * - If we cannot find the destination on the public network, we can only
 *   use channels it put in the routehints.
 *   In this case, that is the number of channels we assess the payee as
 *   having.
 *   However, the `routehints` paymod may filter out some routehints, thus
 *   we should assess based on the post-filtered routehints.
 * - The `presplit` is the first splitter that executes, so we have to have
 *   performed the payee-channels assessment by then.
 */

/* The default `max-concurrent-htlcs` is 30, but node operators might want
 * to push it even lower to reduce their liabilities in case they have to
 * unilaterally close.
 * This will not necessarily improve even in a post-anchor-commitments world,
 * since one of the reasons to unilaterally close is if some HTLC is about to
 * expire, which of course requires the HTLCs to be published anyway, meaning
 * it will still be potentially costly.
 * So our initial assumption is 15 HTLCs per channel.
 *
 * The presplitter will divide this by `PRESPLIT_MAX_HTLC_SHARE` as well.
 */
#define ASSUMED_MAX_HTLCS_PER_CHANNEL 15

static struct command_result *
payee_incoming_limit_count(struct command *cmd,
			   const char *buf,
			   const jsmntok_t *result,
			   struct payment *p)
{
	const jsmntok_t *channelstok;
	size_t num_channels = 0;

	channelstok = json_get_member(buf, result, "channels");
	assert(channelstok);

	/* Count channels.
	 * `listchannels` returns half-channels, i.e. it normally
	 * gives two objects per channel, one for each direction.
	 * However, `listchannels <source>` returns only half-channel
	 * objects whose `source` is the given channel.
	 * Thus, the length of `channels` is accurately the number
	 * of channels.
	 */
	num_channels = channelstok->size;

	/* If num_channels is 0, check if there is an invoice.  */
	if (num_channels == 0)
		num_channels = tal_count(p->routes);

	/* If we got a decent number of channels, limit!  */
	if (num_channels != 0) {
		const char *why;
		u32 lim;
		why = tal_fmt(tmpctx,
			      "Destination %s has %zd channels, "
			      "assuming %d HTLCs per channel",
			      type_to_string(tmpctx, struct node_id,
					     p->destination),
			      num_channels,
			      ASSUMED_MAX_HTLCS_PER_CHANNEL);
		lim = num_channels * ASSUMED_MAX_HTLCS_PER_CHANNEL;
		payment_lower_max_htlcs(p, lim, why);
	}

	payment_continue(p);
	return command_still_pending(cmd);
}

static void payee_incoming_limit_step_cb(void *d UNUSED, struct payment *p)
{
	/* Only operate at the initialization of te root payment.
	 * Also, no point operating if payment does not support MPP anyway.
	 */
	if (p->parent || p->step != PAYMENT_STEP_INITIALIZED
	 || !payment_supports_mpp(p))
		return payment_continue(p);

	/* Get information on the destination.  */
	struct out_req *req;
	req = jsonrpc_request_start(p->plugin, NULL, "listchannels",
				    &payee_incoming_limit_count,
				    &payment_rpc_failure, p);
	json_add_node_id(req->js, "source", p->destination);
	(void) send_outreq(p->plugin, req);
}

REGISTER_PAYMENT_MODIFIER(payee_incoming_limit, void *, NULL,
			  payee_incoming_limit_step_cb);
