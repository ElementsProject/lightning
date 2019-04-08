#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/intmap/intmap.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/amount.h>
#include <common/bolt11.h>
#include <common/pseudorand.h>
#include <common/type_to_string.h>
#include <gossipd/gossip_constants.h>
#include <plugins/libplugin.h>
#include <stdio.h>

/* Public key of this node. */
static struct node_id my_id;
static unsigned int maxdelay_default;
static LIST_HEAD(pay_status);

struct pay_attempt {
	/* What we changed when starting this attempt. */
	const char *why;
	/* Time we started & finished attempt */
	struct timeabs start, end;
	/* Route hint we were using (if any) */
	struct route_info *routehint;
	/* Channels we excluded when doing route lookup. */
	const char **excludes;
	/* Route we got (NULL == route lookup fail). */
	const char *route;
	/* The failure result (NULL on success) */
	const char *failure;
	/* The non-failure result (NULL on failure) */
	const char *result;
};

struct pay_status {
	/* Destination, as text */
	const char *dest;

	/* We're in 'pay_status' global list. */
	struct list_node list;

	/* Description user provided (if any) */
	const char *label;
	/* Amount they wanted to pay. */
	struct amount_msat msat;
	/* CLTV delay required by destination. */
	u32 final_cltv;
	/* Bolt11 invoice. */
	const char *bolt11;

	/* What we did about routehints (if anything) */
	const char *routehint_modifications;

	/* Details of shadow route we chose (if any) */
	char *shadow;

	/* Details of initial exclusions (if any) */
	const char *exclusions;

	/* Array of payment attempts. */
	struct pay_attempt *attempts;
};

struct pay_command {
	/* Destination, as text */
	const char *dest;

	/* How much we're paying, and what riskfactor for routing. */
	struct amount_msat msat;
	double riskfactor;
	unsigned int final_cltv;

	/* Limits on what routes we'll accept. */
	double maxfeepercent;
	unsigned int maxdelay;
	struct amount_msat exemptfee;

	/* Payment hash, as text. */
	const char *payment_hash;

	/* Description, if any. */
	const char *label;

	/* Chatty description of attempts. */
	struct pay_status *ps;

	/* Error to use if getroute says it can't find route. */
	const char *expensive_route;

	/* Time to stop retrying. */
	struct timeabs stoptime;

	/* Channels which have failed us. */
	const char **excludes;

	/* Current routehint, if any. */
	struct route_info *current_routehint;

	/* Any remaining routehints to try. */
	struct route_info **routehints;

	/* Current node during shadow route calculation. */
	const char *shadow_dest;
};

static struct pay_attempt *current_attempt(struct pay_command *pc)
{
	return &pc->ps->attempts[tal_count(pc->ps->attempts)-1];
}

PRINTF_FMT(2,3) static void attempt_failed_fmt(struct pay_command *pc, const char *fmt, ...)
{
	struct pay_attempt *attempt = current_attempt(pc);
	va_list ap;

	va_start(ap,fmt);
	attempt->failure = tal_vfmt(pc->ps->attempts, fmt, ap);
	attempt->end = time_now();
	va_end(ap);
}

static void attempt_failed_tok(struct pay_command *pc, const char *method,
			       const char *buf, const jsmntok_t *errtok)
{
	const jsmntok_t *msg = json_get_member(buf, errtok, "message");

	if (msg)
		attempt_failed_fmt(pc, "%.*sCall to %s:%.*s",
				   msg->start - errtok->start,
				   buf + errtok->start,
				   method,
				   errtok->end - msg->start,
				   buf + msg->start);
	else
		attempt_failed_fmt(pc,
				   "{ 'message': 'Call to %s failed', %.*s",
				   method,
				   errtok->end - errtok->start - 1,
				   buf + errtok->start + 1);
}

static struct command_result *start_pay_attempt(struct command *cmd,
						struct pay_command *pc,
						const char *fmt, ...);

/* Is this (erring) channel within the routehint itself? */
static bool channel_in_routehint(const struct route_info *routehint,
				 const char *buf, const jsmntok_t *scidtok)
{
	struct short_channel_id scid;

	if (!json_to_short_channel_id(buf, scidtok, &scid, false))
		plugin_err("bad erring_channel '%.*s'",
			   scidtok->end - scidtok->start, buf + scidtok->start);

	for (size_t i = 0; i < tal_count(routehint); i++)
		if (short_channel_id_eq(&scid, &routehint[i].short_channel_id))
			return true;

	return false;
}

static struct command_result *waitsendpay_expired(struct command *cmd,
						  struct pay_command *pc)
{
	char *errmsg, *data;

	errmsg = tal_fmt(pc, "Gave up after %zu attempts",
			 tal_count(pc->ps->attempts));
	data = tal_strdup(pc, "'attempts': [ ");
	for (size_t i = 0; i < tal_count(pc->ps->attempts); i++) {
		if (pc->ps->attempts[i].route)
			tal_append_fmt(&data, "%s { 'route': %s,\n 'failure': %s\n }",
				       i == 0 ? "" : ",",
				       pc->ps->attempts[i].route,
				       pc->ps->attempts[i].failure);
		else
			tal_append_fmt(&data, "%s { 'failure': %s\n }",
				       i == 0 ? "" : ",",
				       pc->ps->attempts[i].failure);
	}
	tal_append_fmt(&data, "]");
	return command_done_err(cmd, PAY_STOPPED_RETRYING, errmsg, data);
}

static struct command_result *next_routehint(struct command *cmd,
					     struct pay_command *pc)
{
	if (tal_count(pc->routehints) > 0) {
		pc->current_routehint = pc->routehints[0];
		tal_arr_remove(&pc->routehints, 0);
		return start_pay_attempt(cmd, pc, "Trying route hint");
	}

	/* No (more) routehints; we're out of routes. */
	/* If we eliminated one because it was too pricy, return that. */
	if (pc->expensive_route)
		return command_fail(cmd, PAY_ROUTE_TOO_EXPENSIVE,
				    "%s", pc->expensive_route);

	return command_fail(cmd, PAY_ROUTE_NOT_FOUND,
				    "Could not find a route");
}

static struct command_result *waitsendpay_error(struct command *cmd,
						const char *buf,
						const jsmntok_t *error,
						struct pay_command *pc)
{
	const jsmntok_t *codetok, *scidtok, *dirtok;
	int code;

	attempt_failed_tok(pc, "waitsendpay", buf, error);

	codetok = json_get_member(buf, error, "code");
	if (!json_to_int(buf, codetok, &code))
		plugin_err("waitsendpay error gave no 'code'? '%.*s'",
			   error->end - error->start, buf + error->start);

	/* FIXME: Handle PAY_UNPARSEABLE_ONION! */

	/* Many error codes are final. */
	if (code != PAY_TRY_OTHER_ROUTE) {
		return forward_error(cmd, buf, error, pc);
	}

	scidtok = json_delve(buf, error, ".data.erring_channel");
	if (!scidtok)
		plugin_err("waitsendpay error no erring_channel '%.*s'",
			   error->end - error->start, buf + error->start);
	dirtok = json_delve(buf, error, ".data.erring_direction");
	if (!dirtok)
		plugin_err("waitsendpay error no erring_direction '%.*s'",
			   error->end - error->start, buf + error->start);

	if (time_after(time_now(), pc->stoptime)) {
		return waitsendpay_expired(cmd, pc);
	}

	/* If failure is in routehint part, try next one */
	if (channel_in_routehint(pc->current_routehint, buf, scidtok))
		return next_routehint(cmd, pc);

	/* Otherwise, add erring channel to exclusion list. */
	tal_arr_expand(&pc->excludes,
		       tal_fmt(pc->excludes, "%.*s/%c",
			       scidtok->end - scidtok->start,
			       buf + scidtok->start,
			       buf[dirtok->start]));
	/* Try again. */
	return start_pay_attempt(cmd, pc, "Excluded channel %s",
				 pc->excludes[tal_count(pc->excludes)-1]);
}

static struct command_result *waitsendpay_done(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *result,
					       struct pay_command *pc)
{
	struct pay_attempt *attempt = current_attempt(pc);

	attempt->result = json_strdup(pc->ps->attempts, buf, result);
	attempt->end = time_now();

	return forward_result(cmd, buf, result, pc);
}

static struct command_result *sendpay_done(struct command *cmd,
					   const char *buf,
					   const jsmntok_t *result,
					   struct pay_command *pc)
{
	return send_outreq(cmd, "waitsendpay",
			   waitsendpay_done, waitsendpay_error, pc,
			   "'payment_hash': '%s', 'timeout': 60",
			   pc->payment_hash);
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

/* Calculate cltv we need at the start of this route to get cltv at the end. */
static u32 route_cltv(u32 cltv,
		      const struct route_info *route, size_t num_route)
{
	for (size_t i = 0; i < num_route; i++)
		cltv += route[i].cltv_expiry_delta;
	return cltv;
}

/* The pubkey to use is the destination of this routehint. */
static const char *route_pubkey(const tal_t *ctx,
				const struct pay_command *pc,
				const struct route_info *routehint,
				size_t n)
{
	if (n == tal_count(routehint))
		return pc->dest;
	return type_to_string(ctx, struct node_id, &routehint[n].pubkey);
}

static const char *join_routehint(const tal_t *ctx,
				  const char *buf,
				  const jsmntok_t *route,
				  const struct pay_command *pc,
				  const struct route_info *routehint)
{
	char *ret;

	/* Truncate closing ] from route */
	ret = tal_strndup(ctx, buf + route->start, route->end - route->start - 1);
	for (size_t i = 0; i < tal_count(routehint); i++) {
		/* amount to be received by *destination* */
		struct amount_msat dest_amount;

		if (!route_msatoshi(&dest_amount, pc->msat,
				    routehint + i + 1,
				    tal_count(routehint) - i - 1))
			return tal_free(ret);

		tal_append_fmt(&ret, ", {"
			       " 'id': '%s',"
			       " 'channel': '%s',"
			       " 'msatoshi': '%s',"
			       " 'delay': %u }",
			       /* pubkey of *destination* */
			       route_pubkey(tmpctx, pc, routehint, i + 1),
			       type_to_string(tmpctx, struct short_channel_id,
					      &routehint[i].short_channel_id),
			       type_to_string(tmpctx, struct amount_msat,
					      &dest_amount),
			       /* cltv for *destination* */
			       route_cltv(pc->final_cltv, routehint + i + 1,
					  tal_count(routehint) - i - 1));
	}
	/* Put ] back */
	tal_append_fmt(&ret, "]");
	return ret;
}

static struct command_result *sendpay_error(struct command *cmd,
					    const char *buf,
					    const jsmntok_t *error,
					    struct pay_command *pc)
{
	attempt_failed_tok(pc, "sendpay", buf, error);

	return forward_error(cmd, buf, error, pc);
}

static const jsmntok_t *find_worst_channel(const char *buf,
					   const jsmntok_t *route,
					   const char *fieldname,
					   u64 final)
{
	u64 prev = final, worstval = 0;
	const jsmntok_t *worst = NULL, *t;
	size_t i;

	json_for_each_arr(i, t, route) {
		u64 val;

		json_to_u64(buf, json_get_member(buf, t, fieldname), &val);
		if (worst == NULL || val - prev > worstval) {
			worst = t;
			worstval = val - prev;
		}
		prev = val;
	}

	return worst;
}

/* Can't exclude if it's in routehint itself. */
static bool maybe_exclude(struct pay_command *pc,
			  const char *buf, const jsmntok_t *route)
{
	const jsmntok_t *scid, *dir;

	scid = json_get_member(buf, route, "channel");

	if (channel_in_routehint(pc->current_routehint, buf, scid))
		return false;

	dir = json_get_member(buf, route, "direction");
	tal_arr_expand(&pc->excludes,
		       tal_fmt(pc->excludes, "%.*s/%c",
			       scid->end - scid->start,
			       buf + scid->start,
			       buf[dir->start]));
	return true;
}

static struct command_result *getroute_done(struct command *cmd,
					    const char *buf,
					    const jsmntok_t *result,
					    struct pay_command *pc)
{
	struct pay_attempt *attempt = current_attempt(pc);
	const jsmntok_t *t = json_get_member(buf, result, "route");
	char *json_desc;
	struct amount_msat fee;
	u32 delay;
	double feepercent;

	if (!t)
		plugin_err("getroute gave no 'route'? '%.*s'",
			   result->end - result->start, buf);

	if (pc->current_routehint) {
		attempt->route = join_routehint(pc->ps->attempts, buf, t,
						pc, pc->current_routehint);
		if (!attempt->route) {
			attempt_failed_fmt(pc,
					   "{ 'message': 'Joining routehint gave absurd fee' }");
			return next_routehint(cmd, pc);
		}
	} else
		attempt->route = json_strdup(pc->ps->attempts, buf, t);

	if (!json_to_msat(buf, json_delve(buf, t, "[0].msatoshi"), &fee))
		plugin_err("getroute with invalid msatoshi? %.*s",
			   result->end - result->start, buf);
	if (!amount_msat_sub(&fee, fee, pc->msat))
		plugin_err("final amount %s less than paid %s",
			   type_to_string(tmpctx, struct amount_msat, &fee),
			   type_to_string(tmpctx, struct amount_msat, &pc->msat));

	if (!json_to_number(buf, json_delve(buf, t, "[0].delay"), &delay))
		plugin_err("getroute with invalid delay? %.*s",
			   result->end - result->start, buf);

	/* Casting u64 to double will lose some precision. The loss of precision
	 * in feepercent will be like 3.0000..(some dots)..1 % - 3.0 %.
	 * That loss will not be representable in double. So, it's Okay to
	 * cast u64 to double for feepercent calculation. */
	feepercent = ((double)fee.millisatoshis) * 100.0 / ((double) pc->msat.millisatoshis); /* Raw: fee double manipulation */

	if (amount_msat_greater(fee, pc->exemptfee)
	    && feepercent > pc->maxfeepercent) {
		const jsmntok_t *charger;

		attempt_failed_fmt(pc, "{ 'message': 'Route wanted fee of %s' }",
				   type_to_string(tmpctx, struct amount_msat,
						  &fee));

		/* Remember this if we eliminating this causes us to have no
		 * routes at all! */
		if (!pc->expensive_route)
			pc->expensive_route
				= tal_fmt(pc, "Route wanted fee of %s",
					  type_to_string(tmpctx,
							 struct amount_msat,
							 &fee));

		/* Try excluding most fee-charging channel (unless it's in
		 * routeboost). */
		charger = find_worst_channel(buf, t, "msatoshi", pc->msat.millisatoshis); /* Raw: shared function needs u64 */
		if (maybe_exclude(pc, buf, charger)) {
			return start_pay_attempt(cmd, pc,
						 "Excluded expensive channel %s",
						 pc->excludes[tal_count(pc->excludes)-1]);
		}

		return next_routehint(cmd, pc);
	}

	if (delay > pc->maxdelay) {
		const jsmntok_t *delayer;

		attempt_failed_fmt(pc,
				   "{ 'message': 'Route wanted delay of %u blocks' }",
				   delay);

		/* Remember this if we eliminating this causes us to have no
		 * routes at all! */
		if (!pc->expensive_route)
			pc->expensive_route
				= tal_fmt(pc, "Route wanted delay of %u blocks",
					  delay);

		delayer = find_worst_channel(buf, t, "delay", pc->final_cltv);

		/* Try excluding most delaying channel (unless it's in
		 * routeboost). */
		if (maybe_exclude(pc, buf, delayer)) {
			return start_pay_attempt(cmd, pc,
						 "Excluded delaying channel %s",
						 pc->excludes[tal_count(pc->excludes)-1]);
		}

		return next_routehint(cmd, pc);
	}

	if (pc->label)
		json_desc = tal_fmt(pc, ", 'label': '%s'", pc->label);
	else
		json_desc = "";

	return send_outreq(cmd, "sendpay", sendpay_done, sendpay_error, pc,
			   "'route': %s, 'payment_hash': '%s', 'bolt11': '%s'%s",
			   attempt->route,
			   pc->payment_hash,
			   pc->ps->bolt11,
			   json_desc);

}

static struct command_result *getroute_error(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *error,
					     struct pay_command *pc)
{
	int code;
	const jsmntok_t *codetok;

	attempt_failed_tok(pc, "getroute", buf, error);

	codetok = json_get_member(buf, error, "code");
	if (!json_to_int(buf, codetok, &code))
		plugin_err("getroute error gave no 'code'? '%.*s'",
			   error->end - error->start, buf + error->start);

	/* Strange errors from getroute should be forwarded. */
	if (code != PAY_ROUTE_NOT_FOUND)
		return forward_error(cmd, buf, error, pc);

	return next_routehint(cmd, pc);
}

/* Deep copy of excludes array. */
static const char **dup_excludes(const tal_t *ctx, const char **excludes)
{
	const char **ret = tal_dup_arr(ctx, const char *,
				       excludes, tal_count(excludes), 0);
	for (size_t i = 0; i < tal_count(ret); i++)
		ret[i] = tal_strdup(ret, excludes[i]);
	return ret;
}

static struct command_result *start_pay_attempt(struct command *cmd,
						struct pay_command *pc,
						const char *fmt, ...)
{
	char *exclude;
	struct amount_msat msat;
	const char *dest;
	size_t max_hops = ROUTING_MAX_HOPS;
	u32 cltv;
	struct pay_attempt *attempt;
	va_list ap;
	size_t n;

	n = tal_count(pc->ps->attempts);
	tal_resize(&pc->ps->attempts, n+1);
	attempt = &pc->ps->attempts[n];

	va_start(ap, fmt);
	attempt->start = time_now();
	/* Mark it unfinished */
	attempt->end.ts.tv_sec = -1;
	attempt->excludes = dup_excludes(pc->ps, pc->excludes);
	attempt->route = NULL;
	attempt->failure = NULL;
	attempt->result = NULL;
	attempt->why = tal_vfmt(pc->ps, fmt, ap);
	va_end(ap);

	/* routehint set below. */

	if (tal_count(pc->excludes) != 0) {
		exclude = tal_strdup(tmpctx, ",'exclude': [");
		for (size_t i = 0; i < tal_count(pc->excludes); i++)
			/* JSON.org grammar doesn't allow trailing , */
			tal_append_fmt(&exclude, "%s %s",
				       i == 0 ? "" : ",",
				       pc->excludes[i]);
		tal_append_fmt(&exclude, "]");
	} else
		exclude = "";

	/* If we have a routehint, try that first; we need to do extra
	 * checks that it meets our criteria though. */
	if (pc->current_routehint) {
		attempt->routehint = tal_steal(pc->ps, pc->current_routehint);
		if (!route_msatoshi(&msat, pc->msat,
				    attempt->routehint,
				    tal_count(attempt->routehint))) {
			attempt_failed_fmt(pc,
					   "{ 'message': 'Routehint absurd fee' }");
			return next_routehint(cmd, pc);
		}
		dest = type_to_string(tmpctx, struct node_id,
				      &attempt->routehint[0].pubkey);
		max_hops -= tal_count(attempt->routehint);
		cltv = route_cltv(pc->final_cltv,
				  attempt->routehint,
				  tal_count(attempt->routehint));
	} else {
		msat = pc->msat;
		dest = pc->dest;
		cltv = pc->final_cltv;
		attempt->routehint = NULL;
	}

	/* OK, ask for route to destination */
	return send_outreq(cmd, "getroute", getroute_done, getroute_error, pc,
			   "'id': '%s',"
			   "'msatoshi': '%s',"
			   "'cltv': %u,"
			   "'maxhops': %zu,"
			   "'riskfactor': %f%s",
			   dest,
			   type_to_string(tmpctx, struct amount_msat, &msat),
			   cltv, max_hops, pc->riskfactor, exclude);
}

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
static struct command_result *shadow_route(struct command *cmd,
					   struct pay_command *pc);

static struct command_result *add_shadow_route(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *result,
					       struct pay_command *pc)
{
	/* Use reservoir sampling across the capable channels. */
	const jsmntok_t *channels = json_get_member(buf, result, "channels");
	const jsmntok_t *chan, *best = NULL;
	size_t i;
	u64 sample = 0;
	u32 cltv, best_cltv;

	json_for_each_arr(i, chan, channels) {
		struct amount_sat sat;
		u64 v;

		json_to_sat(buf, json_get_member(buf, chan, "satoshis"), &sat);
		if (amount_msat_greater_sat(pc->msat, sat))
			continue;

		/* Don't use if total would exceed 1/4 of our time allowance. */
		json_to_number(buf, json_get_member(buf, chan, "delay"), &cltv);
		if ((pc->final_cltv + cltv) * 4 > pc->maxdelay)
			continue;

		v = pseudorand(UINT64_MAX);
		if (!best || v > sample) {
			best = chan;
			best_cltv = cltv;
			sample = v;
		}
	}

	if (!best) {
		tal_append_fmt(&pc->ps->shadow,
			       "No suitable channels found to %s. ",
			       pc->shadow_dest);
		return start_pay_attempt(cmd, pc, "Initial attempt");
	}

	pc->final_cltv += best_cltv;
	pc->shadow_dest = json_strdup(pc, buf,
				      json_get_member(buf, best, "destination"));
	tal_append_fmt(&pc->ps->shadow,
		       "Added %u cltv delay for shadow to %s. ",
		       best_cltv, pc->shadow_dest);
	return shadow_route(cmd, pc);
}

static struct command_result *shadow_route(struct command *cmd,
					   struct pay_command *pc)
{
	if (pseudorand(2) == 0)
		return start_pay_attempt(cmd, pc, "Initial attempt");

	return send_outreq(cmd, "listchannels",
			   add_shadow_route, forward_error, pc,
			   "'source' : '%s'", pc->shadow_dest);
}

/* gossipd doesn't know much about the current state of channels; here we
 * manually exclude peers which are disconnected and channels which lack
 * current capacity (it will eliminate those without total capacity). */
static struct command_result *listpeers_done(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *result,
					     struct pay_command *pc)
{
	const jsmntok_t *peers, *peer;
	size_t i;
	char *mods = tal_strdup(tmpctx, "");

	peers = json_get_member(buf, result, "peers");
	if (!peers)
		plugin_err("listpeers gave no 'peers'? '%.*s'",
			   result->end - result->start, buf);

	json_for_each_arr(i, peer, peers) {
		const jsmntok_t *chans, *chan;
		bool connected;
		size_t j;

		json_to_bool(buf, json_get_member(buf, peer, "connected"),
			     &connected);
		chans = json_get_member(buf, peer, "channels");
		json_for_each_arr(j, chan, chans) {
			const jsmntok_t *state, *scid, *dir;
			struct amount_msat spendable;

			/* gossipd will only consider things in state NORMAL
			 * anyway; we don't need to exclude others. */
			state = json_get_member(buf, chan, "state");
			if (!json_tok_streq(buf, state, "CHANNELD_NORMAL"))
				continue;

			json_to_msat(buf,
				    json_get_member(buf, chan,
						    "spendable_msatoshi"),
				    &spendable);

			if (connected
			    && amount_msat_greater_eq(spendable, pc->msat))
				continue;

			/* Exclude this disconnected or low-capacity channel */
			scid = json_get_member(buf, chan, "short_channel_id");
			dir = json_get_member(buf, chan, "direction");
			tal_arr_expand(&pc->excludes,
				       tal_fmt(pc->excludes, "%.*s/%c",
					       scid->end - scid->start,
					       buf + scid->start,
					       buf[dir->start]));

			tal_append_fmt(&mods,
				       "Excluded channel %s (%s, %s). ",
				       pc->excludes[tal_count(pc->excludes)-1],
				       type_to_string(tmpctx, struct amount_msat,
						      &spendable),
				       connected ? "connected" : "disconnected");
		}
	}

	if (!streq(mods, ""))
		pc->ps->exclusions = tal_steal(pc->ps, mods);

	pc->ps->shadow = tal_strdup(pc->ps, "");
	return shadow_route(cmd, pc);
}

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
static struct route_info **filter_routehints(struct pay_command *pc,
					     struct route_info **hints)
{
	char *mods = tal_strdup(tmpctx, "");

	for (size_t i = 0; i < tal_count(hints); i++) {
		/* Trim any routehint > 10 hops */
		size_t max_hops = ROUTING_MAX_HOPS / 2;
		if (tal_count(hints[i]) > max_hops) {
			tal_append_fmt(&mods,
				       "Trimmed routehint %zu (%zu hops) to %zu. ",
				       i, tal_count(hints[i]), max_hops);
			trim_route(&hints[i], max_hops);
		}

		/* If we are first hop, trim. */
		if (tal_count(hints[i]) > 0
		    && node_id_eq(&hints[i][0].pubkey, &my_id)) {
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
		}
	}

	if (!streq(mods, ""))
		pc->ps->routehint_modifications = tal_steal(pc->ps, mods);

	return tal_steal(pc, hints);
}

static struct pay_status *add_pay_status(struct pay_command *pc,
					   const char *b11str)
{
	struct pay_status *ps = tal(NULL, struct pay_status);

	/* The pay_status outlives the pc, so it simply takes field ownership */
	ps->dest = tal_steal(ps, pc->dest);
	ps->label = tal_steal(ps, pc->label);
	ps->msat = pc->msat;
	ps->final_cltv = pc->final_cltv;
	ps->bolt11 = tal_steal(ps, b11str);
	ps->routehint_modifications = NULL;
	ps->shadow = NULL;
	ps->exclusions = NULL;
	ps->attempts = tal_arr(ps, struct pay_attempt, 0);

	list_add_tail(&pay_status, &ps->list);
	return ps;
}

static struct command_result *json_pay(struct command *cmd,
				       const char *buf,
				       const jsmntok_t *params)
{
	struct amount_msat *msat;
	struct bolt11 *b11;
	const char *b11str, *description_deprecated;
	char *fail;
	double *riskfactor;
	unsigned int *retryfor;
	struct pay_command *pc = tal(cmd, struct pay_command);
	double *maxfeepercent;
	unsigned int *maxdelay;
	struct amount_msat *exemptfee;

	/* If params is array, label takes place of description.  For
	 * keywords, its a separate parameter. */
	if (!params || params->type == JSMN_ARRAY) {
		if (!param(cmd, buf, params,
			   p_req("bolt11", param_string, &b11str),
			   p_opt("msatoshi", param_msat, &msat),
			   p_opt("label", param_string, &pc->label),
			   p_opt_def("riskfactor", param_double, &riskfactor, 10),
			   p_opt_def("maxfeepercent", param_percent, &maxfeepercent, 0.5),
			   p_opt_def("retry_for", param_number, &retryfor, 60),
			   p_opt_def("maxdelay", param_number, &maxdelay,
				     maxdelay_default),
			   p_opt_def("exemptfee", param_msat, &exemptfee, AMOUNT_MSAT(5000)),
			   NULL))
			return NULL;

		/* This works because bolt11_decode ignores unneeded descriptions */
		if (deprecated_apis)
			description_deprecated = pc->label;
		else
			description_deprecated = NULL;
	} else {
		/* If by keyword, treat description and label as
		 * separate parameters. */
		if (!param(cmd, buf, params,
			   p_req("bolt11", param_string, &b11str),
			   p_opt("msatoshi", param_msat, &msat),
			   p_opt("description", param_string,
				 &description_deprecated),
			   p_opt_def("riskfactor", param_double, &riskfactor, 10),
			   p_opt_def("maxfeepercent", param_percent, &maxfeepercent, 0.5),
			   p_opt_def("retry_for", param_number, &retryfor, 60),
			   p_opt_def("maxdelay", param_number, &maxdelay,
				     maxdelay_default),
			   p_opt_def("exemptfee", param_msat, &exemptfee, AMOUNT_MSAT(5000)),
			   p_opt("label", param_string, &pc->label),
			   NULL))
		return NULL;

		if (description_deprecated && !deprecated_apis)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Deprecated parameter description, use label");
		if (description_deprecated && pc->label)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Cannot specify both description and label");
	}

	b11 = bolt11_decode(cmd, b11str, description_deprecated, &fail);
	if (!b11) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Invalid bolt11: %s", fail);
	}

	if (time_now().ts.tv_sec > b11->timestamp + b11->expiry) {
		return command_fail(cmd, PAY_INVOICE_EXPIRED, "Invoice expired");
	}

	if (b11->msat) {
		if (msat) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "msatoshi parameter unnecessary");
		}
		pc->msat = *b11->msat;
	} else {
		if (!msat) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "msatoshi parameter required");
		}
		pc->msat = *msat;
	}

	pc->maxfeepercent = *maxfeepercent;
	pc->maxdelay = *maxdelay;
	pc->exemptfee = *exemptfee;
	pc->riskfactor = *riskfactor;
	pc->final_cltv = b11->min_final_cltv_expiry;
	pc->dest = type_to_string(cmd, struct node_id, &b11->receiver_id);
	pc->shadow_dest = tal_strdup(pc, pc->dest);
	pc->payment_hash = type_to_string(pc, struct sha256,
					  &b11->payment_hash);
	pc->stoptime = timeabs_add(time_now(), time_from_sec(*retryfor));
	pc->excludes = tal_arr(cmd, const char *, 0);
	pc->ps = add_pay_status(pc, b11str);
	/* We try first without using routehint */
	pc->current_routehint = NULL;
	pc->routehints = filter_routehints(pc, b11->routes);
	pc->expensive_route = NULL;

	/* Get capacities of local channels. */
	return send_outreq(cmd, "listpeers", listpeers_done, forward_error, pc,
			   /* gcc doesn't like zero-length format strings! */
			   " ");
}

/* FIXME: Add this to ccan/time? */
#define UTC_TIMELEN (sizeof("YYYY-mm-ddTHH:MM:SS.nnnZ"))
static void utc_timestring(const struct timeabs *time, char str[UTC_TIMELEN])
{
	char iso8601_msec_fmt[sizeof("YYYY-mm-ddTHH:MM:SS.%03dZ")];

	strftime(iso8601_msec_fmt, sizeof(iso8601_msec_fmt), "%FT%T.%%03dZ",
		 gmtime(&time->ts.tv_sec));
	snprintf(str, UTC_TIMELEN, iso8601_msec_fmt,
		 (int) time->ts.tv_nsec / 1000000);
}

static void add_attempt(char **ret,
			const struct pay_status *ps,
			const struct pay_attempt *attempt)
{
	char timestr[UTC_TIMELEN];

	utc_timestring(&attempt->start, timestr);

	tal_append_fmt(ret, "{ 'strategy': '%s',"
		       " 'start_time': '%s',"
		       " 'age_in_seconds': %"PRIu64,
		       attempt->why,
		       timestr,
		       time_to_sec(time_between(time_now(), attempt->start)));
	if (attempt->result || attempt->failure) {
		utc_timestring(&attempt->end, timestr);
		tal_append_fmt(ret, ", 'end_time': '%s'"
			       ", 'duration_in_seconds': %"PRIu64,
			       timestr,
			       time_to_sec(time_between(attempt->end,
							attempt->start)));
	}
	if (tal_count(attempt->routehint)) {
		tal_append_fmt(ret, ", 'routehint': [");
		for (size_t i = 0; i < tal_count(attempt->routehint); i++) {
			tal_append_fmt(ret, "%s{"
				       " 'id': '%s',"
				       " 'channel': '%s',"
				       " 'fee_base_msat': %u,"
				       " 'fee_proportional_millionths': %u,"
				       " 'cltv_expiry_delta': %u }",
				       i == 0 ? "" : ", ",
				       type_to_string(tmpctx, struct node_id,
						      &attempt->routehint[i].pubkey),
				       type_to_string(tmpctx,
						      struct short_channel_id,
						      &attempt->routehint[i].short_channel_id),
				       attempt->routehint[i].fee_base_msat,
				       attempt->routehint[i].fee_proportional_millionths,
				       attempt->routehint[i].cltv_expiry_delta);
		}
		tal_append_fmt(ret, "]");
	}
	if (tal_count(attempt->excludes)) {
		for (size_t i = 0; i < tal_count(attempt->excludes); i++) {
			if (i == 0)
				tal_append_fmt(ret, ", 'excluded_channels': [");
			else
				tal_append_fmt(ret, ", ");
			tal_append_fmt(ret, "'%s'", attempt->excludes[i]);
		}
		tal_append_fmt(ret, "]");
	}

	if (attempt->route)
		tal_append_fmt(ret, ", 'route': %s", attempt->route);

	if (attempt->failure)
		tal_append_fmt(ret, ", 'failure': %s", attempt->failure);

	if (attempt->result)
		tal_append_fmt(ret, ", 'success': %s", attempt->result);

	tal_append_fmt(ret, "}");
}

static struct command_result *json_paystatus(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *params)
{
	struct pay_status *ps;
	const char *b11str;
	char *ret;
	bool some = false;

	if (!param(cmd, buf, params,
		   p_opt("bolt11", param_string, &b11str),
		   NULL))
		return NULL;

	ret = tal_fmt(cmd, "{ 'pay': [");
	/* FIXME: Index by bolt11 string! */
	list_for_each(&pay_status, ps, list) {
		if (b11str && !streq(b11str, ps->bolt11))
			continue;

		if (some)
			tal_append_fmt(&ret, ",\n");
		some = true;

		tal_append_fmt(&ret, "{ 'bolt11': '%s',"
			       " 'msatoshi': %"PRIu64", "
			       " 'amount_msat': '%s', "
			       " 'destination': '%s'",
			       ps->bolt11,
			       ps->msat.millisatoshis, /* Raw: JSON */
			       type_to_string(tmpctx, struct amount_msat,
					      &ps->msat), ps->dest);
		if (ps->label)
			tal_append_fmt(&ret, ", 'label': '%s'", ps->label);
		if (ps->routehint_modifications)
			tal_append_fmt(&ret, ", 'routehint_modifications': '%s'",
				       ps->routehint_modifications);
		if (ps->shadow && !streq(ps->shadow, ""))
			tal_append_fmt(&ret, ", 'shadow': '%s'", ps->shadow);
		if (ps->exclusions)
			tal_append_fmt(&ret, ", 'local_exclusions': '%s'",
				       ps->exclusions);

		assert(tal_count(ps->attempts));
		for (size_t i = 0; i < tal_count(ps->attempts); i++) {
			if (i == 0)
				tal_append_fmt(&ret, ", 'attempts': [");
			else
				tal_append_fmt(&ret, ",");

			add_attempt(&ret, ps, &ps->attempts[i]);
		}
		tal_append_fmt(&ret, "] }");
	}
	tal_append_fmt(&ret, "] }");

	return command_success(cmd, ret);
}

static const jsmntok_t *copy_member(char **ret,
				    const char *buf,
				    const jsmntok_t *result,
				    const char *membername,
				    const char *term)
{
	const jsmntok_t *m = json_get_member(buf, result, membername);
	if (m)
		tal_append_fmt(ret, "'%s': %.*s%s",
			       membername,
			       json_tok_full_len(m), json_tok_full(buf, m),
			       term);
	return m;
}

static struct command_result *listsendpays_done(struct command *cmd,
						const char *buf,
						const jsmntok_t *result,
						char *b11str)
{
	size_t i;
	const jsmntok_t *t, *arr;
	char *ret;
	bool some = false;

	arr = json_get_member(buf, result, "payments");
	if (!arr || arr->type != JSMN_ARRAY)
		return command_fail(cmd, LIGHTNINGD,
				    "Unexpected non-array result from listsendpays");

	ret = tal_fmt(cmd, "{ 'pays': [");
	json_for_each_arr(i, t, arr) {
		const jsmntok_t *status;

		if (some)
			tal_append_fmt(&ret, ",\n");
		some = true;

		tal_append_fmt(&ret, "{");
		/* Old payments didn't have bolt11 field */
		if (!copy_member(&ret, buf, t, "bolt11", ",")) {
			if (b11str) {
				/* If it's a single query, we can fake it */
				tal_append_fmt(&ret, "'bolt11': '%s',", b11str);
			} else {
				copy_member(&ret, buf, t, "payment_hash", ",");
				copy_member(&ret, buf, t, "destination", ",");
				copy_member(&ret, buf, t, "amount_msat", ",");
			}
		}

		status = copy_member(&ret, buf, t, "status", ",");
		if (status && json_tok_streq(buf, status, "complete"))
			copy_member(&ret, buf, t, "payment_preimage", ",");
		copy_member(&ret, buf, t, "label", ",");
		copy_member(&ret, buf, t, "amount_sent_msat", "");
		tal_append_fmt(&ret, "}");
	}
	tal_append_fmt(&ret, "] }");
	return command_success(cmd, ret);
}

static struct command_result *json_listpays(struct command *cmd,
					    const char *buf,
					    const jsmntok_t *params)
{
	const char *b11str, *paramstr;

	/* FIXME: would be nice to parse as a bolt11 so check worked in future */
	if (!param(cmd, buf, params,
		   p_opt("bolt11", param_string, &b11str),
		   NULL))
		return NULL;

	if (b11str)
		paramstr = tal_fmt(tmpctx, "'bolt11' : '%s'", b11str);
	else
		paramstr = "";
	return send_outreq(cmd, "listsendpays",
			   listsendpays_done, forward_error,
			   cast_const(char *, b11str),
			   "%s", paramstr);
}

static void init(struct plugin_conn *rpc)
{
	const char *field;

	field = rpc_delve(tmpctx, "getinfo", "", rpc, ".id");
	if (!node_id_from_hexstr(field, strlen(field), &my_id))
		plugin_err("getinfo didn't contain valid id: '%s'", field);

	field = rpc_delve(tmpctx, "listconfigs",
			  "'config': 'max-locktime-blocks'",
			  rpc, ".max-locktime-blocks");
	maxdelay_default = atoi(field);
}

static const struct plugin_command commands[] = { {
		"pay",
		"Send payment specified by {bolt11} with {amount}",
		"Try to send a payment, retrying {retry_for} seconds before giving up",
		json_pay
	}, {
		"paystatus",
		"Detail status of attempts to pay {bolt11}, or all",
		"Covers both old payments and current ones.",
		json_paystatus
	}, {
		"listpays",
		"List result of payment {bolt11}, or all",
		"Covers old payments (failed and succeeded) and current ones.",
		json_listpays
	}
};

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, commands, ARRAY_SIZE(commands));
}
