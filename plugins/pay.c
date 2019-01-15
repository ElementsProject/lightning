#include <ccan/array_size/array_size.h>
#include <ccan/intmap/intmap.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/bolt11.h>
#include <common/pseudorand.h>
#include <common/type_to_string.h>
#include <gossipd/gossip_constants.h>
#include <plugins/libplugin.h>

/* Public key of this node. */
static struct pubkey my_id;
static unsigned int maxdelay_default;
static LIST_HEAD(pay_status);

struct pay_attempt {
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
	const char *desc;
	/* Amount they wanted to pay. */
	u64 msatoshi;
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
	u64 msatoshi;
	double riskfactor;
	unsigned int final_cltv;

	/* Limits on what routes we'll accept. */
	double maxfeepercent;
	unsigned int maxdelay;
	u64 exemptfee;

	/* Payment hash, as text. */
	const char *payment_hash;

	/* Description, if any. */
	const char *desc;

	/* Chatty description of attempts. */
	struct pay_status *ps;

	/* Time to stop retrying. */
	struct timeabs stoptime;

	/* Channels which have failed us. */
	const char **excludes;

	/* Any routehints to use. */
	struct route_info **routehints;

	/* Current node during shadow route calculation. */
	const char *shadow;
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
			       const char *buf, const jsmntok_t *tok)
{
	attempt_failed_fmt(pc, "Call to %s gave error %.*s",
			   method, tok->end - tok->start, buf + tok->start);
}

static struct command_result *start_pay_attempt(struct command *cmd,
						struct pay_command *pc);

/* Is this (erring) channel within the routehint itself? */
static bool channel_in_routehint(const struct route_info *routehint,
				 const char *buf, const jsmntok_t *scidtok)
{
	struct short_channel_id scid;

	if (!json_to_short_channel_id(buf, scidtok, &scid))
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
			tal_append_fmt(&data, "%s { 'route': %s,\n 'failure': '%s'\n }",
				       i == 0 ? "" : ",",
				       pc->ps->attempts[i].route,
				       pc->ps->attempts[i].failure);
		else
			tal_append_fmt(&data, "%s { 'failure': '%s'\n }",
				       i == 0 ? "" : ",",
				       pc->ps->attempts[i].failure);
	}
	tal_append_fmt(&data, "]");
	return command_done_err(cmd, PAY_STOPPED_RETRYING, errmsg, data);
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

	/* If failure is in routehint part, eliminate that */
	if (tal_count(pc->routehints) != 0
	    && channel_in_routehint(pc->routehints[0], buf, scidtok)) {
		tal_arr_remove(&pc->routehints, 0);
	} else {
		/* Otherwise, add erring channel to exclusion list. */
		tal_arr_expand(&pc->excludes,
			       tal_fmt(pc->excludes, "%.*s/%c",
				       scidtok->end - scidtok->start,
				       buf + scidtok->start,
				       buf[dirtok->start]));
	}

	if (time_after(time_now(), pc->stoptime)) {
		return waitsendpay_expired(cmd, pc);
	}

	/* Try again. */
	return start_pay_attempt(cmd, pc);
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
static u64 route_msatoshi(u64 msatoshi,
			  const struct route_info *route, size_t num_route)
{
	for (ssize_t i = num_route - 1; i >= 0; i--) {
		u64 fee;

		fee = route[i].fee_base_msat;
		fee += (route[i].fee_proportional_millionths * msatoshi) / 1000000;
		msatoshi += fee;
	}
	return msatoshi;
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
	return type_to_string(ctx, struct pubkey, &routehint[n].pubkey);
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
		tal_append_fmt(&ret, ", {"
			       " 'id': '%s',"
			       " 'channel': '%s',"
			       " 'msatoshi': %"PRIu64","
			       " 'delay': %u }",
			       /* pubkey of *destination* */
			       route_pubkey(tmpctx, pc, routehint, i + 1),
			       type_to_string(tmpctx, struct short_channel_id,
					      &routehint[i].short_channel_id),
			       /* amount to be received by *destination* */
			       route_msatoshi(pc->msatoshi, routehint + i + 1,
					      tal_count(routehint) - i - 1),
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

/* Try again with the next routehint (or none if that was the last) */
static struct command_result *next_routehint(struct command *cmd,
					     struct pay_command *pc)
{
	tal_arr_remove(&pc->routehints, 0);
	return start_pay_attempt(cmd, pc);
}

static struct command_result *getroute_done(struct command *cmd,
					    const char *buf,
					    const jsmntok_t *result,
					    struct pay_command *pc)
{
	struct pay_attempt *attempt = current_attempt(pc);
	const jsmntok_t *t = json_get_member(buf, result, "route");
	char *json_desc;
	u64 fee;
	u32 delay;
	double feepercent;

	if (!t)
		plugin_err("getroute gave no 'route'? '%.*s'",
			   result->end - result->start, buf);

	if (tal_count(pc->routehints))
		attempt->route = join_routehint(pc->ps->attempts, buf, t,
						pc, pc->routehints[0]);
	else
		attempt->route = json_strdup(pc->ps->attempts, buf, t);

	if (!json_to_u64(buf, json_delve(buf, t, "[0].msatoshi"), &fee))
		plugin_err("getroute with invalid msatoshi? '%.*s'",
			   result->end - result->start, buf);
	fee -= pc->msatoshi;

	if (!json_to_number(buf, json_delve(buf, t, "[0].delay"), &delay))
		plugin_err("getroute with invalid delay? '%.*s'",
			   result->end - result->start, buf);

	/* Casting u64 to double will lose some precision. The loss of precision
	 * in feepercent will be like 3.0000..(some dots)..1 % - 3.0 %.
	 * That loss will not be representable in double. So, it's Okay to
	 * cast u64 to double for feepercent calculation. */
	feepercent = ((double)fee) * 100.0 / ((double) pc->msatoshi);

	if (fee > pc->exemptfee && feepercent > pc->maxfeepercent) {
		attempt_failed_fmt(pc, "Route wanted fee of %"PRIu64" msatoshis", fee);

		if (tal_count(pc->routehints) != 0)
			return next_routehint(cmd, pc);

		return command_fail(cmd, PAY_ROUTE_TOO_EXPENSIVE,
				    "Route wanted fee of %"PRIu64" msatoshis",
				    fee);
	}

	if (delay > pc->maxdelay) {
		attempt_failed_fmt(pc, "Route wanted delay %u blocks", delay);

		if (tal_count(pc->routehints) != 0)
			return next_routehint(cmd, pc);

		return command_fail(cmd, PAY_ROUTE_TOO_EXPENSIVE,
				    "Route wanted delay of %u blocks", delay);
	}

	if (pc->desc)
		json_desc = tal_fmt(pc, ", 'description': '%s'", pc->desc);
	else
		json_desc = "";

	return send_outreq(cmd, "sendpay", sendpay_done, sendpay_error, pc,
			   "'route': %s, 'payment_hash': '%s'%s",
			   attempt->route,
			   pc->payment_hash,
			   json_desc);

}

static struct command_result *getroute_error(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *error,
					     struct pay_command *pc)
{
	attempt_failed_tok(pc, "getroute", buf, error);

	/* If we were trying to use a routehint, remove and try again. */
	if (tal_count(pc->routehints) != 0)
		return next_routehint(cmd, pc);

	return forward_error(cmd, buf, error, pc);
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
						struct pay_command *pc)
{
	char *exclude;
	u64 amount;
	const char *dest;
	size_t max_hops = ROUTING_MAX_HOPS;
	u32 cltv;
	struct pay_attempt attempt;

	attempt.start = time_now();
	/* Mark it unfinished */
	attempt.end.ts.tv_sec = -1;
	attempt.excludes = dup_excludes(pc->ps, pc->excludes);
	attempt.route = NULL;
	attempt.failure = NULL;
	attempt.result = NULL;
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
	if (tal_count(pc->routehints)) {
		amount = route_msatoshi(pc->msatoshi,
					pc->routehints[0],
					tal_count(pc->routehints[0]));
		dest = type_to_string(tmpctx, struct pubkey,
				      &pc->routehints[0][0].pubkey);
		max_hops -= tal_count(pc->routehints[0]);
		cltv = route_cltv(pc->final_cltv,
				  pc->routehints[0],
				  tal_count(pc->routehints[0]));
		attempt.routehint = tal_steal(pc->ps, pc->routehints[0]);
	} else {
		amount = pc->msatoshi;
		dest = pc->dest;
		cltv = pc->final_cltv;
		attempt.routehint = NULL;
	}

	tal_arr_expand(&pc->ps->attempts, attempt);

	/* OK, ask for route to destination */
	return send_outreq(cmd, "getroute", getroute_done, getroute_error, pc,
			   "'id': '%s',"
			   "'msatoshi': %"PRIu64","
			   "'cltv': %u,"
			   "'maxhops': %zu,"
			   "'riskfactor': %f%s",
			   dest, amount, cltv, max_hops, pc->riskfactor, exclude);
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
	const jsmntok_t *chan, *end, *best = NULL;
	u64 sample;
	u32 cltv, best_cltv;

	end = json_next(channels);
	for (chan = channels + 1; chan < end; chan = json_next(chan)) {
		u64 sats, v;

		json_to_u64(buf, json_get_member(buf, chan, "satoshis"), &sats);
		if (sats * 1000 < pc->msatoshi)
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
			       pc->shadow);
		return start_pay_attempt(cmd, pc);
	}

	pc->final_cltv += best_cltv;
	pc->shadow = json_strdup(pc, buf,
				 json_get_member(buf, best, "destination"));
	tal_append_fmt(&pc->ps->shadow,
		       "Added %u cltv delay for shadow to %s. ", best_cltv, pc->shadow);
	return shadow_route(cmd, pc);
}

static struct command_result *shadow_route(struct command *cmd,
					   struct pay_command *pc)
{
	if (pseudorand(2) == 0)
		return start_pay_attempt(cmd, pc);

	return send_outreq(cmd, "listchannels",
			   add_shadow_route, forward_error, pc,
			   "'source' : '%s'", pc->shadow);
}

/* gossipd doesn't know much about the current state of channels; here we
 * manually exclude peers which are disconnected and channels which lack
 * current capacity (it will eliminate those without total capacity). */
static struct command_result *listpeers_done(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *result,
					     struct pay_command *pc)
{
	const jsmntok_t *peer, *peers_end;
	char *mods = tal_strdup(tmpctx, "");

	peer = json_get_member(buf, result, "peers");
	if (!peer)
		plugin_err("listpeers gave no 'peers'? '%.*s'",
			   result->end - result->start, buf);

	peers_end = json_next(peer);
	for (peer = peer + 1; peer < peers_end; peer = json_next(peer)) {
		const jsmntok_t *chan, *chans_end;
		bool connected;

		json_to_bool(buf, json_get_member(buf, peer, "connected"),
			     &connected);
		chan = json_get_member(buf, peer, "channels");
		chans_end = json_next(chan);
		for (chan = chan + 1; chan < chans_end; chan = json_next(chan)) {
			const jsmntok_t *state, *spendable, *scid, *dir;
			u64 capacity;

			/* gossipd will only consider things in state NORMAL
			 * anyway; we don't need to exclude others. */
			state = json_get_member(buf, chan, "state");
			if (!json_tok_streq(buf, state, "CHANNELD_NORMAL"))
				continue;

			spendable = json_get_member(buf, chan,
						    "spendable_msatoshi");
			json_to_u64(buf, spendable, &capacity);

			if (connected && capacity >= pc->msatoshi)
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
				       "Excluded channel %s (%"PRIu64" msat, %s). ",
				       pc->excludes[tal_count(pc->excludes)-1],
				       capacity,
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
		    && pubkey_eq(&hints[i][0].pubkey, &my_id)) {
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
	ps->desc = tal_steal(ps, pc->desc);
	ps->msatoshi = pc->msatoshi;
	ps->final_cltv = pc->final_cltv;
	ps->bolt11 = tal_steal(ps, b11str);
	ps->routehint_modifications = NULL;
	ps->shadow = NULL;
	ps->exclusions = NULL;
	ps->attempts = tal_arr(ps, struct pay_attempt, 0);

	list_add_tail(&pay_status, &ps->list);
	return ps;
}

static struct command_result *handle_pay(struct command *cmd,
					 const char *buf,
					 const jsmntok_t *params)
{
	u64 *msatoshi;
	struct bolt11 *b11;
	const char *b11str;
	char *fail;
	double *riskfactor;
	unsigned int *retryfor;
	struct pay_command *pc = tal(cmd, struct pay_command);
	double *maxfeepercent;
	unsigned int *maxdelay;
	u64 *exemptfee;

	setup_locale();

	if (!param(cmd, buf, params,
		   p_req("bolt11", param_string, &b11str),
		   p_opt("msatoshi", param_u64, &msatoshi),
		   p_opt("description", param_string, &pc->desc),
		   p_opt_def("riskfactor", param_double, &riskfactor, 1.0),
		   p_opt_def("maxfeepercent", param_percent, &maxfeepercent, 0.5),
		   p_opt_def("retry_for", param_number, &retryfor, 60),
		   p_opt_def("maxdelay", param_number, &maxdelay,
			     maxdelay_default),
		   p_opt_def("exemptfee", param_u64, &exemptfee, 5000),
		   NULL))
		return NULL;

	b11 = bolt11_decode(cmd, b11str, pc->desc, &fail);
	if (!b11) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Invalid bolt11: %s", fail);
	}

	if (time_now().ts.tv_sec > b11->timestamp + b11->expiry) {
		return command_fail(cmd, PAY_INVOICE_EXPIRED, "Invoice expired");
	}

	if (b11->msatoshi) {
		if (msatoshi) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "msatoshi parameter unnecessary");
		}
		pc->msatoshi = *b11->msatoshi;
	} else {
		if (!msatoshi) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "msatoshi parameter required");
		}
		pc->msatoshi = *msatoshi;
	}

	pc->maxfeepercent = *maxfeepercent;
	pc->maxdelay = *maxdelay;
	pc->exemptfee = *exemptfee;
	pc->riskfactor = *riskfactor;
	pc->final_cltv = b11->min_final_cltv_expiry;
	pc->dest = type_to_string(cmd, struct pubkey, &b11->receiver_id);
	pc->shadow = tal_strdup(pc, pc->dest);
	pc->payment_hash = type_to_string(pc, struct sha256,
					  &b11->payment_hash);
	pc->stoptime = timeabs_add(time_now(), time_from_sec(*retryfor));
	pc->excludes = tal_arr(cmd, const char *, 0);
	pc->ps = add_pay_status(pc, b11str);
	pc->routehints = filter_routehints(pc, b11->routes);

	/* Get capacities of local channels. */
	return send_outreq(cmd, "listpeers", listpeers_done, forward_error, pc,
			   " ");
}

static void init(struct plugin_conn *rpc)
{
	const char *field;

	field = rpc_delve(tmpctx, "getinfo", "", rpc, ".id");
	if (!pubkey_from_hexstr(field, strlen(field), &my_id))
		plugin_err("getinfo didn't contain valid id: '%s'", field);

	field = rpc_delve(tmpctx, "listconfigs",
			  "'config': 'max-locktime-blocks'",
			  rpc, ".max-locktime-blocks");
	maxdelay_default = atoi(field);
}

static const struct plugin_command commands[] = { {
		"pay2",
		"Send payment specified by {bolt11} with {msatoshi}",
		"Try to send a payment, retrying {retry_for} seconds before giving up",
		handle_pay
	}
};

int main(int argc, char *argv[])
{
	plugin_main(argv, init, commands, ARRAY_SIZE(commands));
}
