#include "pay.h"
#include "payalgo.h"
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/list/list.h>
#include <ccan/structeq/structeq.h>
#include <ccan/take/take.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/bolt11.h>
#include <common/pseudorand.h>
#include <common/route_builder.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <gossipd/gen_gossip_wire.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/subd.h>
#include <sodium/randombytes.h>
#include <wallet/wallet.h>

/* Record of failures. */
enum pay_failure_type {
	FAIL_UNPARSEABLE_ONION,
	FAIL_PAYMENT_REPLY
};
/* A payment failure. */
struct pay_failure {
	/* Part of pay_failures list of struct pay */
	struct list_node list;
	/* The type of payment failure */
	enum pay_failure_type type;
	/* A tal_arr of route hops, whose parent is
	 * this struct */
	struct route_hop *route;
	/* The raw onion reply, if TYPE_UNPARSEABLE_ONION, a
	 * tal_arr whose parent is this struct */
	const u8 *onionreply;
	/* The routing failure, if TYPE_PAYMENT_REPLY, a tal
	 * object whose parent is this struct */
	struct routing_failure *routing_failure;
	/* The detail of the routing failure. A tal_arr
	 * string whose parent is this struct. */
	char *details;
};

/* Output a pay failure */
static void
json_add_failure(struct json_result *r, char const *n,
		 const struct pay_failure *f)
{
	struct routing_failure *rf;
	json_object_start(r, n);
	json_add_string(r, "message", f->details);
	switch (f->type) {
	case FAIL_UNPARSEABLE_ONION:
		json_add_string(r, "type", "FAIL_UNPARSEABLE_ONION");
		json_add_hex(r, "onionreply", f->onionreply,
			     tal_len(f->onionreply));
		break;

	case FAIL_PAYMENT_REPLY:
		rf = f->routing_failure;
		json_add_string(r, "type", "FAIL_PAYMENT_REPLY");
		json_add_num(r, "erring_index", rf->erring_index);
		json_add_num(r, "failcode", (unsigned) rf->failcode);
		json_add_pubkey(r, "erring_node", &rf->erring_node);
		json_add_short_channel_id(r, "erring_channel",
					  &rf->erring_channel);
		if (rf->channel_update)
			json_add_hex(r, "channel_update",
				     rf->channel_update,
				     tal_len(rf->channel_update));
		break;
	}
	json_add_route(r, "route", f->route, tal_count(f->route));
	json_object_end(r);
}

/* Output an array of payment failures. */
static void
json_add_failures(struct json_result *r, char const *n,
		  const struct list_head *fs)
{
	struct pay_failure *f;
	json_array_start(r, n);
	list_for_each(fs, f, list) {
		json_add_failure(r, NULL, f);
	}
	json_array_end(r);
}

/* A point by which we can contact the payee.
 * This represents a single 'r' field of the bolt11 invoice. */
struct contactpoint {
	/* Part of contact_points list of struct pay. */
	struct list_node list;
	/* Destination to search by getroute.
	 * First node on route, or the actual destination if
	 * subroute is empty array. */
	struct pubkey to_find;
	/* Total additional delay on subroute. */
	u32 total_cltv_delta;
	/* Route to use. Non-NULL tal_arr array. */
	struct route_info *subroute;
};

/* Append a contactpoint route to the route found by getroute. */
static void
contactpoint_append(struct route_hop **route,
		    const struct contactpoint *cp,
		    /* Actual destination. */
		    const struct pubkey *receiver_id,
		    /* Actual value we will give to destination. */
		    u64 try_msatoshi,
		    /* Actual final cltv delay. */
		    u32 final_cltv)
{
	size_t route_end;
	size_t actual_route_size;
	int i;
	struct route_builder builder;

	if (tal_count(cp->subroute) == 0)
		return;

	route_end = tal_count(*route);
	actual_route_size = route_end + tal_count(cp->subroute);

	/* Initial route could start empty, if we are the
	 * contactpoint.
	 * If there is initial route, it should terminate
	 * in the contact point to_find node.
	 */
	if (route_end != 0)
		assert(structeq(&(*route)[route_end - 1].nodeid, &cp->to_find));

	tal_resize(route, actual_route_size);

	/* Start up the route builder. */
	route_builder_init(&builder,
			   /* Start from end of existing route. */
			   *route + route_end,
			   tal_count(cp->subroute),
			   receiver_id,
			   try_msatoshi,
			   final_cltv);
	/* Load in reverse as we need to compute amounts and delays in
	 * reverse. */
	for (i = tal_count(cp->subroute) - 1; i >= 0; --i) {
		/* Load the current step. */
		route_builder_step(&builder,
				   &cp->subroute[i].pubkey,
				   &cp->subroute[i].short_channel_id,
				   cp->subroute[i].fee_base_msat,
				   cp->subroute[i].fee_proportional_millionths,
				   cp->subroute[i].cltv_expiry_delta);
	}
	route_builder_complete(&builder);
}
/* Compute the payment at the contact point, given a
 * msatoshi target to be given to the destination. */
static u64
msatoshi_at_contactpoint(const struct contactpoint *cp, u64 msatoshi)
{
	int i;
	for (i = tal_count(cp->subroute) - 1; i >= 0; --i)
		add_fees(&msatoshi,
			 cp->subroute[i].fee_base_msat,
			 cp->subroute[i].fee_proportional_millionths);
	return msatoshi;
}

/* Create a gossip_getroute_request message for a given msatoshi
 * at the destination. */
static u8 *
contactpoint_make_getroute(const tal_t *ctx,
			   const struct pubkey *source,
			   const struct contactpoint *cp,
			   u64 msatoshi,
			   u16 riskfactor,
			   u32 final_cltv,
			   double fuzz,
			   const struct siphash_seed *seed)
{
	/* Add the fees of the subroute. */
	msatoshi = msatoshi_at_contactpoint(cp, msatoshi);
	/* Add the delta of the subroute. */
	final_cltv += cp->total_cltv_delta;
	return towire_gossip_getroute_request(ctx,
					      source,
					      &cp->to_find,
					      msatoshi,
					      riskfactor,
					      final_cltv,
					      &fuzz,
					      seed);
}

/* Pay command */
struct pay {
	/* Parent command. */
	struct command *cmd;

	/* Bolt11 details */
	struct sha256 payment_hash;
	struct pubkey receiver_id;
	struct timeabs expiry;
	u32 min_final_cltv_expiry;

	/* Command details */
	u64 msatoshi;
	double riskfactor;
	double maxfeepercent;
	u32 maxdelay;

	/* Number of getroute and sendpay tries */
	unsigned int getroute_tries;
	unsigned int sendpay_tries;

	/* Current fuzz we pass into getroute. */
	double fuzz;

	/* Parent of the current pay attempt. This object is
	 * freed, then allocated at the start of each pay
	 * attempt to ensure no leaks across long pay attempts */
	char *try_parent;
	/* The msatoshi we will try to send to destination on
	 * the current pay attempt.
	 * This is the msatoshi that will actually reach
	 * the destination. */
	u64 try_msatoshi;

	/* List of contactpoints to try.
	 * The top of this list is the contact point we
	 * are trying to contact.
	 * When this list becomes empty, we have not found
	 * a viable route. */
	struct list_head contactpoints;

	/* Current route being attempted. */
	struct route_hop *route;
	/* The length of the public part of the route. */
	size_t public_length;

	/* List of failures to pay. */
	struct list_head pay_failures;

	/* Whether we are attempting payment or not. */
	bool in_sendpay;
};

/* Construct an empty contactpoint for the destination. */
static void
create_contactpoint_at_dest(struct pay *pay,
			    const struct pubkey *dest)
{
	struct contactpoint *cp = tal(pay, struct contactpoint);
	/* Always try destination first. */
	list_add(&pay->contactpoints, &cp->list);
	cp->to_find = *dest;
	cp->total_cltv_delta = 0;
	cp->subroute = tal_arr(cp, struct route_info, 0);
}
/* Construct a contactpoint from a BOLT11 route. */
static void
create_contactpoint(struct pay *pay,
		    const struct route_info *subroute TAKES)
{
	struct contactpoint *cp;
	size_t i;

	assert(tal_count(subroute) > 0);

	cp = tal(pay, struct contactpoint);
	list_add_tail(&pay->contactpoints, &cp->list);
	cp->to_find = subroute[0].pubkey;
	/* tal_dup_arr is TAKES*/
	cp->subroute = tal_dup_arr(cp, struct route_info, subroute,
				   tal_count(subroute), 0);
	cp->total_cltv_delta = 0;
	for (i = 0; i < tal_count(cp->subroute); ++i)
		cp->total_cltv_delta += cp->subroute[i].cltv_expiry_delta;
}

static struct routing_failure *
dup_routing_failure(const tal_t *ctx, const struct routing_failure *fail)
{
	struct routing_failure *nobj = tal(ctx, struct routing_failure);

	nobj->erring_index = fail->erring_index;
	nobj->failcode = fail->failcode;
	nobj->erring_node = fail->erring_node;
	nobj->erring_channel = fail->erring_channel;
	if (fail->channel_update)
		nobj->channel_update =  tal_dup_arr(nobj, u8,
						    fail->channel_update,
						    tal_count(fail->channel_update),
						    0);
	else
		nobj->channel_update = NULL;

	return nobj;
}

/* Add a pay_failure from a sendpay_result */
static void
add_pay_failure(struct pay *pay,
		const struct sendpay_result *r)
{
	struct pay_failure *f = tal(pay, struct pay_failure);

	/* Append to tail */
	list_add_tail(&pay->pay_failures, &f->list);

	switch (r->errorcode) {
	case PAY_UNPARSEABLE_ONION:
		f->type = FAIL_UNPARSEABLE_ONION;
		f->onionreply = tal_dup_arr(f, u8, r->onionreply,
					    tal_count(r->onionreply), 0);
		break;

	case PAY_TRY_OTHER_ROUTE:
		f->type = FAIL_PAYMENT_REPLY;
		f->routing_failure = dup_routing_failure(f,
							 r->routing_failure);
		break;

		/* All other errors are disallowed */
	default:
		abort();
	}
	f->details = tal_strdup(f, r->details);
	/* Grab the route */
	f->route = tal_steal(f, pay->route);
	pay->route = NULL;
}

static void
json_pay_success(struct pay *pay,
		 const struct sendpay_result *r)
{
	struct command *cmd = pay->cmd;
	struct json_result *response;

	response = new_json_result(cmd);
	json_object_start(response, NULL);
	json_add_payment_fields(response, r->payment);
	json_add_num(response, "getroute_tries", pay->getroute_tries);
	json_add_num(response, "sendpay_tries", pay->sendpay_tries);
	json_add_route(response, "route",
		       pay->route, tal_count(pay->route));
	json_add_failures(response, "failures", &pay->pay_failures);
	json_object_end(response);
	command_success(cmd, response);
}

static void json_pay_failure(struct pay *pay,
			     const struct sendpay_result *r)
{
	struct json_result *data;
	const char *msg = NULL;
	struct routing_failure *fail;

	assert(!r->succeeded);

	data = new_json_result(pay);

	switch (r->errorcode) {
	case PAY_IN_PROGRESS:
		json_object_start(data, NULL);
		json_add_num(data, "getroute_tries", pay->getroute_tries);
		json_add_num(data, "sendpay_tries", pay->sendpay_tries);
		json_add_payment_fields(data, r->payment);
		json_add_failures(data, "failures", &pay->pay_failures);
		json_object_end(data);
		msg = r->details;
		break;

	case PAY_RHASH_ALREADY_USED:
	case PAY_STOPPED_RETRYING:
		json_object_start(data, NULL);
		json_add_num(data, "getroute_tries", pay->getroute_tries);
		json_add_num(data, "sendpay_tries", pay->sendpay_tries);
		json_add_failures(data, "failures", &pay->pay_failures);
		json_object_end(data);
		msg = r->details;
		break;

	case PAY_UNPARSEABLE_ONION:
		/* Impossible case */
		abort();
		break;

	case PAY_DESTINATION_PERM_FAIL:
		fail = r->routing_failure;

		json_object_start(data, NULL);
		json_add_num(data, "erring_index",
			     fail->erring_index);
		json_add_num(data, "failcode",
			     (unsigned) fail->failcode);
		json_add_pubkey(data, "erring_node", &fail->erring_node);
		json_add_short_channel_id(data, "erring_channel",
					  &fail->erring_channel);
		if (fail->channel_update)
			json_add_hex(data, "channel_update",
				     fail->channel_update,
				     tal_len(fail->channel_update));
		json_add_failures(data, "failures", &pay->pay_failures);
		json_object_end(data);

		assert(r->details != NULL);
		msg = tal_fmt(pay,
			      "failed: %s (%s)",
			      onion_type_name(fail->failcode),
			      r->details);

		break;

	case PAY_TRY_OTHER_ROUTE:
		/* Impossible case */
		abort();
		break;
	}

	assert(msg);
	command_fail_detailed(pay->cmd, r->errorcode, data, "%s", msg);
}

/* Determine if we should delay before retrying. Return a reason
 * string, or NULL if we will not retry */
static const char *should_delay_retry(const tal_t *ctx,
				      const struct sendpay_result *r)
{
	/* The routing failures WIRE_EXPIRY_TOO_FAR, WIRE_EXPIRY_TOO_SOON,
	 * and WIRE_FINAL_EXPIRY_TOO_SOON may arise due to disagreement
	 * between the peers about what the block heights are. So
	 * delay for those before retrying. */
	if (!r->succeeded && r->errorcode == PAY_TRY_OTHER_ROUTE) {
		switch (r->routing_failure->failcode) {
		case WIRE_EXPIRY_TOO_FAR:
		case WIRE_EXPIRY_TOO_SOON:
		case WIRE_FINAL_EXPIRY_TOO_SOON:
			return tal_fmt(ctx,
				       "Possible blockheight disagreement "
				       "(%s from peer)",
				       onion_type_name(r->routing_failure->failcode));

		default:
			/* Do nothing */ ;
		}
	}

	return NULL;
}

/* Start a payment attempt. */
static bool json_pay_try(struct pay *pay);

/* Used when delaying. */
static void do_pay_try(struct pay *pay)
{
	log_info(pay->cmd->ld->log, "pay(%p): Try another route", pay);
	json_pay_try(pay);
}

/* Call when sendpay returns to us. */
static void json_pay_sendpay_resolve(const struct sendpay_result *r,
				     void *vpay)
{
	struct pay *pay = (struct pay *) vpay;
	char const *why;
	unsigned int erring_index;

	pay->in_sendpay = false;

	/* If we succeed, hurray */
	if (r->succeeded) {
		log_info(pay->cmd->ld->log, "pay(%p): Success", pay);
		json_pay_success(pay, r);
		return;
	}

	/* We can retry only if it is one of the retryable errors
	 * below. If it is not, fail now. */
	if (r->errorcode != PAY_UNPARSEABLE_ONION &&
	    r->errorcode != PAY_TRY_OTHER_ROUTE) {
		log_info(pay->cmd->ld->log, "pay(%p): Failed, reporting to caller", pay);
		json_pay_failure(pay, r);
		return;
	}

	add_pay_failure(pay, r);

	/* Should retry here, question is whether to retry now or later */

	why = should_delay_retry(pay->try_parent, r);
	if (why) {
		/* We have some reason to delay retrying. */

		log_info(pay->cmd->ld->log,
			 "pay(%p): Delay before retry: %s", pay, why);

		/* Clear previous try memory. */
		pay->try_parent = tal_free(pay->try_parent);
		pay->try_parent = tal(pay, char);

		/* Delay for 3 seconds if needed. FIXME: random
		 * exponential backoff */
		new_reltimer(&pay->cmd->ld->timers, pay->try_parent,
			     time_from_sec(3),
			     &do_pay_try, pay);
		return;
	}

	/* Determine if payment failure point was on a private
	 * route, and is not the destination.
	 * If so, it is a failure on the private route, so
	 * skip the current contactpoint. */
	if (r->errorcode == PAY_TRY_OTHER_ROUTE) {
		erring_index = r->routing_failure->erring_index;
		if (erring_index >= pay->public_length &&
		    erring_index != tal_count(pay->route)) {
			log_info(pay->cmd->ld->log,
				 "pay(%p): erring_index = %u, which is "
				 "on the private route (starting at %u); "
				 "skip to next contactpoint",
				 pay,
				 erring_index,
				 (unsigned int) pay->public_length);
			tal_free(list_pop(&pay->contactpoints,
					  struct contactpoint, list));
		}
	}

	do_pay_try(pay);
}

/* Generates a string describing the route. Route should be a
 * tal_arr */
static char const *stringify_route(const tal_t *ctx, struct route_hop *route)
{
	size_t i;
	char *rv = tal_strdup(ctx, "us");
	for (i = 0; i < tal_count(route); ++i)
		tal_append_fmt(&rv, " -> %s (%"PRIu64"msat, %"PRIu32"blk) -> %s",
			       type_to_string(ctx, struct short_channel_id, &route[i].channel_id),
			       route[i].amount, route[i].delay,
			       type_to_string(ctx, struct pubkey, &route[i].nodeid));
	return rv;
}

static void log_route(struct pay *pay, struct route_hop *route)
{
	log_info(pay->cmd->ld->log, "pay(%p): sendpay via route: %s",
			pay, stringify_route(tmpctx, route));
}

static void json_pay_sendpay_resume(const struct sendpay_result *r,
				    void *vpay)
{
	struct pay *pay = (struct pay *) vpay;
	bool completed = r->succeeded || r->errorcode != PAY_IN_PROGRESS;

	if (completed)
		/* Already completed. */
		json_pay_sendpay_resolve(r, pay);
	else {
		/* Clear previous try memory. */
		pay->try_parent = tal_free(pay->try_parent);
		pay->try_parent = tal(pay, char);

		/* Not yet complete? Wait for it. */
		wait_payment(pay->try_parent, pay->cmd->ld, &pay->payment_hash,
			     json_pay_sendpay_resolve, pay);
	}
}

static void
attempt_sendpay(struct pay *pay, struct route_hop *route)
{
	u64 msatoshi_sent;
	u64 fee;
	double feepercent;
	bool fee_too_high;
	bool delay_too_high;
	struct json_result *data;
	char const *err;

	assert(tal_count(route) != 0);

	msatoshi_sent = route[0].amount;
	fee = msatoshi_sent - pay->msatoshi;
	/* Casting u64 to double will lose some precision. The loss of precision
	 * in feepercent will be like 3.0000..(some dots)..1 % - 3.0 %.
	 * That loss will not be representable in double. So, it's Okay to
	 * cast u64 to double for feepercent calculation. */
	feepercent = ((double) fee) * 100.0 / ((double) pay->msatoshi);
	fee_too_high = (feepercent > pay->maxfeepercent);
	delay_too_high = (route[0].delay > pay->maxdelay);
	/* compare fuzz to range */
	if ((fee_too_high || delay_too_high) && pay->fuzz < 0.01) {
		data = new_json_result(pay);
		json_object_start(data, NULL);
		json_add_u64(data, "msatoshi", pay->msatoshi);
		json_add_u64(data, "fee", fee);
		json_add_double(data, "feepercent", feepercent);
		json_add_double(data, "maxfeepercent", pay->maxfeepercent);
		json_add_u64(data, "delay", (u64) route[0].delay);
		json_add_num(data, "maxdelay", pay->maxdelay);
		json_add_num(data, "getroute_tries", pay->getroute_tries);
		json_add_num(data, "sendpay_tries", pay->sendpay_tries);
		json_add_route(data, "route",
			       route, tal_count(route));
		json_add_failures(data, "failures", &pay->pay_failures);
		json_object_end(data);

		err = "";
		if (fee_too_high)
			err = tal_fmt(pay,
				      "Fee %"PRIu64" is %f%% "
				      "of payment %"PRIu64"; "
				      "max fee requested is %f%%.",
				      fee, feepercent,
				      pay->msatoshi,
				      pay->maxfeepercent);
		if (fee_too_high && delay_too_high)
			err = tal_fmt(pay, "%s ", err);
		if (delay_too_high)
			err = tal_fmt(pay,
				      "%s"
				      "Delay (locktime) is %"PRIu32" blocks; "
				      "max delay requested is %u.",
				      err, route[0].delay, pay->maxdelay);


		command_fail_detailed(pay->cmd, PAY_ROUTE_TOO_EXPENSIVE,
				      data, "%s", err);
		return;
	}
	if (fee_too_high || delay_too_high) {
		/* Retry with lower fuzz */
		pay->fuzz -= 0.15;
		if (pay->fuzz <= 0.0)
			pay->fuzz = 0.0;
		json_pay_try(pay);
		return;
	}

	++pay->sendpay_tries;

	log_route(pay, route);
	assert(!pay->route);
	pay->route = tal_dup_arr(pay, struct route_hop, route,
				 tal_count(route), 0);

	pay->in_sendpay = true;
	send_payment(pay->try_parent,
		     pay->cmd->ld, &pay->payment_hash, route,
		     pay->msatoshi,
		     &json_pay_sendpay_resume, pay);
}

/* For scheduling a deferred sendpay. */
struct deferred_attempt_sendpay_note {
	struct pay *pay;
	struct route_hop *route;
};
static void
resume_attempt_sendpay(struct deferred_attempt_sendpay_note *note)
{
	tal_steal(tmpctx, note);
	attempt_sendpay(note->pay, note->route);
}
static void
deferred_attempt_sendpay(struct pay *pay, struct route_hop *route TAKES)
{
	struct deferred_attempt_sendpay_note *note;
	note = tal(pay->try_parent, struct deferred_attempt_sendpay_note);
	note->pay = pay;
	note->route = tal_dup_arr(note, struct route_hop,
				  route, tal_count(route), 0);
	new_reltimer(&pay->cmd->ld->timers, note, time_from_sec(0),
		     &resume_attempt_sendpay, note);
}

static void json_pay_getroute_reply(struct subd *gossip UNUSED,
				    const u8 *reply, const int *fds UNUSED,
				    struct pay *pay)
{
	struct route_hop *route;

	fromwire_gossip_getroute_reply(reply, reply, &route);

	if (tal_count(route) == 0) {
		/* Cannot reach contactpoint, go to next contactpoint. */
		log_info(pay->cmd->ld->log,
			 "pay(%p): no route found to contactpoint; "
			 "skip to next contactpoint",
			 pay);
		tal_free(list_pop(&pay->contactpoints,
				  struct contactpoint, list));
		json_pay_try(pay);
		return;
	}
	/* Result of getroute is directly the public part of the
	 * route, prior to appending the contactpoint route. */
	pay->public_length = tal_count(route);
	/* Append contactpoint route to found route. */
	contactpoint_append(&route,
			    list_top(&pay->contactpoints,
				     struct contactpoint, list),
			    &pay->receiver_id,
			    pay->try_msatoshi,
			    pay->min_final_cltv_expiry);

	attempt_sendpay(pay, route);
}

static void
fail_no_route(struct pay *pay)
{
	struct json_result *data;
	data = new_json_result(pay);
	json_object_start(data, NULL);
	json_add_num(data, "getroute_tries", pay->getroute_tries);
	json_add_num(data, "sendpay_tries", pay->sendpay_tries);
	json_add_failures(data, "failures", &pay->pay_failures);
	json_object_end(data);
	command_fail_detailed(pay->cmd, PAY_ROUTE_NOT_FOUND, data,
			      "Could not find a route");
}

/* Start a payment attempt. Return true if deferred,
 * false if resolved now. */
static bool json_pay_try(struct pay *pay)
{
	u8 *req;
	struct command *cmd = pay->cmd;
	struct timeabs now = time_now();
	struct siphash_seed seed;
	u64 maxoverpayment;
	u64 overpayment;
	struct contactpoint *cp;
	struct route_hop *route;

	/* If no more contactpoints to try, fail now. */
	if (list_empty(&pay->contactpoints)) {
		fail_no_route(pay);
		return false;
	}

	/* If too late anyway, fail now. */
	if (time_after(now, pay->expiry)) {
		struct json_result *data = new_json_result(cmd);
		json_object_start(data, NULL);
		json_add_num(data, "now", now.ts.tv_sec);
		json_add_num(data, "expiry", pay->expiry.ts.tv_sec);
		json_add_num(data, "getroute_tries", pay->getroute_tries);
		json_add_num(data, "sendpay_tries", pay->sendpay_tries);
		json_add_failures(data, "failures", &pay->pay_failures);
		json_object_end(data);
		command_fail_detailed(cmd, PAY_INVOICE_EXPIRED, data,
				      "Invoice expired");
		return false;
	}

	/* Clear previous try memory. */
	pay->try_parent = tal_free(pay->try_parent);
	pay->try_parent = tal(pay, char);

	/* Clear route */
	pay->route = tal_free(pay->route);

	/* Generate an overpayment, from fuzz * maxfee. */
	/* Now normally the use of double for money is very bad.
	 * Note however that a later stage will ensure that
	 * we do not end up paying more than maxfeepercent
	 * of the msatoshi we intend to pay. */
	maxoverpayment = ((double) pay->msatoshi * pay->fuzz * pay->maxfeepercent)
		/ 100.0;
	if (maxoverpayment > 0) {
		/* We will never generate the maximum computed
		 * overpayment this way. Maybe OK for most
		 * purposes. */
		overpayment = pseudorand(maxoverpayment);
	} else
		overpayment = 0;
	pay->try_msatoshi = pay->msatoshi + overpayment;

	cp = list_top(&pay->contactpoints, struct contactpoint, list);

	/* If we are the contactpoint already, just append to an
	 * empty route and try it now. */
	if (structeq(&cp->to_find, &cmd->ld->id)) {
		route = tal_arr(pay->try_parent, struct route_hop, 0);
		contactpoint_append(&route, cp,
				    &pay->receiver_id, pay->try_msatoshi,
				    pay->min_final_cltv_expiry);

		/* If still a 0-length route, this is, self-pay attempt.
		 * Refuse and fail with route not found. */
		if (tal_count(route) == 0) {
			fail_no_route(pay);
			return false;
		}

		/* Defer the sendpay attempt so that we directly
		 * know that we did things deferred.
		 * The attempt_sendpay, could handle things immediately,
		 * but does not return true/false for deferred/resolved.
		 */
		deferred_attempt_sendpay(pay, take(route));
		/* We deferred, so return true. */
		return true;
	}

	++pay->getroute_tries;

	/* Generate random seed */
	randombytes_buf(&seed, sizeof(seed));

	req = contactpoint_make_getroute(pay->try_parent,
					 &cmd->ld->id,
					 cp,
					 pay->try_msatoshi,
					 pay->riskfactor,
					 pay->min_final_cltv_expiry,
					 pay->fuzz,
					 &seed);
	subd_req(pay->try_parent, cmd->ld->gossip, req, -1, 0, json_pay_getroute_reply, pay);

	return true;
}

static void json_pay_stop_retrying(struct pay *pay)
{
	struct sendpay_result *sr;

	sr = tal(pay, struct sendpay_result);
	sr->succeeded = false;
	if (pay->in_sendpay) {
		/* Still in sendpay. Return with PAY_IN_PROGRESS */
		sr->errorcode = PAY_IN_PROGRESS;
		sr->payment = wallet_payment_by_hash(sr,
						     pay->cmd->ld->wallet,
						     &pay->payment_hash);
		sr->details = "Stopped retrying during payment attempt; "
			      "continue monitoring with "
			      "pay or listpayments";
	} else {
		/* Outside sendpay, no ongoing payment */
		sr->errorcode = PAY_STOPPED_RETRYING;
		sr->details = "Stopped retrying, no ongoing payment";
	}
	json_pay_failure(pay, sr);
}

static void json_pay(struct command *cmd,
		     const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *bolt11tok, *msatoshitok, *desctok, *riskfactortok, *maxfeetok;
	jsmntok_t *retryfortok;
	jsmntok_t *maxdelaytok;
	double riskfactor = 1.0;
	double maxfeepercent = 0.5;
	u64 msatoshi;
	struct pay *pay = tal(cmd, struct pay);
	struct bolt11 *b11;
	char *fail, *b11str, *desc;
	unsigned int retryfor = 60;
	unsigned int maxdelay = 500;
	size_t i;

	if (!json_get_params(cmd, buffer, params,
			     "bolt11", &bolt11tok,
			     "?msatoshi", &msatoshitok,
			     "?description", &desctok,
			     "?riskfactor", &riskfactortok,
			     "?maxfeepercent", &maxfeetok,
			     "?retry_for", &retryfortok,
			     "?maxdelay", &maxdelaytok,
			     NULL)) {
		return;
	}

	b11str = tal_strndup(cmd, buffer + bolt11tok->start,
			     bolt11tok->end - bolt11tok->start);
	if (desctok)
		desc = tal_strndup(cmd, buffer + desctok->start,
				   desctok->end - desctok->start);
	else
		desc = NULL;

	b11 = bolt11_decode(pay, b11str, desc, &fail);
	if (!b11) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "Invalid bolt11: %s", fail);
		return;
	}

	pay->cmd = cmd;
	pay->payment_hash = b11->payment_hash;
	pay->receiver_id = b11->receiver_id;
	memset(&pay->expiry, 0, sizeof(pay->expiry));
	pay->expiry.ts.tv_sec = b11->timestamp + b11->expiry;
	pay->min_final_cltv_expiry = b11->min_final_cltv_expiry;

	if (retryfortok && !json_tok_number(buffer, retryfortok, &retryfor)) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "'%.*s' is not an integer",
			     retryfortok->end - retryfortok->start,
			     buffer + retryfortok->start);
		return;
	}

	if (b11->msatoshi) {
		msatoshi = *b11->msatoshi;
		if (msatoshitok) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "msatoshi parameter unnecessary");
			return;
		}
	} else {
		if (!msatoshitok) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "msatoshi parameter required");
			return;
		}
		if (!json_tok_u64(buffer, msatoshitok, &msatoshi)) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "msatoshi '%.*s' is not a valid number",
				     msatoshitok->end-msatoshitok->start,
				     buffer + msatoshitok->start);
			return;
		}
	}
	pay->msatoshi = msatoshi;

	if (riskfactortok
	    && !json_tok_double(buffer, riskfactortok, &riskfactor)) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "'%.*s' is not a valid double",
			     riskfactortok->end - riskfactortok->start,
			     buffer + riskfactortok->start);
		return;
	}
	pay->riskfactor = riskfactor * 1000;

	if (maxfeetok
	    && !json_tok_double(buffer, maxfeetok, &maxfeepercent)) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "'%.*s' is not a valid double",
			     maxfeetok->end - maxfeetok->start,
			     buffer + maxfeetok->start);
		return;
	}
	/* Ensure it is in range 0.0 <= maxfeepercent <= 100.0 */
	if (!(0.0 <= maxfeepercent)) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "%f maxfeepercent must be non-negative",
			     maxfeepercent);
		return;
	}
	if (!(maxfeepercent <= 100.0)) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "%f maxfeepercent must be <= 100.0",
			     maxfeepercent);
		return;
	}
	pay->maxfeepercent = maxfeepercent;

	if (maxdelaytok
	    && !json_tok_number(buffer, maxdelaytok, &maxdelay)) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "'%.*s' is not a valid integer",
			     maxdelaytok->end - maxdelaytok->start,
			     buffer + maxdelaytok->start);
		return;
	}
	if (maxdelay < pay->min_final_cltv_expiry) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "maxdelay (%u) must be greater than "
			     "min_final_cltv_expiry (%"PRIu32") of "
			     "invoice",
			     maxdelay, pay->min_final_cltv_expiry);
		return;
	}
	pay->maxdelay = maxdelay;

	pay->getroute_tries = 0;
	pay->sendpay_tries = 0;
	/* Higher fuzz increases the potential fees we will pay, since
	 * higher fuzz makes it more likely that high-fee paths get
	 * selected. We start with very high fuzz, but if the
	 * returned route is too expensive for the given
	 * `maxfeepercent` or `maxdelay` we reduce the fuzz.
	 * Starting with high
	 * fuzz means, if the user allows high fee/locktime, we can take
	 * advantage of that to increase randomization and
	 * improve privacy somewhat. */
	pay->fuzz = 0.75;
	pay->try_parent = NULL;
	/* Start with no route */
	pay->route = NULL;
	/* Start with no failures */
	list_head_init(&pay->pay_failures);
	pay->in_sendpay = false;

	/* Load contactpoints. */
	list_head_init(&pay->contactpoints);
	/* Always add destination as first contactpoint. */
	create_contactpoint_at_dest(pay, &pay->receiver_id);
	for (i = 0; i < tal_count(b11->routes); ++i)
		create_contactpoint(pay, take(b11->routes[i]));

	/* Initiate payment */
	if (json_pay_try(pay))
		command_still_pending(cmd);
	else
		return;

	/* Set up timeout. */
	new_reltimer(&cmd->ld->timers, pay, time_from_sec(retryfor),
		     &json_pay_stop_retrying, pay);
}

static const struct json_command pay_command = {
	"pay",
	json_pay,
	"Send payment specified by {bolt11} with optional {msatoshi} "
	"(if and only if {bolt11} does not have amount), "
	"{description} (required if {bolt11} uses description hash), "
	"{riskfactor} (default 1.0), "
	"{maxfeepercent} (default 0.5) the maximum acceptable fee as a percentage (e.g. 0.5 => 0.5%), "
	"{retry_for} (default 60) the integer number of seconds before we stop retrying, and "
	"{maxdelay} (default 500) the maximum number of blocks we allow the funds to possibly get locked"
};
AUTODATA(json_command, &pay_command);
