#include "config.h"
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/cast/cast.h>
#include <ccan/json_escape/json_escape.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/blindedpath.h>
#include <common/bolt11_json.h>
#include <common/bolt12_merkle.h>
#include <common/configdir.h>
#include <common/invoice_path_id.h>
#include <common/json_command.h>
#include <common/json_param.h>
#include <common/overflows.h>
#include <common/random_select.h>
#include <common/timeout.h>
#include <db/exec.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/channel.h>
#include <lightningd/hsm_control.h>
#include <lightningd/invoice.h>
#include <lightningd/notification.h>
#include <lightningd/peer_htlcs.h>
#include <lightningd/plugin_hook.h>
#include <lightningd/routehint.h>
#include <sodium/randombytes.h>
#include <stdio.h>
#include <wallet/invoices.h>
#include <wallet/walletrpc.h>
#include <wire/wire_sync.h>

const char *invoice_status_str(enum invoice_status state)
{
	switch (state) {
	case PAID:
		return "paid";
	case EXPIRED:
		return "expired";
	case UNPAID:
		return "unpaid";
	}
	abort();
}

static void json_add_invoice_fields(struct json_stream *response,
				    const struct invoice_details *inv)
{
	json_add_escaped_string(response, "label", inv->label);
	if (inv->invstring)
		json_add_invstring(response, inv->invstring);
	json_add_sha256(response, "payment_hash", &inv->rhash);
	if (inv->msat)
		json_add_amount_msat(response, "amount_msat", *inv->msat);
	json_add_string(response, "status", invoice_status_str(inv->state));
	if (inv->state == PAID) {
		json_add_u64(response, "pay_index", inv->pay_index);
		json_add_amount_msat(response,
				     "amount_received_msat", inv->received);
		json_add_u64(response, "paid_at", inv->paid_timestamp);
		if (inv->paid_outpoint) {
			json_object_start(response, "paid_outpoint");
			json_add_txid(response, "txid", &inv->paid_outpoint->txid);
			json_add_num(response, "outnum", inv->paid_outpoint->n);
			json_object_end(response);
		}
		json_add_preimage(response, "payment_preimage", &inv->r);
	}
	if (inv->description)
		json_add_string(response, "description", inv->description);

	json_add_u64(response, "expires_at", inv->expiry_time);
	if (inv->local_offer_id) {
		char *fail;
		struct tlv_invoice *tinv;

		json_add_sha256(response, "local_offer_id", inv->local_offer_id);

		/* Everyone loves seeing their own payer notes!
		 * Well: they will.  Trust me. */
		tinv = invoice_decode(tmpctx,
				      inv->invstring, strlen(inv->invstring),
				      NULL, NULL, &fail);
		if (tinv && tinv->invreq_payer_note)
			json_add_stringn(response, "invreq_payer_note",
					 tinv->invreq_payer_note,
					 tal_bytelen(tinv->invreq_payer_note));
	}
	json_add_u64(response, "created_index", inv->created_index);
	if (inv->updated_index)
		json_add_u64(response, "updated_index", inv->updated_index);
}

static void json_add_invoice(struct json_stream *response,
			     const char *fieldname,
			     const struct invoice_details *inv)
{
	json_object_start(response, fieldname);
	json_add_invoice_fields(response, inv);
	json_object_end(response);
}

static struct command_result *tell_waiter(struct command *cmd, u64 inv_dbid)
{
	struct json_stream *response;
	const struct invoice_details *details;

	details = invoices_get_details(cmd, cmd->ld->wallet->invoices, inv_dbid);
	if (details->state == PAID) {
		response = json_stream_success(cmd);
		json_add_invoice_fields(response, details);
		return command_success(cmd, response);
	} else {
		response = json_stream_fail(cmd, INVOICE_EXPIRED_DURING_WAIT,
					    "invoice expired during wait");
		json_add_invoice_fields(response, details);
		json_object_end(response);
		return command_failed(cmd, response);
	}
}

static void tell_waiter_deleted(struct command *cmd)
{
	was_pending(command_fail(cmd, LIGHTNINGD,
				 "Invoice deleted during wait"));
}
static void wait_on_invoice(const u64 *inv_dbid, void *cmd)
{
	if (inv_dbid)
		tell_waiter((struct command *) cmd, *inv_dbid);
	else
		tell_waiter_deleted((struct command *) cmd);
}
static void wait_timed_out(struct command *cmd)
{
	was_pending(command_fail(cmd, INVOICE_WAIT_TIMED_OUT,
				 "Timed out while waiting "
				 "for invoice to be paid"));
}

/* We derive invoice secret using 1-way function from payment_preimage
 * (just a different one from the payment_hash!) */
static void invoice_secret(const struct preimage *payment_preimage,
			   struct secret *payment_secret)
{
	struct preimage modified;
	struct sha256 secret;

	modified = *payment_preimage;
	modified.r[0] ^= 1;

	sha256(&secret, modified.r,
	       ARRAY_SIZE(modified.r) * sizeof(*modified.r));
	BUILD_ASSERT(sizeof(secret.u.u8) == sizeof(payment_secret->data));
	memcpy(payment_secret->data, secret.u.u8, sizeof(secret.u.u8));
}

/* FIXME: The spec should require a *real* secret: a signature of the
 * payment_hash using the payer_id key.  This just means they've
 * *seen* the invoice! */
static void invoice_secret_bolt12(struct lightningd *ld,
				  const struct sha256 *payment_hash,
				  struct secret *payment_secret)
{
	const void *path_id = invoice_path_id(tmpctx,
					      &ld->invoicesecret_base,
					      payment_hash);
	assert(tal_bytelen(path_id) == sizeof(*payment_secret));
	memcpy(payment_secret, path_id, sizeof(*payment_secret));
}

struct invoice_payment_hook_payload {
	struct lightningd *ld;
	/* Set to NULL if it is deleted while waiting for plugin */
	struct htlc_set *set;
	/* What invoice it's trying to pay. */
	const struct json_escape *label;
	/* Outpoint that pays the invoice, if paid on chain. */
	struct bitcoin_outpoint *outpoint;
	/* Amount it's offering. */
	struct amount_msat msat;
	/* Preimage we'll give it if succeeds. */
	struct preimage preimage;
	/* FIXME: Include raw payload! */
};

static void invoice_payment_add_tlvs(struct json_stream *stream,
				     struct htlc_set *hset)
{
	struct htlc_in *hin;
	const struct tlv_payload *tlvs;
	assert(tal_count(hset->htlcs) > 0);

	/* Pick the first HTLC as representative for the entire set. */
	hin = hset->htlcs[0];

	tlvs = hin->payload->tlv;

	json_array_start(stream, "extratlvs");

	for (size_t i = 0; i < tal_count(tlvs->fields); i++) {
		struct tlv_field *field = &tlvs->fields[i];
		/* If we have metadata attached it is not an extra TLV field. */
		if (field->meta == NULL) {
			json_object_start(stream, NULL);
			json_add_u64(stream, "type", field->numtype);
			json_add_num(stream, "length", field->length);
			json_add_hex_talarr(stream, "value", field->value);
			json_object_end(stream);
		}
	}
	json_array_end(stream);
}

static void
invoice_payment_serialize(struct invoice_payment_hook_payload *payload,
			  struct json_stream *stream,
			  struct plugin *plugin)
{
	json_object_start(stream, "payment");
	json_add_escaped_string(stream, "label", payload->label);
	json_add_preimage(stream, "preimage", &payload->preimage);
	json_add_amount_msat(stream, "msat", payload->msat);

	if (payload->ld->developer && payload->set)
		invoice_payment_add_tlvs(stream, payload->set);
	json_object_end(stream); /* .payment */
}

/* Set times out or HTLC deleted?  Remove set ptr from payload so we
 * know to ignore plugin return */
static void invoice_payload_remove_set(struct htlc_set *set,
				       struct invoice_payment_hook_payload *payload)
{
	assert(payload->set == set);
	payload->set = NULL;
}

static const u8 *hook_gives_failmsg(const tal_t *ctx,
				    struct lightningd *ld,
				    const struct htlc_in *hin,
				    const char *buffer,
				    const jsmntok_t *toks)
{
	const jsmntok_t *resulttok;
	const jsmntok_t *t;
	unsigned int val;

	/* No plugin registered on hook at all? */
	if (!buffer)
		return NULL;

	resulttok = json_get_member(buffer, toks, "result");
	if (resulttok) {
		if (json_tok_streq(buffer, resulttok, "continue")) {
			return NULL;
		} else if (json_tok_streq(buffer, resulttok, "reject")) {
			return failmsg_incorrect_or_unknown(ctx, ld, hin);
		} else
			fatal("Invalid invoice_payment hook result: %.*s",
			      toks[0].end - toks[0].start, buffer);
	}

	t = json_get_member(buffer, toks, "failure_message");
	if (t) {
		const u8 *failmsg = json_tok_bin_from_hex(ctx, buffer, t);
		if (!failmsg)
			fatal("Invalid invoice_payment_hook failure_message: %.*s",
			      toks[0].end - toks[1].start, buffer);
		return failmsg;
	}

	t = json_get_member(buffer, toks, "failure_code");
	if (!t) {
		static bool warned = false;
		if (!warned) {
			warned = true;
			log_unusual(ld->log,
				    "Plugin did not return object with "
				    "'result' or 'failure_message' fields.  "
				    "This is now deprecated and you should "
				    "return {'result': 'continue' } or "
				    "{'result': 'reject'} or "
				    "{'failure_message'... instead.");
		}
		return failmsg_incorrect_or_unknown(ctx, ld, hin);
	}

	if (!lightningd_deprecated_in_ok(ld, ld->log,
					 ld->deprecated_ok,
					 "invoice_payment_hook", "failure_code",
					 "v22.08", "V23.02", NULL))
		return NULL;

	if (!json_to_number(buffer, t, &val))
		fatal("Invalid invoice_payment_hook failure_code: %.*s",
		      toks[0].end - toks[1].start, buffer);

	if (val == WIRE_TEMPORARY_NODE_FAILURE)
		return towire_temporary_node_failure(ctx);
	if (val != WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS)
		log_broken(hin->key.channel->log,
			   "invoice_payment hook returned failcode %u,"
			   " changing to incorrect_or_unknown_payment_details",
			   val);

	return failmsg_incorrect_or_unknown(ctx, ld, hin);
}

static void
invoice_payment_hooks_done(struct invoice_payment_hook_payload *payload STEALS)
{
	u64 inv_dbid;
	struct lightningd *ld = payload->ld;

	tal_del_destructor2(payload->set, invoice_payload_remove_set, payload);
	/* We want to free this, whatever happens. */
	tal_steal(tmpctx, payload);

	/* If invoice gets paid meanwhile (plugin responds out-of-order?) then
	 * we can also fail */
	if (!invoices_find_by_label(ld->wallet->invoices, &inv_dbid, payload->label)) {
		htlc_set_fail(payload->set, take(failmsg_incorrect_or_unknown(
							 NULL, ld, payload->set->htlcs[0])));
		return;
	}

	/* Paid or expired in the meantime. */
	if (!invoices_resolve(ld->wallet->invoices, inv_dbid, payload->msat,
			      payload->label, payload->outpoint)) {
		if (payload->set)
			htlc_set_fail(payload->set, take(failmsg_incorrect_or_unknown(
								NULL, ld, payload->set->htlcs[0])));
		return;
	}

	log_info(ld->log, "Resolved invoice '%s' with amount %s in %zu htlcs",
		 payload->label->s,
		 fmt_amount_msat(tmpctx, payload->msat),
		 payload->set ? tal_count(payload->set->htlcs) : 0);
	if (payload->set)
		htlc_set_fulfill(payload->set, &payload->preimage);

	notify_invoice_payment(ld, payload->msat, &payload->preimage,
			       payload->label, payload->outpoint);
}

static bool
invoice_payment_deserialize(struct invoice_payment_hook_payload *payload,
			    const char *buffer,
			    const jsmntok_t *toks)
{
	struct lightningd *ld = payload->ld;
	const u8 *failmsg;

	/* If peer dies or something, this can happen. */
	if (!payload->set && !payload->outpoint) {
		log_debug(ld->log, "invoice '%s' paying htlc_in has gone!",
			  payload->label->s);
		return false;
	}

	if (payload->set) {
		/* Did we have a hook result? */
		failmsg = hook_gives_failmsg(NULL, ld,
						payload->set->htlcs[0], buffer, toks);
		if (failmsg) {
			htlc_set_fail(payload->set, take(failmsg));
			return false;
		}
	}
	return true;
}

REGISTER_PLUGIN_HOOK(invoice_payment,
		     invoice_payment_deserialize,
		     invoice_payment_hooks_done,
		     invoice_payment_serialize,
		     struct invoice_payment_hook_payload *);

const struct invoice_details *
invoice_check_payment(const tal_t *ctx,
		      struct lightningd *ld,
		      const struct sha256 *payment_hash,
		      const struct amount_msat msat,
		      const struct secret *payment_secret,
		      const char **err)
{
	u64 inv_dbid;
	const struct invoice_details *details;

	/* BOLT #4:
	 *  - if the payment hash has already been paid:
	 *    - MAY treat the payment hash as unknown.
	 *    - MAY succeed in accepting the HTLC.
	 *...
	 *  - if the payment hash is unknown:
	 *    - MUST fail the HTLC.
	 *    - MUST return an `incorrect_or_unknown_payment_details` error.
	 */
	if (!invoices_find_unpaid(ld->wallet->invoices, &inv_dbid, payment_hash)) {
		if (invoices_find_by_rhash(ld->wallet->invoices, &inv_dbid, payment_hash)) {
			*err = tal_fmt(ctx, "Already paid or expired invoice %s",
				       fmt_sha256(tmpctx, payment_hash));
		} else {
			*err = tal_fmt(ctx, "Unknown invoice %s",
				       fmt_sha256(tmpctx, payment_hash));
		}
		return NULL;
	}

	details = invoices_get_details(ctx, ld->wallet->invoices, inv_dbid);

	/* BOLT #4:
	 *  - if the `payment_secret` doesn't match the expected value for that
	 *     `payment_hash`, or the `payment_secret` is required and is not
	 *     present:
	 *    - MUST fail the HTLC.
	 */
	if (feature_is_set(details->features, COMPULSORY_FEATURE(OPT_VAR_ONION))
	    && !payment_secret) {
		*err = tal_fmt(ctx, "Attempt to pay %s without secret",
			       fmt_sha256(tmpctx, &details->rhash));
		return tal_free(details);
	}

	if (payment_secret) {
		struct secret expected;

		if (details->invstring && strstarts(details->invstring, "lni1"))
			invoice_secret_bolt12(ld, payment_hash, &expected);
		else
			invoice_secret(&details->r, &expected);
		if (!secret_eq_consttime(payment_secret, &expected)) {
			*err = tal_fmt(ctx, "Attempt to pay %s with wrong secret",
				       fmt_sha256(tmpctx, &details->rhash));
			return tal_free(details);
		}
	}

	/* BOLT #4:
	 *
	 * An _intermediate hop_ MUST NOT, but the _final node_:
	 *...
	 *   - if the amount paid is less than the amount expected:
	 *     - MUST fail the HTLC.
	 */
	if (details->msat != NULL) {
		struct amount_msat twice;

		if (amount_msat_less(msat, *details->msat)) {
			*err = tal_fmt(ctx, "Attempt to pay %s with amount %s < %s",
				       fmt_sha256(tmpctx, &details->rhash),
				       fmt_amount_msat(tmpctx, msat),
				       fmt_amount_msat(tmpctx, *details->msat));
			return tal_free(details);
		}

		if (amount_msat_add(&twice, *details->msat, *details->msat)
		    && amount_msat_greater(msat, twice)) {
			*err = tal_fmt(ctx, "Attempt to pay %s with amount %s > %s",
				       fmt_sha256(tmpctx, &details->rhash),
				       fmt_amount_msat(tmpctx, msat),
				       fmt_amount_msat(tmpctx, twice));
			/* BOLT #4:
			 *
			 * - if the amount paid is more than twice the amount
			 *   expected:
			 *   - SHOULD fail the HTLC.
			 */
			return tal_free(details);
		}
	}
	return details;
}

void invoice_try_pay(struct lightningd *ld,
		     struct htlc_set *set,
		     const struct invoice_details *details,
		     struct amount_msat msat,
		     const struct bitcoin_outpoint *outpoint)
{
	struct invoice_payment_hook_payload *payload;

	payload = tal(NULL, struct invoice_payment_hook_payload);
	payload->ld = ld;
	payload->label = tal_steal(payload, details->label);
	payload->preimage = details->r;
	payload->msat = msat;
	payload->set = set;
	payload->outpoint = tal_dup_or_null(payload, struct bitcoin_outpoint, outpoint);

	// set is NULL if invoice is being paid on-chain
	if (payload->set)
		tal_add_destructor2(set, invoice_payload_remove_set, payload);
	plugin_hook_call_invoice_payment(ld, NULL, payload);
}

static bool hsm_sign_b11(const u5 *u5bytes,
			 const u8 *hrpu8,
			 secp256k1_ecdsa_recoverable_signature *rsig,
			 struct lightningd *ld)
{
	const u8 *msg;

	msg = hsm_sync_req(tmpctx, ld,
			   take(towire_hsmd_sign_invoice(NULL, u5bytes, hrpu8)));
        if (!fromwire_hsmd_sign_invoice_reply(msg, rsig))
		fatal("HSM gave bad sign_invoice_reply %s",
		      tal_hex(msg, msg));

	return true;
}

static void hsm_sign_b12_invoice(struct lightningd *ld,
				 struct tlv_invoice *invoice)
{
	struct sha256 merkle;
	const u8 *msg;

	assert(!invoice->signature);

 	merkle_tlv(invoice->fields, &merkle);
	msg = towire_hsmd_sign_bolt12(NULL, "invoice", "signature", &merkle, NULL);

	msg = hsm_sync_req(tmpctx, ld, take(msg));
	invoice->signature = tal(invoice, struct bip340sig);
        if (!fromwire_hsmd_sign_bolt12_reply(msg, invoice->signature))
		fatal("HSM gave bad sign_invoice_reply %s",
		      tal_hex(msg, msg));
}

static struct command_result *parse_fallback(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *fallback,
					     const u8 **fallback_script)

{
	enum address_parse_result fallback_parse;

	fallback_parse
		= json_to_address_scriptpubkey(cmd,
					       chainparams,
					       buffer, fallback,
					       fallback_script);
	if (fallback_parse == ADDRESS_PARSE_UNRECOGNIZED) {
		return command_fail(cmd, LIGHTNINGD,
				    "Fallback address not valid");
	} else if (fallback_parse == ADDRESS_PARSE_WRONG_NETWORK) {
		return command_fail(cmd, LIGHTNINGD,
				    "Fallback address does not match our network %s",
				    chainparams->network_name);
	}
	return NULL;
}

/*
 * From array of incoming channels [inchan], find suitable ones for
 * a payment-to-us of [amount_needed], using criteria:
 * 1. Channel's peer is known, in state CHANNELD_NORMAL and is online.
 * 2. Channel's peer capacity to pay us is sufficient.
 *
 * Then use weighted reservoir sampling, which makes probing channel balances
 * harder, to choose one channel from the set of suitable channels. It favors
 * channels that have less balance on our side as fraction of their capacity.
 */
static struct route_info **select_inchan(const tal_t *ctx,
					 struct lightningd *ld,
					 struct amount_msat amount_needed,
					 const struct routehint_candidate
					 *candidates)
{
	/* BOLT11 struct wants an array of arrays (can provide multiple routes) */
	struct route_info **r = NULL;
	double total_weight = 0.0;

	/* Collect suitable channels and assign each a weight.  */
	for (size_t i = 0; i < tal_count(candidates); i++) {
		struct amount_msat excess, capacity;
		struct amount_sat cumulative_reserve;
		double excess_frac;

		/* Does the peer have sufficient balance to pay us,
		 * even after having taken into account their reserve? */
		if (!amount_msat_sub(&excess, candidates[i].capacity,
				     amount_needed))
			continue;

		/* Channel balance as seen by our node:

		        |<----------------- capacity ----------------->|
		        .                                              .
		        .             |<------------------ their_msat -------------------->|
		        .             |                                .                   |
		        .             |<----- capacity_to_pay_us ----->|<- their_reserve ->|
		        .             |                                |                   |
		        .             |<- amount_needed --><- excess ->|                   |
		        .             |                                |                   |
		|-------|-------------|--------------------------------|-------------------|
		0       ^             ^                                ^                funding
		   our_reserve     our_msat	*/

		/* Find capacity and calculate its excess fraction */
		if (!amount_sat_add(&cumulative_reserve,
				    candidates[i].c->our_config.channel_reserve,
				    candidates[i].c->channel_info.their_config.channel_reserve)
		    || !amount_sat_to_msat(&capacity, candidates[i].c->funding_sats)
		    || !amount_msat_sub_sat(&capacity, capacity, cumulative_reserve)) {
			log_broken(ld->log, "Channel %s capacity overflow!",
					fmt_short_channel_id(tmpctx, *candidates[i].c->scid));
			continue;
		}

		/* We don't want a 0 probability if 0 excess; it might be the
		 * only one!  So bump it by 1 msat */
		if (!amount_msat_add(&excess, excess, AMOUNT_MSAT(1))) {
			log_broken(ld->log, "Channel %s excess overflow!",
				   fmt_short_channel_id(tmpctx,
							*candidates[i].c->scid));
			continue;
		}
		excess_frac = amount_msat_ratio(excess, capacity);

		if (random_select(excess_frac, &total_weight)) {
			tal_free(r);
			r = tal_arr(ctx, struct route_info *, 1);
			r[0] = tal_dup(r, struct route_info, candidates[i].r);
		}
	}

	return r;
}

static int cmp_rr_number(const struct routehint_candidate *a,
			 const struct routehint_candidate *b,
			 struct lightningd *ld)
{
	if (a->c->rr_number > b->c->rr_number)
		return 1;
	if (a->c->rr_number < b->c->rr_number)
		return -1;

	/* They're unique, so can't be equal */
	log_broken(ld->log, "Two equal candidates %p and %p, channels %p and %p, rr_number %"PRIu64" and %"PRIu64,
		   a, b, a->c, b->c, a->c->rr_number, b->c->rr_number);
	return 0;
}

/** select_inchan_mpp
 *
 * @brief fallback in case select_inchan cannot find a *single*
 * channel capable of accepting the payment as a whole.
 * Also the main routehint-selector if we are completely unpublished
 * (i.e. all our channels are unpublished), since if we are completely
 * unpublished then the payer cannot fall back to just directly routing
 * to us.
 */
static struct route_info **select_inchan_mpp(const tal_t *ctx,
					     struct lightningd *ld,
					     struct amount_msat amount_needed,
					     struct routehint_candidate
					     *candidates)
{
	/* The total amount we have gathered for incoming channels.  */
	struct amount_msat gathered;
	/* Routehint array.  */
	struct route_info **routehints;

	gathered = AMOUNT_MSAT(0);
	routehints = tal_arr(ctx, struct route_info *, 0);

	/* Sort by rr_number, so we get fresh channels. */
	asort(candidates, tal_count(candidates), cmp_rr_number, ld);
	for (size_t i = 0; i < tal_count(candidates); i++) {
		if (amount_msat_greater_eq(gathered, amount_needed))
			break;

		/* Add to current routehints set.  */
		if (!amount_msat_add(&gathered, gathered, candidates[i].capacity)) {
			log_broken(ld->log,
				   "Gathered channel capacity overflow: "
				   "%s + %s",
				   fmt_amount_msat(tmpctx, gathered),
				   fmt_amount_msat(tmpctx, candidates[i].capacity));
			continue;
		}
		tal_arr_expand(&routehints,
			       tal_dup(routehints, struct route_info,
				       candidates[i].r));
		/* Put to the back of the round-robin list */
		candidates[i].c->rr_number = ld->rr_counter++;
	}

	return routehints;
}

/* Encapsulating struct while we wait for gossipd to give us incoming channels */
struct chanhints {
	bool expose_all_private;
	struct short_channel_id *hints;
};

struct invoice_info {
	struct command *cmd;
	struct preimage payment_preimage;
	struct bolt11 *b11;
	struct json_escape *label;
	struct chanhints *chanhints;
	bool custom_fallbacks;
};

/* Add routehints based on listincoming results: NULL means success. */
static struct command_result *
add_routehints(struct invoice_info *info,
	       const char *buffer,
	       const jsmntok_t *toks,
	       bool *warning_mpp,
	       bool *warning_capacity,
	       bool *warning_deadends,
	       bool *warning_offline,
	       bool *warning_private_unused)
{
	const struct chanhints *chanhints = info->chanhints;
	bool node_unpublished;
	struct amount_msat avail_capacity, deadend_capacity, offline_capacity,
		private_capacity;
	struct routehint_candidate *candidates;
	struct amount_msat total, needed;

	/* Dev code can force routes. */
	if (info->b11->routes) {
	       *warning_mpp = *warning_capacity = *warning_deadends
		       = *warning_offline = *warning_private_unused
		       = false;
		return NULL;
	}

	candidates = routehint_candidates(tmpctx, info->cmd->ld,
					  buffer, toks,
					  chanhints ? &chanhints->expose_all_private : NULL,
					  chanhints ? chanhints->hints : NULL,
					  &node_unpublished,
					  &avail_capacity,
					  &private_capacity,
					  &deadend_capacity,
					  &offline_capacity);

	/* If they told us to use scids and we couldn't, fail. */
	if (tal_count(candidates) == 0
	    && chanhints && tal_count(chanhints->hints) != 0) {
		return command_fail(info->cmd,
				    INVOICE_HINTS_GAVE_NO_ROUTES,
				    "None of those hints were suitable local channels");
	}

	needed = info->b11->msat ? *info->b11->msat : AMOUNT_MSAT(1);

	/* If we are not completely unpublished, try with reservoir
	 * sampling first.
	 *
	 * Why do we not do this if we are completely unpublished?
	 * Because it is possible that multiple invoices will, by
	 * chance, select the same channel as routehint.
	 * This single channel might not be able to accept all the
	 * incoming payments on all the invoices generated.
	 * If we were published, that is fine because the payer can
	 * fall back to just attempting to route directly.
	 * But if we were unpublished, the only way for the payer to
	 * reach us would be via the routehints we provide, so we
	 * should make an effort to avoid overlapping incoming
	 * channels, which is done by select_inchan_mpp.
	 */
	if (!node_unpublished)
		info->b11->routes = select_inchan(info->b11,
						  info->cmd->ld,
						  needed,
						  candidates);

	/* If we are completely unpublished, or if the above reservoir
	 * sampling fails, select channels by round-robin.  */
	if (tal_count(info->b11->routes) == 0) {
		info->b11->routes = select_inchan_mpp(info->b11,
						      info->cmd->ld,
						      needed,
						      candidates);
		*warning_mpp = (tal_count(info->b11->routes) > 1);
	} else {
		*warning_mpp = false;
	}

	log_debug(info->cmd->ld->log, "needed = %s, avail_capacity = %s, private_capacity = %s, offline_capacity = %s, deadend_capacity = %s",
		  fmt_amount_msat(tmpctx, needed),
		  fmt_amount_msat(tmpctx, avail_capacity),
		  fmt_amount_msat(tmpctx, private_capacity),
		  fmt_amount_msat(tmpctx, offline_capacity),
		  fmt_amount_msat(tmpctx, deadend_capacity));

	if (!amount_msat_add(&total, avail_capacity, offline_capacity)
	    || !amount_msat_add(&total, total, deadend_capacity)
	    || !amount_msat_add(&total, total, private_capacity))
		fatal("Cannot add %s + %s + %s + %s",
		      fmt_amount_msat(tmpctx, avail_capacity),
		      fmt_amount_msat(tmpctx, offline_capacity),
		      fmt_amount_msat(tmpctx, deadend_capacity),
		      fmt_amount_msat(tmpctx, private_capacity));

	/* If we literally didn't have capacity at all, warn. */
	*warning_capacity = amount_msat_greater_eq(needed, total);

	/* We only warn about these if we didn't have capacity and
	 * they would have helped. */
	*warning_offline = false;
	*warning_deadends = false;
	*warning_private_unused = false;
	if (amount_msat_greater(needed, avail_capacity)) {
		struct amount_msat tot;

		/* We didn't get enough: would offline have helped? */
		if (!amount_msat_add(&tot, avail_capacity, offline_capacity))
			abort();
		if (amount_msat_greater_eq(tot, needed)) {
			*warning_offline = true;
			goto done;
		}

		/* Hmm, what about deadends? */
		if (!amount_msat_add(&tot, tot, deadend_capacity))
			abort();
		if (amount_msat_greater_eq(tot, needed)) {
			*warning_deadends = true;
			goto done;
		}

		/* What about private channels? */
		if (!amount_msat_add(&tot, tot, private_capacity))
			abort();
		if (amount_msat_greater_eq(tot, needed)) {
			*warning_private_unused = true;
			goto done;
		}
	}

done:
	return NULL;
}

static struct command_result *
invoice_complete(struct invoice_info *info,
		 bool warning_no_listincoming,
		 bool warning_mpp,
		 bool warning_capacity,
		 bool warning_deadends,
		 bool warning_offline,
		 bool warning_private_unused)
{
	struct json_stream *response;
	u64 inv_dbid;
	char *b11enc;
	const struct invoice_details *details;
	struct secret payment_secret;
	struct wallet *wallet = info->cmd->ld->wallet;

	b11enc = bolt11_encode(info, info->b11, false,
			       hsm_sign_b11, info->cmd->ld);

	/* Check duplicate preimage (unlikely unless they specified it!) */
	if (invoices_find_by_rhash(wallet->invoices,
				   &inv_dbid, &info->b11->payment_hash)) {
		return command_fail(info->cmd,
				    INVOICE_PREIMAGE_ALREADY_EXISTS,
				    "preimage already used");
	}

	if (!invoices_create(wallet->invoices,
			     &inv_dbid,
			     info->b11->msat,
			     info->label,
			     info->b11->expiry,
			     b11enc,
			     info->b11->description,
			     info->b11->features,
			     &info->payment_preimage,
			     &info->b11->payment_hash,
			     NULL)) {
		return command_fail(info->cmd, INVOICE_LABEL_ALREADY_EXISTS,
				    "Duplicate label '%s'",
				    info->label->s);
	}

	if (info->cmd->ld->unified_invoices && info->b11->fallbacks && !info->custom_fallbacks) {
		for (size_t i = 0; i < tal_count(info->b11->fallbacks); i++) {
			const u8 *fallback_script = info->b11->fallbacks[i];
			invoices_create_fallback(wallet->invoices, inv_dbid, fallback_script);
		}
	}

	/* Get details */
	details = invoices_get_details(info, wallet->invoices, inv_dbid);

	response = json_stream_success(info->cmd);
	json_add_sha256(response, "payment_hash", &details->rhash);
	json_add_u64(response, "expires_at", details->expiry_time);
	json_add_string(response, "bolt11", details->invstring);
	invoice_secret(&details->r, &payment_secret);
	json_add_secret(response, "payment_secret", &payment_secret);
	json_add_u64(response, "created_index", details->created_index);

	notify_invoice_creation(info->cmd->ld, info->b11->msat,
				&info->payment_preimage, info->label);

	if (warning_no_listincoming)
		json_add_string(response, "warning_listincoming",
				"No listincoming command available, cannot add routehints to invoice");
	if (warning_mpp)
		json_add_string(response, "warning_mpp",
				"The invoice is only payable by MPP-capable payers.");
	if (warning_capacity)
		json_add_string(response, "warning_capacity",
				"Insufficient incoming channel capacity to pay invoice");

	if (warning_deadends)
		json_add_string(response, "warning_deadends",
				"Insufficient incoming capacity, once dead-end peers were excluded");

	if (warning_offline)
		json_add_string(response, "warning_offline",
				"Insufficient incoming capacity, once offline peers were excluded");

	if (warning_private_unused)
		json_add_string(response, "warning_private_unused",
				"Insufficient incoming capacity, once private channels were excluded (try exposeprivatechannels=true?)");

	if (info->cmd->ld->unified_invoices && info->custom_fallbacks)
		json_add_string(response, "warning_custom_fallbacks",
				"WARNING: Not tracking on-chain payments for custom fallback addresses");

	return command_success(info->cmd, response);
}

/* Return from "listincoming". */
static void listincoming_done(const char *buffer,
			      const jsmntok_t *toks,
			      const jsmntok_t *idtok UNUSED,
			      struct invoice_info *info)
{
	struct command_result *ret;
	bool warning_mpp, warning_capacity, warning_deadends, warning_offline, warning_private_unused;

	ret = add_routehints(info, buffer, toks,
			     &warning_mpp,
			     &warning_capacity,
			     &warning_deadends,
			     &warning_offline,
			     &warning_private_unused);
	if (ret)
		return;

	invoice_complete(info,
			 false,
			 warning_mpp,
			 warning_capacity,
			 warning_deadends,
			 warning_offline,
			 warning_private_unused);
}

void invoice_check_onchain_payment(struct lightningd *ld,
				   const u8 *scriptPubKey,
				   struct amount_sat sat,
				   const struct bitcoin_outpoint *outpoint)
{
	u64 inv_dbid;
	const struct invoice_details *details;
	struct amount_msat msat;
	if (!amount_sat_to_msat(&msat, sat))
		abort();
	/* Does this onchain payment fulfill an invoice? */
	if(!invoices_find_by_fallback_script(ld->wallet->invoices, &inv_dbid, scriptPubKey)) {
		return;
	}

	details = invoices_get_details(tmpctx, ld->wallet->invoices, inv_dbid);

	if (amount_msat_less(msat, *details->msat)) {
		// notify_underpaid_onchain_invoice();
		return;
	}

	invoice_try_pay(ld, NULL, details, msat, outpoint);
}

/* Since this is a dev-only option, we will crash if dev-routes is not
 * an array-of-arrays-of-correct-items. */
static struct route_info *unpack_route(const tal_t *ctx,
				       const char *buffer,
				       const jsmntok_t *routetok)
{
	const jsmntok_t *t;
	size_t i;
	struct route_info *route = tal_arr(ctx, struct route_info, routetok->size);

	json_for_each_arr(i, t, routetok) {
		const jsmntok_t *pubkey, *fee_base, *fee_prop, *scid, *cltv;
		struct route_info *r = &route[i];
		u32 cltv_u32;

		pubkey = json_get_member(buffer, t, "id");
		scid = json_get_member(buffer, t, "short_channel_id");
		fee_base = json_get_member(buffer, t, "fee_base_msat");
		fee_prop = json_get_member(buffer, t,
					   "fee_proportional_millionths");
		cltv = json_get_member(buffer, t, "cltv_expiry_delta");

		if (!json_to_node_id(buffer, pubkey, &r->pubkey)
		    || !json_to_short_channel_id(buffer, scid,
						 &r->short_channel_id)
		    || !json_to_number(buffer, fee_base, &r->fee_base_msat)
		    || !json_to_number(buffer, fee_prop,
				       &r->fee_proportional_millionths)
		    || !json_to_number(buffer, cltv, &cltv_u32))
			abort();
		/* We don't have a json_to_u16 */
		r->cltv_expiry_delta = cltv_u32;
	}
	return route;
}

static struct route_info **unpack_routes(const tal_t *ctx,
					 const char *buffer,
					 const jsmntok_t *routestok)
{
	struct route_info **routes;
	const jsmntok_t *t;
	size_t i;

	if (!routestok)
		return NULL;

	routes = tal_arr(ctx, struct route_info *, routestok->size);
	json_for_each_arr(i, t, routestok)
		routes[i] = unpack_route(routes, buffer, t);

	return routes;
}

static struct command_result *param_positive_msat_or_any(struct command *cmd,
							 const char *name,
							 const char *buffer,
							 const jsmntok_t *tok,
							 struct amount_msat **msat)
{
	if (json_tok_streq(buffer, tok, "any")) {
		*msat = NULL;
		return NULL;
	}
	*msat = tal(cmd, struct amount_msat);
	if (parse_amount_msat(*msat, buffer + tok->start, tok->end - tok->start)
	    && !amount_msat_eq(**msat, AMOUNT_MSAT(0)))
		return NULL;

	return command_fail_badparam(cmd, name, buffer, tok,
				     "should be positive msat or 'any'");
}

static struct command_result *param_chanhints(struct command *cmd,
					      const char *name,
					      const char *buffer,
					      const jsmntok_t *tok,
					      struct chanhints **chanhints)
{
	bool boolhint;

	*chanhints = tal(cmd, struct chanhints);

	/* Could be simply "true" or "false" */
	if (json_to_bool(buffer, tok, &boolhint)) {
		(*chanhints)->expose_all_private = boolhint;
		(*chanhints)->hints = NULL;
		return NULL;
	}

	(*chanhints)->expose_all_private = true;
	/* Could be a single short_channel_id or an array */
	if (tok->type == JSMN_ARRAY) {
		size_t i;
		const jsmntok_t *t;

		(*chanhints)->hints
			= tal_arr(*chanhints, struct short_channel_id,
				  tok->size);
		json_for_each_arr(i, t, tok) {
			if (!json_to_short_channel_id(buffer, t,
						      &(*chanhints)->hints[i])) {
				return command_fail_badparam(cmd, name, buffer, t,
						    "should be a short channel id");
			}
		}
		return NULL;
	}

	/* Otherwise should be a short_channel_id */
	return param_short_channel_id(cmd, name, buffer, tok,
				      &(*chanhints)->hints);
}

static struct command_result *param_preimage(struct command *cmd,
					     const char *name,
					     const char *buffer,
					     const jsmntok_t *tok,
					     struct preimage **preimage)
{
	*preimage = tal(cmd, struct preimage);
	if (!hex_decode(buffer + tok->start, tok->end - tok->start,
			*preimage, sizeof(**preimage)))
		return command_fail_badparam(cmd, "preimage",
					     buffer, tok,
					     "should be 64 hex digits");
	return NULL;
}

static struct command_result *json_invoice(struct command *cmd,
					   const char *buffer,
					   const jsmntok_t *obj UNNEEDED,
					   const jsmntok_t *params)
{
	const jsmntok_t *fallbacks;
	struct amount_msat *msatoshi_val;
	struct invoice_info *info;
	const char *desc_val;
	const u8 **fallback_scripts = NULL;
	u64 *expiry;
	struct sha256 rhash;
	struct secret payment_secret;
	struct preimage *preimage;
	u32 *cltv;
	struct jsonrpc_request *req;
	struct plugin *plugin;
	bool *hashonly;
	const size_t inv_max_label_len = 128;
	const jsmntok_t *dev_routes;

	info = tal(cmd, struct invoice_info);
	info->cmd = cmd;

	if (!param_check(cmd, buffer, params,
			 p_req("amount_msat", param_positive_msat_or_any, &msatoshi_val),
			 p_req("label", param_label, &info->label),
			 p_req("description", param_escaped_string, &desc_val),
			 p_opt_def("expiry", param_u64, &expiry, 3600*24*7),
			 p_opt("fallbacks", param_array, &fallbacks),
			 p_opt("preimage", param_preimage, &preimage),
			 p_opt("exposeprivatechannels", param_chanhints,
			       &info->chanhints),
			 p_opt_def("cltv", param_number, &cltv,
				   cmd->ld->config.cltv_final),
			 p_opt_def("deschashonly", param_bool, &hashonly, false),
			 p_opt("dev-routes", param_array, &dev_routes),
			 NULL))
		return command_param_failed();

	if (dev_routes && !cmd->ld->developer)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "dev-routes requires --developer");

	if (strlen(info->label->s) > inv_max_label_len) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Label '%s' over %zu bytes", info->label->s, inv_max_label_len);
	}

	if (strlen(desc_val) > BOLT11_FIELD_BYTE_LIMIT && !*hashonly) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Descriptions greater than %d bytes "
				    "not yet supported "
				    "(description length %zu)",
				    BOLT11_FIELD_BYTE_LIMIT,
				    strlen(desc_val));
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	info->custom_fallbacks = false;
	if (fallbacks) {
		info->custom_fallbacks = true;
		if (cmd->ld->unified_invoices) {
			log_info(cmd->ld->log,
				 "WARNING: Not tracking on-chain payments "
				 "for custom fallback addresses");
		}
		size_t i;
		const jsmntok_t *t;

		fallback_scripts = tal_arr(cmd, const u8 *, fallbacks->size);
		json_for_each_arr(i, t, fallbacks) {
			struct command_result *r;

			r = parse_fallback(cmd, buffer, t, &fallback_scripts[i]);
			if (r)
				return r;
		}
	} else if (cmd->ld->unified_invoices) {
		struct pubkey pubkey;
		const u8 *p2tr;

		fallback_scripts = tal_arr(cmd, const u8 *, 1);

		if (!newaddr_inner(cmd, &pubkey, ADDR_P2TR))
			return command_fail(cmd, LIGHTNINGD, "Keys exhausted ");

		p2tr = scriptpubkey_p2tr(fallback_scripts, &pubkey);
		fallback_scripts[0] = p2tr;
	}

	if (preimage)
		info->payment_preimage = *preimage;
	else
		/* Generate random secret preimage. */
		randombytes_buf(&info->payment_preimage,
				sizeof(info->payment_preimage));
	/* Generate preimage hash. */
	sha256(&rhash, &info->payment_preimage, sizeof(info->payment_preimage));
	/* Generate payment secret. */
	invoice_secret(&info->payment_preimage, &payment_secret);

	info->b11 = new_bolt11(info, msatoshi_val);
	info->b11->chain = chainparams;
	info->b11->timestamp = time_now().ts.tv_sec;
	info->b11->payment_hash = rhash;
	info->b11->receiver_id = cmd->ld->id;
	info->b11->min_final_cltv_expiry = *cltv;
	info->b11->expiry = *expiry;
	info->b11->description = tal_steal(info->b11, desc_val);
	/* BOLT #11:
	 * * `h` (23): `data_length` 52. 256-bit description of purpose of payment (SHA256).
	 *...
	 * A writer:
	 *...
	 *    - MUST include either exactly one `d` or exactly one `h` field.
	 */
	if (*hashonly) {
		info->b11->description_hash = tal(info->b11, struct sha256);
		sha256(info->b11->description_hash, desc_val, strlen(desc_val));
	} else
		info->b11->description_hash = NULL;
	info->b11->payment_secret = tal_dup(info->b11, struct secret,
					    &payment_secret);
	info->b11->features = tal_dup_talarr(info->b11, u8,
					     cmd->ld->our_features
					     ->bits[BOLT11_FEATURE]);

	info->b11->routes = unpack_routes(info->b11, buffer, dev_routes);

	if (fallback_scripts)
		info->b11->fallbacks = tal_steal(info->b11, fallback_scripts);

	/* We can't generate routehints without listincoming. */
	plugin = find_plugin_for_command(cmd->ld, "listincoming");
	if (!plugin) {
		return invoice_complete(info, true,
					false, false, false, false, false);
	}

	req = jsonrpc_request_start(info, "listincoming",
				    cmd->id, plugin->non_numeric_ids,
				    command_log(cmd),
				    NULL, listincoming_done,
				    info);
	jsonrpc_request_end(req);
	plugin_request_send(plugin, req);
	return command_still_pending(cmd);
}

static const struct json_command invoice_command = {
	"invoice",
	"payment",
	json_invoice,
	"Create an invoice for {msatoshi} with {label} "
	"and {description} with optional {expiry} seconds "
	"(default 1 week), optional {fallbacks} address list"
	"(default empty list) and optional {preimage} "
	"(default autogenerated)"};
AUTODATA(json_command, &invoice_command);

static void json_add_invoices(struct json_stream *response,
			      struct wallet *wallet,
			      const struct json_escape *label,
			      const struct sha256 *payment_hash,
			      const struct sha256 *local_offer_id,
			      const enum wait_index *listindex,
			      u64 liststart,
			      const u32 *listlimit)
{
	const struct invoice_details *details;
	u64 inv_dbid;

	/* Don't iterate entire db if we're just after one. */
	if (label) {
		if (invoices_find_by_label(wallet->invoices, &inv_dbid, label)) {
			details =
			    invoices_get_details(tmpctx, wallet->invoices, inv_dbid);
			json_add_invoice(response, NULL, details);
		}
	} else if (payment_hash != NULL) {
		if (invoices_find_by_rhash(wallet->invoices, &inv_dbid,
						 payment_hash)) {
			details =
			    invoices_get_details(tmpctx, wallet->invoices, inv_dbid);
			json_add_invoice(response, NULL, details);
		}
	} else {
		struct db_stmt *stmt;

		for (stmt = invoices_first(wallet->invoices,
					   listindex, liststart, listlimit,
					   &inv_dbid);
		     stmt;
		     stmt = invoices_next(wallet->invoices, stmt, &inv_dbid)) {
			details = invoices_get_details(tmpctx,
						       wallet->invoices, inv_dbid);
			/* FIXME: db can filter this better! */
			if (local_offer_id) {
				if (!details->local_offer_id
				    || !sha256_eq(local_offer_id,
						  details->local_offer_id))
					continue;
			}
			json_add_invoice(response, NULL, details);
		}
	}
}

static struct command_result *json_listinvoices(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	struct json_escape *label;
	struct json_stream *response;
	struct wallet *wallet = cmd->ld->wallet;
	const char *invstring;
	struct sha256 *payment_hash, *offer_id;
	enum wait_index *listindex;
	u64 *liststart;
	u32 *listlimit;
	char *fail;

	if (!param_check(cmd, buffer, params,
			 p_opt("label", param_label, &label),
			 p_opt("invstring", param_invstring, &invstring),
			 p_opt("payment_hash", param_sha256, &payment_hash),
			 p_opt("offer_id", param_sha256, &offer_id),
			 p_opt("index", param_index, &listindex),
			 p_opt_def("start", param_u64, &liststart, 0),
			 p_opt("limit", param_u32, &listlimit),
			 NULL))
		return command_param_failed();

	/* Yeah, I wasn't sure about this style either.  It's curt though! */
	if (!!label + !!invstring + !!payment_hash + !!offer_id > 1) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Can only specify one of"
				    " {label}, {invstring}, {payment_hash}"
				    " or {offer_id}");
	}
	if (*liststart != 0 && !listindex) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Can only specify {start} with {index}");
	}
	if (listlimit && !listindex) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Can only specify {limit} with {index}");
	}

	/* Extract the payment_hash from the invoice. */
	if (invstring != NULL) {
		struct bolt11 *b11;
		b11 = bolt11_decode(cmd, invstring, cmd->ld->our_features, NULL,
				    NULL, &fail);
		if (b11)
			payment_hash = &b11->payment_hash;
		else {
			struct tlv_invoice *b12
				= invoice_decode(tmpctx, invstring,
						 strlen(invstring),
						 cmd->ld->our_features, NULL,
						 &fail);
			if (!b12 || !b12->invoice_payment_hash) {
				return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
						    "Invalid invstring");
			}
			payment_hash = b12->invoice_payment_hash;
		}
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	response = json_stream_success(cmd);
	json_array_start(response, "invoices");
	json_add_invoices(response, wallet, label, payment_hash, offer_id,
			  listindex, *liststart, listlimit);
	json_array_end(response);
	return command_success(cmd, response);
}

static const struct json_command listinvoices_command = {
	"listinvoices",
	"payment",
	json_listinvoices,
	"Show invoice matching {label}, {invstring}, {payment_hash} or {offerid} (or all, if "
	"no query parameter specified)"
};
AUTODATA(json_command, &listinvoices_command);

static struct command_result *json_delinvoice(struct command *cmd,
					      const char *buffer,
					      const jsmntok_t *obj UNNEEDED,
					      const jsmntok_t *params)
{
	u64 inv_dbid;
	struct invoice_details *details;
	struct json_stream *response;
	const char *status, *actual_status;
	struct json_escape *label;
	struct wallet *wallet = cmd->ld->wallet;
	bool *deldesc;

	if (!param_check(cmd, buffer, params,
			 p_req("label", param_label, &label),
			 p_req("status", param_string, &status),
			 p_opt_def("desconly", param_bool, &deldesc, false),
			 NULL))
		return command_param_failed();

	if (!invoices_find_by_label(wallet->invoices, &inv_dbid, label)) {
		return command_fail(cmd, INVOICE_NOT_FOUND, "Unknown invoice");
	}

	details = invoices_get_details(cmd, cmd->ld->wallet->invoices, inv_dbid);

	/* This is time-sensitive, so only call once; otherwise error msg
	 * might not make sense if it changed! */
	actual_status = invoice_status_str(details->state);
	if (!streq(actual_status, status)) {
		struct json_stream *js;
		js = json_stream_fail(cmd, INVOICE_STATUS_UNEXPECTED,
				      tal_fmt(tmpctx,
					      "Invoice status is %s not %s",
					      actual_status, status));
		json_add_string(js, "current_status", actual_status);
		json_add_string(js, "expected_status", status);
		json_object_end(js);
		return command_failed(cmd, js);
	}

	if (*deldesc) {
		if (!details->description)
			return command_fail(cmd, INVOICE_NO_DESCRIPTION,
					    "Invoice description already removed");

		if (command_check_only(cmd))
			return command_check_done(cmd);

		if (!invoices_delete_description(wallet->invoices, inv_dbid,
						 details->label, details->description)) {
			log_broken(cmd->ld->log,
				   "Error attempting to delete description of invoice %"PRIu64,
				   inv_dbid);
			/* FIXME: allocate a generic DATABASE_ERROR code.  */
			return command_fail(cmd, LIGHTNINGD, "Database error");
		}
		details->description = tal_free(details->description);
	} else {
		if (command_check_only(cmd))
			return command_check_done(cmd);

		if (!invoices_delete(wallet->invoices, inv_dbid,
				     details->state,
				     details->label,
				     details->invstring)) {
			log_broken(cmd->ld->log,
				   "Error attempting to remove invoice %"PRIu64,
				   inv_dbid);
			/* FIXME: allocate a generic DATABASE_ERROR code.  */
			return command_fail(cmd, LIGHTNINGD, "Database error");
		}
	}

	response = json_stream_success(cmd);
	json_add_invoice_fields(response, details);
	return command_success(cmd, response);
}

static const struct json_command delinvoice_command = {
	"delinvoice",
	"payment",
	json_delinvoice,
	"Delete unpaid invoice {label} with {status}",
};
AUTODATA(json_command, &delinvoice_command);

static struct command_result *json_delexpiredinvoice(struct command *cmd,
						     const char *buffer,
						     const jsmntok_t *obj UNNEEDED,
						     const jsmntok_t *params)
{
	u64 *maxexpirytime;

	if (!param(cmd, buffer, params,
		   p_opt_def("maxexpirytime", param_u64, &maxexpirytime,
				 time_now().ts.tv_sec),
		   NULL))
		return command_param_failed();

	invoices_delete_expired(cmd->ld->wallet->invoices, *maxexpirytime);

	return command_success(cmd, json_stream_success(cmd));
}
static const struct json_command delexpiredinvoice_command = {
	"delexpiredinvoice",
	"payment",
	json_delexpiredinvoice,
	"Delete all expired invoices that expired as of given {maxexpirytime} (a UNIX epoch time), or all expired invoices if not specified",
	.depr_start = "v22.11",
	.depr_end = "v24.02",
};
AUTODATA(json_command, &delexpiredinvoice_command);

static struct command_result *json_waitanyinvoice(struct command *cmd,
						  const char *buffer,
						  const jsmntok_t *obj UNNEEDED,
						  const jsmntok_t *params)
{
	u64 *pay_index;
	u64 *timeout;
	struct wallet *wallet = cmd->ld->wallet;

	if (!param(cmd, buffer, params,
		   p_opt_def("lastpay_index", param_u64, &pay_index, 0),
		   p_opt("timeout", &param_u64, &timeout),
		   NULL))
		return command_param_failed();

	/*~ We allocate the timeout and the wallet-waitanyinvoice
	 * in the cmd context, so whichever one manages to complete
	 * the command first (and destroy the cmd context)
	 * auto-cancels the other, is not tal amazing?
	 */
	if (timeout)
		(void) new_reltimer(cmd->ld->timers, cmd,
				    time_from_sec(*timeout),
				    &wait_timed_out, cmd);

	/* Set command as pending. We do not know if
	 * wallet_invoice_waitany will return immediately
	 * or not, so indicating pending is safest.  */
	fixme_ignore(command_still_pending(cmd));

	/* Find next paid invoice. */
	invoices_waitany(cmd, wallet->invoices, *pay_index,
			 &wait_on_invoice, (void*) cmd);

	return command_its_complicated("wallet_invoice_waitany might complete"
				       " immediately, but we also call it as a"
				       " callback so plumbing through the return"
				       " is non-trivial.");
}


static const struct json_command waitanyinvoice_command = {
	"waitanyinvoice",
	"payment",
	json_waitanyinvoice,
	"Wait for the next invoice to be paid, after {lastpay_index} (if supplied).  "
	"If {timeout} seconds is reached while waiting, fail with an error."
};
AUTODATA(json_command, &waitanyinvoice_command);

/* Wait for an incoming payment matching the `label` in the JSON
 * command.  This will either return immediately if the payment has
 * already been received or it may add the `cmd` to the list of
 * waiters, if the payment is still pending.
 */
static struct command_result *json_waitinvoice(struct command *cmd,
					       const char *buffer,
					       const jsmntok_t *obj UNNEEDED,
					       const jsmntok_t *params)
{
	u64 inv_dbid;
	const struct invoice_details *details;
	struct wallet *wallet = cmd->ld->wallet;
	struct json_escape *label;

	if (!param_check(cmd, buffer, params,
			 p_req("label", param_label, &label),
			 NULL))
		return command_param_failed();

	if (!invoices_find_by_label(wallet->invoices, &inv_dbid, label)) {
		return command_fail(cmd, LIGHTNINGD, "Label not found");
	}
	if (command_check_only(cmd))
		return command_check_done(cmd);

	details = invoices_get_details(cmd, cmd->ld->wallet->invoices, inv_dbid);

	/* If paid or expired return immediately */
	if (details->state == PAID || details->state == EXPIRED) {
		return tell_waiter(cmd, inv_dbid);
	} else {
		/* There is an unpaid one matching, let's wait... */
		fixme_ignore(command_still_pending(cmd));
		invoices_waitone(cmd, wallet->invoices, inv_dbid,
				 &wait_on_invoice, (void *) cmd);
		return command_its_complicated("wallet_invoice_waitone might"
					       " complete immediately");
	}
}

static const struct json_command waitinvoice_command = {
	"waitinvoice",
	"payment",
	json_waitinvoice,
	"Wait for an incoming payment matching the invoice with {label}, or if the invoice expires"
};
AUTODATA(json_command, &waitinvoice_command);

static struct command_result *json_decodepay(struct command *cmd,
					     const char *buffer,
					     const jsmntok_t *obj UNNEEDED,
					     const jsmntok_t *params)
{
	struct bolt11 *b11;
	struct json_stream *response;
	const char *str, *desc;
	char *fail;

	if (!param_check(cmd, buffer, params,
			 p_req("bolt11", param_invstring, &str),
			 p_opt("description", param_escaped_string, &desc),
			 NULL))
		return command_param_failed();

	b11 = bolt11_decode(cmd, str, cmd->ld->our_features, desc, NULL,
			    &fail);

	if (!b11) {
		return command_fail(cmd, LIGHTNINGD, "Invalid bolt11: %s", fail);
	}

	if (command_check_only(cmd))
		return command_check_done(cmd);

	response = json_stream_success(cmd);
	json_add_bolt11(response, b11);
	return command_success(cmd, response);
}

static const struct json_command decodepay_command = {
	"decodepay",
	"payment",
	json_decodepay,
	"Decode {bolt11}, using {description} if necessary"
};
AUTODATA(json_command, &decodepay_command);

/* If we fail because it exists, we also return the clashing invoice */
static struct command_result *fail_exists(struct command *cmd,
					  const struct json_escape *label)
{
	struct json_stream *data;
	u64 inv_dbid;
	struct wallet *wallet = cmd->ld->wallet;

	data = json_stream_fail(cmd, INVOICE_LABEL_ALREADY_EXISTS,
				"Duplicate label");
	if (!invoices_find_by_label(wallet->invoices, &inv_dbid, label))
		fatal("Duplicate invoice %s not found any more?",
		      label->s);

	json_add_invoice_fields(data,
				invoices_get_details(cmd, wallet->invoices, inv_dbid));
	json_object_end(data);

	return command_failed(cmd, data);
}

/* This is only if we're a public node; otherwise, the offers plugin
 * will have populated a real blinded path */
static void add_stub_blindedpath(const tal_t *ctx,
				 struct lightningd *ld,
				 struct tlv_invoice *inv)
{
	struct blinded_path *path;
	struct privkey blinding;
	struct tlv_encrypted_data_tlv *tlv;

	path = tal(NULL, struct blinded_path);
	if (!pubkey_from_node_id(&path->first_node_id, &ld->id))
		abort();
	randombytes_buf(&blinding, sizeof(blinding));
	if (!pubkey_from_privkey(&blinding, &path->blinding))
		abort();
	path->path = tal_arr(path, struct onionmsg_hop *, 1);
	path->path[0] = tal(path->path, struct onionmsg_hop);

	/* A message in a bottle to ourselves: match it with
	 * the invoice: we assume the payment_hash is unique! */
	tlv = tlv_encrypted_data_tlv_new(tmpctx);
	tlv->path_id = invoice_path_id(inv,
				       &ld->invoicesecret_base,
				       inv->invoice_payment_hash);

	path->path[0]->encrypted_recipient_data
		= encrypt_tlv_encrypted_data(path->path[0],
					     &blinding,
					     &path->first_node_id,
					     tlv,
					     NULL,
					     &path->path[0]->blinded_node_id);

	inv->invoice_paths = tal_arr(inv, struct blinded_path *, 1);
	inv->invoice_paths[0] = tal_steal(inv->invoice_paths, path);

	/* BOLT-offers #12:
	 *  - MUST include `invoice_paths` containing one or more paths to the node.
	 *  - MUST specify `invoice_paths` in order of most-preferred to least-preferred if it has a preference.
	 *  - MUST include `invoice_blindedpay` with exactly one `blinded_payinfo` for each `blinded_path` in `paths`, in order.
	 */
	inv->invoice_blindedpay = tal_arr(inv, struct blinded_payinfo *, 1);
	inv->invoice_blindedpay[0] = tal(inv->invoice_blindedpay,
					 struct blinded_payinfo);
	inv->invoice_blindedpay[0]->fee_base_msat = 0;
	inv->invoice_blindedpay[0]->fee_proportional_millionths = 0;
	inv->invoice_blindedpay[0]->cltv_expiry_delta = ld->config.cltv_final;
	inv->invoice_blindedpay[0]->htlc_minimum_msat = AMOUNT_MSAT(0);
	inv->invoice_blindedpay[0]->htlc_maximum_msat = AMOUNT_MSAT(21000000 * MSAT_PER_BTC);
	inv->invoice_blindedpay[0]->features = NULL;

	/* Recalc ->fields */
	tal_free(inv->fields);
	inv->fields = tlv_make_fields(inv, tlv_invoice);
}

static struct command_result *json_createinvoice(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	const char *invstring;
	struct json_escape *label;
	struct preimage *preimage;
	u64 inv_dbid;
	struct sha256 payment_hash;
	struct json_stream *response;
	struct bolt11 *b11;
	struct sha256 hash;
	const u5 *sig;
	bool have_n;
	char *fail;

	if (!param_check(cmd, buffer, params,
			 p_req("invstring", param_invstring, &invstring),
			 p_req("label", param_label, &label),
			 p_req("preimage", param_preimage, &preimage),
			 NULL))
		return command_param_failed();

	sha256(&payment_hash, preimage, sizeof(*preimage));
	b11 = bolt11_decode_nosig(cmd, invstring, cmd->ld->our_features,
				  NULL, chainparams, &hash, &sig, &have_n,
				  &fail);
	if (b11) {
		/* This adds the signature */
		char *b11enc = bolt11_encode(cmd, b11, have_n,
					     hsm_sign_b11, cmd->ld);

		if (!b11->description)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Missing description in invoice");

		if (!b11->expiry)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Missing expiry in invoice");

		if (!sha256_eq(&payment_hash, &b11->payment_hash))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Incorrect preimage");

		if (command_check_only(cmd))
			return command_check_done(cmd);

		if (!invoices_create(cmd->ld->wallet->invoices,
				     &inv_dbid,
				     b11->msat,
				     label,
				     b11->expiry,
				     b11enc,
				     b11->description,
				     b11->features,
				     preimage,
				     &payment_hash,
				     NULL))
			return fail_exists(cmd, label);

		notify_invoice_creation(cmd->ld, b11->msat, preimage, label);
	} else {
		struct tlv_invoice *inv;
		struct sha256 offer_id, *local_offer_id;
		char *b12enc;
		struct amount_msat msat;
		const char *desc;
		u32 expiry;
		enum offer_status status;

		inv = invoice_decode_nosig(cmd, invstring, strlen(invstring),
					   cmd->ld->our_features, chainparams,
					   &fail);
		if (!inv)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Unparsable invoice '%s': %s",
					    invstring, fail);

		/* BOLT-offers #12:
		 * A writer of an invoice:
		 *...
		 *   - MUST include `invoice_paths` containing one or more paths
		 *    to the node.
		 */
		/* If they don't create a blinded path, add a simple one so we
		 * can recognize payments (bolt12 doesn't use
		 * payment_secret) */
		if (!inv->invoice_paths)
			add_stub_blindedpath(cmd, cmd->ld, inv);

		if (inv->signature)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "invoice already signed");
		hsm_sign_b12_invoice(cmd->ld, inv);
		b12enc = invoice_encode(cmd, inv);

		if (inv->offer_node_id) {
			invoice_offer_id(inv, &offer_id);
			if (wallet_offer_find(tmpctx, cmd->ld->wallet,
					      &offer_id, NULL, &status)) {
				if (!offer_status_active(status))
					return command_fail(cmd,
							    INVOICE_OFFER_INACTIVE,
							    "offer not active");
				local_offer_id = &offer_id;
			} else
				local_offer_id = NULL;
		} else
			local_offer_id = NULL;

		/* BOLT-offers #12:
		 * A writer of an invoice:
		 *...
		 * - MUST set `invoice_amount` to the minimum amount it will
		 *   accept, in units of the minimal lightning-payable unit
		 *   (e.g. milli-satoshis for bitcoin) for `invreq_chain`.
		 */
		if (!inv->invoice_amount)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Missing invoice_amount in invoice");
		msat = amount_msat(*inv->invoice_amount);

		if (inv->invoice_relative_expiry)
			expiry = *inv->invoice_relative_expiry;
		else
			expiry = BOLT12_DEFAULT_REL_EXPIRY;

		if (!inv->invoice_payment_hash)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Missing payment_hash in invoice");
		if (!sha256_eq(&payment_hash, inv->invoice_payment_hash))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Incorrect preimage");

		if (!inv->offer_description)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "Missing description in invoice");

		if (command_check_only(cmd))
			return command_check_done(cmd);

		desc = tal_strndup(cmd,
				   inv->offer_description,
				   tal_bytelen(inv->offer_description));

		if (!invoices_create(cmd->ld->wallet->invoices,
				     &inv_dbid,
				     &msat,
				     label,
				     expiry,
				     b12enc,
				     desc,
				     inv->invoice_features,
				     preimage,
				     &payment_hash,
				     local_offer_id))
			return fail_exists(cmd, label);

		notify_invoice_creation(cmd->ld, &msat,	preimage, label);
	}

	response = json_stream_success(cmd);
	json_add_invoice_fields(response,
				invoices_get_details(cmd, cmd->ld->wallet->invoices,
						     inv_dbid));
	return command_success(cmd, response);
}

static const struct json_command createinvoice_command = {
	"createinvoice",
	"payment",
	json_createinvoice,
	"Lowlevel command to sign and create invoice {invstring}, resolved with {preimage}, using unique {label}."
};

AUTODATA(json_command, &createinvoice_command);

static struct command_result *json_preapproveinvoice(struct command *cmd,
						     const char *buffer,
						     const jsmntok_t *obj UNNEEDED,
						     const jsmntok_t *params)
{
	const char *invstring;
	struct json_stream *response;
	bool approved;
	u8 *req;
	const u8 *msg;

	if (!param(cmd, buffer, params,
		   /* FIXME: parameter should be invstring now */
		   p_req("bolt11", param_invstring, &invstring),
		   NULL))
		return command_param_failed();

	/* Old version didn't have `bool check_only` at end */
	if (!hsm_capable(cmd->ld, WIRE_HSMD_PREAPPROVE_INVOICE_CHECK))
		req = towire_hsmd_preapprove_invoice(NULL, invstring);
	else
		req = towire_hsmd_preapprove_invoice_check(NULL, invstring, false);

	msg = hsm_sync_req(tmpctx, cmd->ld, take(req));

	/* These are identical, but use separate numbers for clarity */
        if (!fromwire_hsmd_preapprove_invoice_reply(msg, &approved)
	    && !fromwire_hsmd_preapprove_invoice_check_reply(msg, &approved)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "HSM gave bad preapprove_invoice_reply %s", tal_hex(msg, msg));
	}

	if (!approved)
		return command_fail(cmd, PAY_INVOICE_PREAPPROVAL_DECLINED, "invoice was declined");

	response = json_stream_success(cmd);
	return command_success(cmd, response);
}

static const struct json_command preapproveinvoice_command = {
	"preapproveinvoice",
	"payment",
	json_preapproveinvoice,
	"Ask the HSM to preapprove an invoice."
};
AUTODATA(json_command, &preapproveinvoice_command);

static struct command_result *json_preapprovekeysend(struct command *cmd,
						     const char *buffer,
						     const jsmntok_t *obj UNNEEDED,
						     const jsmntok_t *params)
{
	struct node_id *destination;
	struct sha256 *payment_hash;
	struct amount_msat *amount;
	struct json_stream *response;
	bool approved;
	const u8 *msg;
	u8 *req;

	if (!param(cmd, buffer, params,
		   p_req("destination", param_node_id, &destination),
		   p_req("payment_hash", param_sha256, &payment_hash),
		   p_req("amount_msat", param_msat, &amount),
		   NULL))
		return command_param_failed();

	if (!hsm_capable(cmd->ld, WIRE_HSMD_PREAPPROVE_KEYSEND_CHECK))
		req = towire_hsmd_preapprove_keysend(NULL, destination, payment_hash, *amount);
	else
		req = towire_hsmd_preapprove_keysend_check(NULL, destination, payment_hash,
							   *amount, false);

	msg = hsm_sync_req(tmpctx, cmd->ld, take(req));

	/* These are identical, but use separate numbers for clarity */
        if (!fromwire_hsmd_preapprove_keysend_reply(msg, &approved)
	    && !fromwire_hsmd_preapprove_keysend_check_reply(msg, &approved)) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "HSM gave bad preapprove_keysend_reply %s", tal_hex(msg, msg));
	}

	if (!approved)
		return command_fail(cmd, PAY_KEYSEND_PREAPPROVAL_DECLINED, "keysend was declined");

	response = json_stream_success(cmd);
	return command_success(cmd, response);
}

static const struct json_command preapprovekeysend_command = {
	"preapprovekeysend",
	"payment",
	json_preapprovekeysend,
	"Ask the HSM to preapprove a keysend payment."
};
AUTODATA(json_command, &preapprovekeysend_command);

static struct command_result *json_signinvoice(struct command *cmd,
						 const char *buffer,
						 const jsmntok_t *obj UNNEEDED,
						 const jsmntok_t *params)
{
	const char *invstring;
	struct json_stream *response;
	struct bolt11 *b11;
	struct sha256 hash;
	const u5 *sig;
	bool have_n;
	char *fail;

	if (!param_check(cmd, buffer, params,
			 p_req("invstring", param_invstring, &invstring),
			 NULL))
		return command_param_failed();

	b11 = bolt11_decode_nosig(cmd, invstring, cmd->ld->our_features,
				  NULL, chainparams, &hash, &sig, &have_n,
				  &fail);

	if (!b11)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Unparsable invoice '%s': %s",
				    invstring, fail);

	/* This adds the signature */
	char *b11enc = bolt11_encode(cmd, b11, have_n,
				     hsm_sign_b11, cmd->ld);

        /* BOLT #11:
         * A writer:
         *...
         *    - MUST include either exactly one `d` or exactly one `h` field.
         */
	if (!b11->description && !b11->description_hash)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Missing description in invoice");

	if (command_check_only(cmd))
		return command_check_done(cmd);

	response = json_stream_success(cmd);
	json_add_invstring(response, b11enc);
	return command_success(cmd, response);
}

static const struct json_command signinvoice_command = {
	"signinvoice",
	"payment",
	json_signinvoice,
	"Lowlevel command to sign invoice {invstring}."
};

AUTODATA(json_command, &signinvoice_command);
