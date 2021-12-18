#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/asort/asort.h>
#include <ccan/tal/str/str.h>
#include <common/json_tok.h>
#include <common/type_to_string.h>
#include <plugins/libplugin-pay.h>
#include <sodium.h>

#define PREIMAGE_TLV_TYPE 5482373484
#define KEYSEND_FEATUREBIT 55
static unsigned int maxdelay_default;
static struct node_id my_id;

/*****************************************************************************
 * Keysend modifier
 * ================
 *
 * The keysend modifier adds the payment preimage to the TLV payload. This
 * enables the recipient to accept the payment despite it not correspondin to
 * an invoice that the recipient created. Keysend does not provide any proof
 * or payment, but does not require an out-of-band communication round to get
 * an invoice first.
 */

/* FIXME: If we have more than one plugin using keysend we can move this to
 * libplugin-pay.c */

struct keysend_data {
	struct preimage preimage;
	struct tlv_field *extra_tlvs;
};

REGISTER_PAYMENT_MODIFIER_HEADER(keysend, struct keysend_data);

static struct keysend_data *keysend_init(struct payment *p)
{
	struct keysend_data *d;
	struct sha256 payment_hash;
	if (p->parent == NULL) {
		/* If we are the root payment we generate a random preimage
		 * and populate the preimage field in the keysend_data and the
		 * payment_hash in the payment. */
		d = tal(p, struct keysend_data);
		randombytes_buf(&d->preimage, sizeof(d->preimage));
		ccan_sha256(&payment_hash, &d->preimage, sizeof(d->preimage));
		p->payment_hash = tal_dup(p, struct sha256, &payment_hash);
#if EXPERIMENTAL_FEATURES
		d->extra_tlvs = NULL;
#endif
		return d;
	} else {
		/* If we are a child payment (retry or split) we copy the
		 * parent's information, since the payment_hash needs to match
		 * in order to be collated at the recipient. */
		return payment_mod_keysend_get_data(p->parent);
	}
}

static void keysend_cb(struct keysend_data *d, struct payment *p) {
	struct createonion_hop *last_payload;
	size_t hopcount;

	/* On the root payment we perform the featurebit check. */
	if (p->parent == NULL && p->step == PAYMENT_STEP_INITIALIZED) {
		if (!payment_root(p)->destination_has_tlv)
			return payment_fail(
			    p,
			    "Recipient %s does not support keysend payments "
			    "(no TLV support)",
			    node_id_to_hexstr(tmpctx, p->destination));
	} else if (p->step == PAYMENT_STEP_FAILED) {
		/* Now we can look at the error, and the failing node,
		   and determine whether they didn't like our
		   attempt. This is required since most nodes don't
		   explicitly signal support for keysend through the
		   featurebit method.*/

		if (p->result != NULL &&
		    node_id_eq(p->destination, p->result->erring_node) &&
		    p->result->failcode == WIRE_INVALID_ONION_PAYLOAD) {
			return payment_abort(
			    p,
			    "Recipient %s reported an invalid payload, this "
			    "usually means they don't support keysend.",
			    node_id_to_hexstr(tmpctx, p->destination));
		}
	}

	if (p->step != PAYMENT_STEP_ONION_PAYLOAD)
		return payment_continue(p);

	hopcount = tal_count(p->createonion_request->hops);
	last_payload = &p->createonion_request->hops[hopcount - 1];
	tlvstream_set_raw(&last_payload->tlv_payload->fields, PREIMAGE_TLV_TYPE,
			  &d->preimage, sizeof(struct preimage));

#if EXPERIMENTAL_FEATURES
	if (d->extra_tlvs != NULL) {
		for (size_t i = 0; i < tal_count(d->extra_tlvs); i++) {
			struct tlv_field *f = &d->extra_tlvs[i];
			tlvstream_set_raw(&last_payload->tlv_payload->fields,
					  f->numtype, f->value, f->length);
		}
	}
#endif

	return payment_continue(p);
}

REGISTER_PAYMENT_MODIFIER(keysend, struct keysend_data *, keysend_init,
			  keysend_cb);
/*
 * End of keysend modifier
 *****************************************************************************/

static const char *init(struct plugin *p, const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	rpc_scan(p, "getinfo", take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%}", JSON_SCAN(json_to_node_id, &my_id));

	rpc_scan(p, "listconfigs",
		 take(json_out_obj(NULL, "config", "max-locktime-blocks")),
		 "{max-locktime-blocks:%}",
		 JSON_SCAN(json_to_number, &maxdelay_default));

	return NULL;
}

struct payment_modifier *pay_mods[] = {
    &keysend_pay_mod,
    &local_channel_hints_pay_mod,
    &directpay_pay_mod,
    &shadowroute_pay_mod,
    &routehints_pay_mod,
    &exemptfee_pay_mod,
    &waitblockheight_pay_mod,
    &retry_pay_mod,
    NULL,
};

static struct command_result *json_keysend(struct command *cmd, const char *buf,
					   const jsmntok_t *params)
{
	struct payment *p;
	const char *label;
	struct amount_msat *exemptfee, *msat;
	struct node_id *destination;
	u64 *maxfee_pct_millionths;
	u32 *maxdelay;
	unsigned int *retryfor;
	struct route_info **hints;
#if EXPERIMENTAL_FEATURES
	struct tlv_field *extra_fields;
#endif

#if DEVELOPER
	bool *use_shadow;
#endif
	if (!param(cmd, buf, params,
		   p_req("destination", param_node_id, &destination),
		   p_req("msatoshi", param_msat, &msat),
		   p_opt("label", param_string, &label),
		   p_opt_def("maxfeepercent", param_millionths,
			     &maxfee_pct_millionths, 500000),
		   p_opt_def("retry_for", param_number, &retryfor, 60),
		   p_opt_def("maxdelay", param_number, &maxdelay,
			     maxdelay_default),
		   p_opt_def("exemptfee", param_msat, &exemptfee, AMOUNT_MSAT(5000)),
#if DEVELOPER
		   p_opt_def("use_shadow", param_bool, &use_shadow, true),
#endif
		   p_opt("routehints", param_routehint_array, &hints),
#if EXPERIMENTAL_FEATURES
		   p_opt("extratlvs", param_extra_tlvs, &extra_fields),
#endif
		   NULL))
		return command_param_failed();

	p = payment_new(cmd, cmd, NULL /* No parent */, pay_mods);
	p->local_id = &my_id;
	p->json_buffer = tal_dup_talarr(p, const char, buf);
	p->json_toks = params;
	p->destination = tal_steal(p, destination);
	p->destination_has_tlv = true;
	p->payment_secret = NULL;
	p->amount = *msat;
	p->routes = tal_steal(p, hints);
	// 22 is the Rust-Lightning default and the highest minimum we know of.
	p->min_final_cltv_expiry = 22;
	p->features = NULL;
	p->invstring = NULL;
	p->why = "Initial attempt";
	p->constraints.cltv_budget = *maxdelay;
	p->deadline = timeabs_add(time_now(), time_from_sec(*retryfor));
	p->getroute->riskfactorppm = 10000000;

	if (node_id_eq(&my_id, p->destination)) {
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "We are the destination. Keysend cannot be used to send funds to yourself");
	}

	if (!amount_msat_fee(&p->constraints.fee_budget, p->amount, 0,
			     *maxfee_pct_millionths / 100)) {
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "Overflow when computing fee budget, fee rate too high.");
	}

	p->constraints.cltv_budget = *maxdelay;

#if EXPERIMENTAL_FEATURES
	payment_mod_keysend_get_data(p)->extra_tlvs =
	    tal_steal(p, extra_fields);
#endif

	payment_mod_exemptfee_get_data(p)->amount = *exemptfee;
#if DEVELOPER
	payment_mod_shadowroute_get_data(p)->use_shadow = *use_shadow;
#endif
	p->label = tal_steal(p, label);
	payment_start(p);
	/* We're keeping this around now */
	tal_steal(cmd->plugin, p);
	return command_still_pending(cmd);
}

static const struct plugin_command commands[] = {
    {
	    "keysend",
	    "payment",
	    "Send a payment without an invoice to a node",
            "Send an unsolicited payment of {amount} to {destination}, by providing the recipient the necessary information to claim the payment",
            json_keysend
    },
};

static struct command_result *
htlc_accepted_continue(struct command *cmd, struct tlv_tlv_payload *payload)
{
	struct json_stream *response;
	response = jsonrpc_stream_success(cmd);

	json_add_string(response, "result", "continue");
	if (payload) {
		u8 *binpayload = tal_arr(cmd, u8, 0);
		towire_tlvstream_raw(&binpayload, payload->fields);
		json_add_string(response, "payload", tal_hex(cmd, binpayload));
	}
	return command_finished(cmd, response);
}

/* Struct wrapping the information we extract from an incoming keysend
 * payment */
struct keysend_in {
	struct sha256 payment_hash;
	struct preimage payment_preimage;
	char *label;
	struct tlv_tlv_payload *payload;
	struct tlv_field *preimage_field;
};

static int tlvfield_cmp(const struct tlv_field *a,
			const struct tlv_field *b, void *unused)
{
	if (a->numtype > b->numtype)
		return 1;
	else if (a->numtype < b->numtype)
		return -1;
	return 0;
}

static struct command_result *
htlc_accepted_invoice_created(struct command *cmd, const char *buf,
			      const jsmntok_t *result,
			      struct keysend_in *ki)
{
	struct tlv_field field;
	int preimage_field_idx = ki->preimage_field - ki->payload->fields;

	/* Remove the preimage field so `lightningd` knows how to handle
	 * this. */
	tal_arr_remove(&ki->payload->fields, preimage_field_idx);

	/* Now we can fill in the payment secret, from invoice. */
	ki->payload->payment_data = tal(ki->payload,
					struct tlv_tlv_payload_payment_data);
	json_to_secret(buf, json_get_member(buf, result, "payment_secret"),
		       &ki->payload->payment_data->payment_secret);

	/* We checked that amt_to_forward was non-NULL before */
	ki->payload->payment_data->total_msat = *ki->payload->amt_to_forward;

	/* In order to put payment_data into ->fields, I'd normally re-serialize,
	 * but we can have completely unknown fields.  So insert manually. */
	/* BOLT #4:
	 *     1. type: 8 (`payment_data`)
	 *     2. data:
	 *         * [`32*byte`:`payment_secret`]
	 *         * [`tu64`:`total_msat`]
	 */
	field.numtype = 8;
	field.value = tal_arr(ki->payload, u8, 0);
	towire_secret(&field.value, &ki->payload->payment_data->payment_secret);
	towire_tu64(&field.value, ki->payload->payment_data->total_msat);
	field.length = tal_bytelen(field.value);
	tal_arr_expand(&ki->payload->fields, field);

	asort(ki->payload->fields, tal_count(ki->payload->fields),
	      tlvfield_cmp, NULL);

	/* Finally we can resolve the payment with the preimage. */
	plugin_log(cmd->plugin, LOG_INFORM,
		   "Resolving incoming HTLC with preimage for payment_hash %s "
		   "provided in the onion payload.",
		   tal_hexstr(tmpctx, &ki->payment_hash, sizeof(struct sha256)));
	return htlc_accepted_continue(cmd, ki->payload);

}

static struct command_result *
htlc_accepted_invoice_failed(struct command *cmd, const char *buf,
			     const jsmntok_t *error,
			     struct keysend_in *ki)
{
	plugin_log(cmd->plugin, LOG_BROKEN,
		   "Could not create invoice for keysend: %.*s",
		   json_tok_full_len(error),
		   json_tok_full(buf, error));
	/* Continue, but don't change it: it will fail. */
	return htlc_accepted_continue(cmd, NULL);

}

static struct command_result *htlc_accepted_call(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params)
{
	const u8 *rawpayload;
	struct sha256 payment_hash;
	size_t max;
	struct tlv_tlv_payload *payload;
	struct tlv_field *preimage_field = NULL, *unknown_field = NULL;
	bigsize_t s;
	struct tlv_field *field;
	struct keysend_in *ki;
	struct out_req *req;
	struct timeabs now = time_now();
	const char *err;

	err = json_scan(tmpctx, buf, params,
			"{onion:{payload:%},htlc:{payment_hash:%}}",
			JSON_SCAN_TAL(cmd, json_tok_bin_from_hex, &rawpayload),
			JSON_SCAN(json_to_sha256, &payment_hash));
	if (err)
		return htlc_accepted_continue(cmd, NULL);

	max = tal_bytelen(rawpayload);
	payload = tlv_tlv_payload_new(cmd);

	s = fromwire_bigsize(&rawpayload, &max);
	if (s != max) {
		return htlc_accepted_continue(cmd, NULL);
	}
	if (!fromwire_tlv_payload(&rawpayload, &max, payload)) {
		plugin_log(
		    cmd->plugin, LOG_UNUSUAL, "Malformed TLV payload %.*s",
		    json_tok_full_len(params),
		    json_tok_full(buf, params));
		return htlc_accepted_continue(cmd, NULL);
	}

	/* Try looking for the field that contains the preimage */
	for (int i=0; i<tal_count(payload->fields); i++) {
		field = &payload->fields[i];
		if (field->numtype == PREIMAGE_TLV_TYPE) {
			preimage_field = field;
			break;
		} else if (field->numtype % 2 == 0 && field->meta == NULL) {
			unknown_field = field;
		}
	}

	/* If we don't have a preimage field then this is not a keysend, let
	 * someone else take care of it. */
	if (preimage_field == NULL)
		return htlc_accepted_continue(cmd, NULL);

	if (unknown_field != NULL) {
#if !EXPERIMENTAL_FEATURES
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "Payload contains unknown even TLV-type %" PRIu64
			   ", can't safely accept the keysend. Deferring to "
			   "other plugins.",
			   unknown_field->numtype);
		return htlc_accepted_continue(cmd, NULL);
#else
		plugin_log(cmd->plugin, LOG_INFORM,
			   "Experimental: Accepting the keysend payment "
			   "despite having unknown even TLV type %" PRIu64 ".",
			   unknown_field->numtype);
#endif
	}

	/* If malformed (amt is compulsory), let lightningd handle it. */
	if (!payload->amt_to_forward) {
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "Sender omitted amount.  Ignoring this HTLC.");
		return htlc_accepted_continue(cmd, NULL);
	}

	/* If the preimage is not 32 bytes long then we can't accept the
	 * payment. */
	if (preimage_field->length != 32) {
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "Sender specified a preimage that is %zu bytes long, "
			   "we expected 32 bytes. Ignoring this HTLC.",
			   preimage_field->length);
		return htlc_accepted_continue(cmd, NULL);
	}

	ki = tal(cmd, struct keysend_in);
	memcpy(&ki->payment_preimage, preimage_field->value, 32);
	ki->label = tal_fmt(ki, "keysend-%lu.%09lu", (unsigned long)now.ts.tv_sec, now.ts.tv_nsec);
	ki->payload = tal_steal(ki, payload);
	ki->preimage_field = preimage_field;

	/* If the preimage doesn't hash to the payment_hash we must continue,
	 * maybe someone else knows how to handle these. */
	sha256(&ki->payment_hash, preimage_field->value, preimage_field->length);
	if (!sha256_eq(&ki->payment_hash, &payment_hash)) {
		plugin_log(
		    cmd->plugin, LOG_UNUSUAL,
		    "Preimage provided by the sender does not match the "
		    "payment_hash: SHA256(%s)=%s != %s. Ignoring keysend.",
		    tal_hexstr(tmpctx,
			       preimage_field->value, preimage_field->length),
		    type_to_string(tmpctx, struct sha256, &ki->payment_hash),
		    type_to_string(tmpctx, struct sha256, &payment_hash));
		tal_free(ki);
		return htlc_accepted_continue(cmd, NULL);
	}

	/* Now we can call `invoice` RPC to backfill an invoce matching this
	 * spontaneous payment, thus leaving us with an accounting
	 * trace. Creating the invoice is best effort: it may fail if the
	 * `payment_hash` is already attached to an existing invoice, and the
	 * label could collide (unlikely since we use the nanosecond time). If
	 * the call to `invoice` fails we will just continue, and `lightningd`
	 * will be nice and reject the payment. */
	req = jsonrpc_request_start(cmd->plugin, cmd, "invoice",
				    &htlc_accepted_invoice_created,
				    &htlc_accepted_invoice_failed,
				    ki);

	plugin_log(cmd->plugin, LOG_INFORM, "Inserting a new invoice for keysend with payment_hash %s", type_to_string(tmpctx, struct sha256, &payment_hash));
	json_add_string(req->js, "msatoshi", "any");
	json_add_string(req->js, "label", ki->label);
	json_add_string(req->js, "description", "Spontaneous incoming payment through keysend");
	json_add_preimage(req->js, "preimage", &ki->payment_preimage);

	return send_outreq(cmd->plugin, req);
}

static const struct plugin_hook hooks[] = {
	{
		"htlc_accepted",
		htlc_accepted_call
	},
};

static const char *notification_topics[] = {
	"pay_success",
	"pay_failure",
};

int main(int argc, char *argv[])
{
	struct feature_set *features = tal(NULL, struct feature_set);
	setup_locale();

	for (int i=0; i<ARRAY_SIZE(features->bits); i++)
		features->bits[i] = tal_arr(features, u8, 0);
	set_feature_bit(&features->bits[NODE_ANNOUNCE_FEATURE], KEYSEND_FEATUREBIT);

	plugin_main(argv, init, PLUGIN_STATIC, true, features, commands,
		    ARRAY_SIZE(commands), NULL, 0, hooks, ARRAY_SIZE(hooks),
		    notification_topics, ARRAY_SIZE(notification_topics), NULL);
}
