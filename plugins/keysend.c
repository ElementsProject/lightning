#include <bitcoin/preimage.h>
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <plugins/libplugin-pay.h>
#include <plugins/libplugin.h>
#include <wire/gen_onion_wire.h>

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
		return d;
	} else {
		/* If we are a child payment (retry or split) we copy the
		 * parent's information, since the payment_hash needs to match
		 * in order to be collated at the recipient. */
		return payment_mod_keysend_get_data(p->parent);
	}
}

static void keysend_cb(struct keysend_data *d, struct payment *p) {
	struct route_hop *last_hop;
	struct createonion_hop *last_payload;
	size_t hopcount;

	if (p->step == PAYMENT_STEP_GOT_ROUTE) {
		/* Force the last step to be a TLV, we might not have an
		 * announcement and it still supports it. Required later when
		 * we adjust the payload. */
		last_hop = &p->route[tal_count(p->route) - 1];
		last_hop->style = ROUTE_HOP_TLV;
	}

	if (p->step != PAYMENT_STEP_ONION_PAYLOAD)
		return payment_continue(p);

	hopcount = tal_count(p->createonion_request->hops);
	last_payload = &p->createonion_request->hops[hopcount - 1];
	tlvstream_set_raw(&last_payload->tlv_payload->fields, PREIMAGE_TLV_TYPE,
			  &d->preimage, sizeof(struct preimage));

	return payment_continue(p);
}

REGISTER_PAYMENT_MODIFIER(keysend, struct keysend_data *, keysend_init,
			  keysend_cb);
/*
 * End of keysend modifier
 *****************************************************************************/

static void init(struct plugin *p, const char *buf UNUSED,
		 const jsmntok_t *config UNUSED)
{
	const char *field;

	field = rpc_delve(tmpctx, p, "getinfo",
			  take(json_out_obj(NULL, NULL, NULL)), ".id");
	if (!node_id_from_hexstr(field, strlen(field), &my_id))
		plugin_err(p, "getinfo didn't contain valid id: '%s'", field);

	field =
	    rpc_delve(tmpctx, p, "listconfigs",
		      take(json_out_obj(NULL, "config", "max-locktime-blocks")),
		      ".max-locktime-blocks");
	maxdelay_default = atoi(field);
}

struct payment_modifier *pay_mods[8] = {
    &keysend_pay_mod,
    &local_channel_hints_pay_mod,
    &directpay_pay_mod,
    &shadowroute_pay_mod,
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
#if DEVELOPER
	bool *use_shadow;
#endif
	p = payment_new(NULL, cmd, NULL /* No parent */, pay_mods);
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
		   NULL))
		return command_param_failed();

	p->local_id = &my_id;
	p->json_buffer = tal_steal(p, buf);
	p->json_toks = params;
	p->destination = tal_steal(p, destination);
	p->payment_secret = NULL;
	p->amount = *msat;
	p->invoice = NULL;
	p->bolt11 = NULL;
	p->why = "Initial attempt";
	p->constraints.cltv_budget = *maxdelay;
	p->deadline = timeabs_add(time_now(), time_from_sec(*retryfor));
	p->getroute->riskfactorppm = 10000000;

	if (!amount_msat_fee(&p->constraints.fee_budget, p->amount, 0,
			     *maxfee_pct_millionths / 100)) {
		tal_free(p);
		return command_fail(
		    cmd, JSONRPC2_INVALID_PARAMS,
		    "Overflow when computing fee budget, fee rate too high.");
	}
	p->constraints.cltv_budget = *maxdelay;

	payment_mod_exemptfee_get_data(p)->amount = *exemptfee;
#if DEVELOPER
	payment_mod_shadowroute_get_data(p)->use_shadow = *use_shadow;
#endif
	p->label = tal_steal(p, label);
	payment_start(p);
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

static struct command_result *
htlc_accepted_invoice_created(struct command *cmd, const char *buf UNUSED,
			      const jsmntok_t *result UNUSED,
			      struct keysend_in *ki)
{
	int preimage_field_idx = ki->preimage_field - ki->payload->fields;

	/* Remove the preimage field so `lightningd` knows how to handle
	 * this. */
	tal_arr_remove(&ki->payload->fields, preimage_field_idx);

	/* Finally we can resolve the payment with the preimage. */
	plugin_log(cmd->plugin, LOG_INFORM,
		   "Resolving incoming HTLC with preimage for payment_hash %s "
		   "provided in the onion payload.",
		   tal_hexstr(tmpctx, &ki->payment_hash, sizeof(struct sha256)));
	return htlc_accepted_continue(cmd, ki->payload);

}

static struct command_result *htlc_accepted_call(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params)
{
	const jsmntok_t *payloadt = json_delve(buf, params, ".onion.payload");
	const jsmntok_t *payment_hash_tok = json_delve(buf, params, ".htlc.payment_hash");
	const u8 *rawpayload;
	size_t max;
	struct tlv_tlv_payload *payload;
	struct tlv_field *preimage_field = NULL;
	char *hexpreimage, *hexpaymenthash;
	bigsize_t s;
	bool unknown_even_type = false;
	struct tlv_field *field;
	struct keysend_in *ki;
	struct out_req *req;
	struct timeabs now = time_now();

	if (!payloadt)
		return htlc_accepted_continue(cmd, NULL);

	rawpayload = json_tok_bin_from_hex(cmd, buf, payloadt);
	max = tal_bytelen(rawpayload);
	payload = tlv_tlv_payload_new(cmd);

	s = fromwire_varint(&rawpayload, &max);
	if (s != max) {
		return htlc_accepted_continue(cmd, NULL);
	}
	if (!fromwire_tlv_payload(&rawpayload, &max, payload)) {
		plugin_log(
		    cmd->plugin, LOG_UNUSUAL, "Malformed TLV payload %.*s",
		    payloadt->end - payloadt->start, buf + payloadt->start);
		return htlc_accepted_continue(cmd, NULL);
	}

	/* Try looking for the field that contains the preimage */
	for (int i=0; i<tal_count(payload->fields); i++) {
		field = &payload->fields[i];
		if (field->numtype == PREIMAGE_TLV_TYPE) {
			preimage_field = field;
			break;
		} else if (field->numtype % 2 == 0 && field->meta == NULL) {
			unknown_even_type = true;
			break;
		}
	}

	/* If we don't have a preimage field then this is not a keysend, let
	 * someone else take care of it. */
	if (preimage_field == NULL)
		return htlc_accepted_continue(cmd, NULL);

	if (unknown_even_type) {
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "Payload contains unknown even TLV-type %" PRIu64
			   ", can't safely accept the keysend. Deferring to "
			   "other plugins.",
			   preimage_field->numtype);
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

	hexpreimage = tal_hex(cmd, preimage_field->value);

	/* If the preimage doesn't hash to the payment_hash we must continue,
	 * maybe someone else knows how to handle these. */
	sha256(&ki->payment_hash, preimage_field->value, preimage_field->length);
	hexpaymenthash = tal_hexstr(cmd, &ki->payment_hash, sizeof(ki->payment_hash));
	if (!json_tok_streq(buf, payment_hash_tok, hexpaymenthash)) {
		plugin_log(
		    cmd->plugin, LOG_UNUSUAL,
		    "Preimage provided by the sender does not match the "
		    "payment_hash: SHA256(%s)=%s != %.*s. Ignoring keysend.",
		    hexpreimage, hexpaymenthash,
		    payment_hash_tok->end - payment_hash_tok->start,
		    buf + payment_hash_tok->start);
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
				    &htlc_accepted_invoice_created,
				    ki);

	plugin_log(cmd->plugin, LOG_INFORM, "Inserting a new invoice for keysend with payment_hash %s", hexpaymenthash);
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

int main(int argc, char *argv[])
{
	struct feature_set features;
	setup_locale();

	for (int i=0; i<ARRAY_SIZE(features.bits); i++)
		features.bits[i] = tal_arr(NULL, u8, 0);
	set_feature_bit(&features.bits[NODE_ANNOUNCE_FEATURE], KEYSEND_FEATUREBIT);

	plugin_main(argv, init, PLUGIN_STATIC, true, &features, commands,
		    ARRAY_SIZE(commands), NULL, 0, hooks, ARRAY_SIZE(hooks),
		    NULL);
}
