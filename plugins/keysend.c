#include <bitcoin/preimage.h>
#include <ccan/array_size/array_size.h>
#include <plugins/libplugin.h>
#include <wire/gen_onion_wire.h>

#define PREIMAGE_TLV_TYPE 5482373484
#define KEYSEND_FEATUREBIT 55

static void init(struct plugin *p, const char *buf UNUSED,
		 const jsmntok_t *config UNUSED)
{
}

static const struct plugin_command commands[] = {
};

static struct command_result *
htlc_accepted_continue(struct command *cmd, struct tlv_tlv_payload *payload)
{
	struct json_stream *response;
	u8 *binpayload, *rawpayload;
	response = jsonrpc_stream_success(cmd);

	json_add_string(response, "result", "continue");
	if (payload) {
		binpayload = tal_arr(cmd, u8, 0);
		towire_tlvstream_raw(&binpayload, payload->fields);
		rawpayload = tal_arr(cmd, u8, 0);
		towire_bigsize(&rawpayload, tal_bytelen(binpayload));
		towire(&rawpayload, binpayload, tal_bytelen(binpayload));
		json_add_string(response, "payload", tal_hex(cmd, rawpayload));
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
	ki->label = tal_fmt(ki, "keysend-%lu.%09lu", now.ts.tv_sec, now.ts.tv_nsec);
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

	plugin_main(argv, init, PLUGIN_STATIC, &features, commands,
		    ARRAY_SIZE(commands), NULL, 0, hooks, ARRAY_SIZE(hooks),
		    NULL);
}
