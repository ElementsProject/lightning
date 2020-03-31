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

static struct command_result *htlc_accepted_continue(struct command *cmd)
{
	struct json_stream *response;
	response = jsonrpc_stream_success(cmd);
	json_add_string(response, "result", "continue");
	return command_finished(cmd, response);
}

static struct command_result *htlc_accepted_resolve(struct command *cmd,
						    char *hexpreimage)
{
	struct json_stream *response;
	response = jsonrpc_stream_success(cmd);
	json_add_string(response, "result", "resolve");
	json_add_string(response, "payment_key", hexpreimage);
	return command_finished(cmd, response);
}

static struct command_result *htlc_accepted_call(struct command *cmd, const char *buf,
					  const jsmntok_t *params)
{
	const jsmntok_t *payloadt = json_delve(buf, params, ".onion.payload");
	const jsmntok_t *payment_hash_tok = json_delve(buf, params, ".htlc.payment_hash");
	const u8 *rawpayload;
	size_t max;
	struct tlv_tlv_payload *payload;
	struct tlv_field *preimage_field = NULL;
	char *hexpreimage, *hexpaymenthash;
	struct sha256 payment_hash;
	bigsize_t s;
	bool unknown_even_type = false;
	struct tlv_field *field;

	if (!payloadt)
		return htlc_accepted_continue(cmd);

	rawpayload = json_tok_bin_from_hex(cmd, buf, payloadt);
	max = tal_bytelen(rawpayload);
	payload = tlv_tlv_payload_new(cmd);

	s = fromwire_varint(&rawpayload, &max);
	if (s != max) {
		return htlc_accepted_continue(cmd);
	}
	fromwire_tlv_payload(&rawpayload, &max, payload);

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
		return htlc_accepted_continue(cmd);

	if (unknown_even_type) {
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "Payload contains unknown even TLV-type %" PRIu64
			   ", can't safely accept the keysend. Deferring to "
			   "other plugins.",
			   preimage_field->numtype);
		return htlc_accepted_continue(cmd);
	}

	/* If the preimage is not 32 bytes long then we can't accept the
	 * payment. */
	if (preimage_field->length != 32) {
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "Sender specified a preimage that is %zu bytes long, "
			   "we expected 32 bytes. Ignoring this HTLC.",
			   preimage_field->length);
		return htlc_accepted_continue(cmd);
	}

	hexpreimage = tal_hex(cmd, preimage_field->value);

	/* If the preimage doesn't hash to the payment_hash we must continue,
	 * maybe someone else knows how to handle these. */
	sha256(&payment_hash, preimage_field->value, preimage_field->length);
	hexpaymenthash = tal_hexstr(cmd, &payment_hash, sizeof(payment_hash));
	if (!json_tok_streq(buf, payment_hash_tok, hexpaymenthash)) {
		plugin_log(
		    cmd->plugin, LOG_UNUSUAL,
		    "Preimage provided by the sender does not match the "
		    "payment_hash: SHA256(%s)=%s != %.*s. Ignoring keysend.",
		    hexpreimage, hexpaymenthash,
		    payment_hash_tok->end - payment_hash_tok->start,
		    buf + payment_hash_tok->start);
		return htlc_accepted_continue(cmd);
	}

	/* Finally we can resolve the payment with the preimage. */
	plugin_log(cmd->plugin, LOG_INFORM,
		   "Resolving incoming HTLC with preimage for payment_hash %s "
		   "provided in the onion payload.",
		   hexpaymenthash);
	return htlc_accepted_resolve(cmd, hexpreimage);
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
