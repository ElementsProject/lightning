#include "invoice.h"
#include "json.h"
#include "jsonrpc.h"
#include "jsonrpc_errors.h"
#include "lightningd.h"
#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/bolt11.h>
#include <common/json_escaped.h>
#include <common/utils.h>
#include <errno.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <inttypes.h>
#include <lightningd/hsm_control.h>
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/log.h>
#include <lightningd/options.h>
#include <lightningd/param.h>
#include <sodium/randombytes.h>
#include <wire/wire_sync.h>

static const char *invoice_status_str(const struct invoice_details *inv)
{
	if (inv->state == PAID)
		return "paid";
	if (inv->state == EXPIRED)
		return "expired";
	return "unpaid";
}

static void json_add_invoice(struct json_result *response,
			     const struct invoice_details *inv)
{
	json_object_start(response, NULL);
	json_add_escaped_string(response, "label", inv->label);
	json_add_string(response, "bolt11", inv->bolt11);
	json_add_hex(response, "payment_hash", &inv->rhash, sizeof(inv->rhash));
	if (inv->msatoshi)
		json_add_u64(response, "msatoshi", *inv->msatoshi);
	json_add_string(response, "status", invoice_status_str(inv));
	if (inv->state == PAID) {
		json_add_u64(response, "pay_index", inv->pay_index);
		json_add_u64(response, "msatoshi_received",
			     inv->msatoshi_received);
		json_add_u64(response, "paid_at", inv->paid_timestamp);
	}

	if (inv->description)
		json_add_string(response, "description", inv->description);

	json_add_u64(response, "expires_at", inv->expiry_time);

	json_object_end(response);
}

static void tell_waiter(struct command *cmd, const struct invoice *inv)
{
	struct json_result *response = new_json_result(cmd);
	const struct invoice_details *details;

	details = wallet_invoice_details(cmd, cmd->ld->wallet, *inv);
	json_add_invoice(response, details);
	if (details->state == PAID)
		command_success(cmd, response);
	else {
		/* FIXME: -2 should be a constant in jsonrpc_errors.h.  */
		command_fail_detailed(cmd, -2, response,
				      "invoice expired during wait");
	}
}
static void tell_waiter_deleted(struct command *cmd)
{
	command_fail(cmd, LIGHTNINGD, "Invoice deleted during wait");
}
static void wait_on_invoice(const struct invoice *invoice, void *cmd)
{
	if (invoice)
		tell_waiter((struct command *) cmd, invoice);
	else
		tell_waiter_deleted((struct command *) cmd);
}

static bool hsm_sign_b11(const u5 *u5bytes,
			 const u8 *hrpu8,
			 secp256k1_ecdsa_recoverable_signature *rsig,
			 struct lightningd *ld)
{
	u8 *msg = towire_hsm_sign_invoice(NULL, u5bytes, hrpu8);

	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = wire_sync_read(tmpctx, ld->hsm_fd);
        if (!fromwire_hsm_sign_invoice_reply(msg, rsig))
		fatal("HSM gave bad sign_invoice_reply %s",
		      tal_hex(msg, msg));

	return true;
}

/* We allow a string, or a literal number, for labels */
static struct json_escaped *json_tok_label(const tal_t *ctx,
					   const char *buffer,
					   const jsmntok_t *tok)
{
	struct json_escaped *label;

	label = json_tok_escaped_string(ctx, buffer, tok);
	if (label)
		return label;

	/* Allow literal numbers */
	if (tok->type != JSMN_PRIMITIVE)
		return NULL;

	for (int i = tok->start; i < tok->end; i++)
		if (!cisdigit(buffer[i]))
			return NULL;

	return json_escaped_string_(ctx, buffer + tok->start,
				    tok->end - tok->start);
}

static bool parse_fallback(struct command *cmd,
			   const char *buffer, const jsmntok_t *fallback,
			   const u8 **fallback_script)

{
	enum address_parse_result fallback_parse;

	fallback_parse
		= json_tok_address_scriptpubkey(cmd,
						get_chainparams(cmd->ld),
						buffer, fallback,
						fallback_script);
	if (fallback_parse == ADDRESS_PARSE_UNRECOGNIZED) {
		command_fail(cmd, LIGHTNINGD, "Fallback address not valid");
		return false;
	} else if (fallback_parse == ADDRESS_PARSE_WRONG_NETWORK) {
		command_fail(cmd, LIGHTNINGD,
			     "Fallback address does not match our network %s",
			     get_chainparams(cmd->ld)->network_name);
		return false;
	}
	return true;
}

static void json_invoice(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct invoice invoice;
	const struct invoice_details *details;
	const jsmntok_t *msatoshi, *label, *desctok, *fallbacks;
	const jsmntok_t *preimagetok;
	u64 *msatoshi_val;
	const struct json_escaped *label_val, *desc;
	const char *desc_val;
	struct json_result *response = new_json_result(cmd);
	struct wallet *wallet = cmd->ld->wallet;
	struct bolt11 *b11;
	char *b11enc;
	const u8 **fallback_scripts = NULL;
	u64 expiry;
	bool result;

	if (!param(cmd, buffer, params,
		   p_req("msatoshi", json_tok_tok, &msatoshi),
		   p_req("label", json_tok_tok, &label),
		   p_req("description", json_tok_tok, &desctok),
		   p_opt_def("expiry", json_tok_u64, &expiry, 3600),
		   p_opt_tok("fallbacks", &fallbacks),
		   p_opt_tok("preimage", &preimagetok),
		   NULL))
		return;

	/* Get arguments. */
	/* msatoshi */
	if (json_tok_streq(buffer, msatoshi, "any"))
		msatoshi_val = NULL;
	else {
		msatoshi_val = tal(cmd, u64);
		if (!json_tok_u64(buffer, msatoshi, msatoshi_val)
		    || *msatoshi_val == 0) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "'%.*s' is not a valid positive number",
				     msatoshi->end - msatoshi->start,
				     buffer + msatoshi->start);
			return;
		}
	}
	/* label */
	label_val = json_tok_label(cmd, buffer, label);
	if (!label_val) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "label '%.*s' not a string or number",
			     label->end - label->start, buffer + label->start);
		return;
	}
	if (wallet_invoice_find_by_label(wallet, &invoice, label_val)) {
		command_fail(cmd, INVOICE_LABEL_ALREADY_EXISTS,
			     "Duplicate label '%s'", label_val->s);
		return;
	}
	if (strlen(label_val->s) > INVOICE_MAX_LABEL_LEN) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "Label '%s' over %u bytes", label_val->s,
			     INVOICE_MAX_LABEL_LEN);
		return;
	}

	desc = json_tok_escaped_string(cmd, buffer, desctok);
	if (!desc) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "description '%.*s' not a string",
			     desctok->end - desctok->start,
			     buffer + desctok->start);
		return;
	}
	desc_val = json_escaped_unescape(cmd, desc);
	if (!desc_val) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "description '%s' is invalid"
			     " (note: we don't allow \\u)",
			     desc->s);
		return;
	}
	/* description */
	if (strlen(desc_val) >= BOLT11_FIELD_BYTE_LIMIT) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "Descriptions greater than %d bytes "
			     "not yet supported "
			     "(description length %zu)",
			     BOLT11_FIELD_BYTE_LIMIT,
			     strlen(desc_val));
		return;
	}

	if (fallbacks) {
		const jsmntok_t *i, *end = json_next(fallbacks);
		size_t n = 0;

		if (fallbacks->type != JSMN_ARRAY) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "fallback must be an array");
			return;
		}
		fallback_scripts = tal_arr(cmd, const u8 *, n);
		for (i = fallbacks + 1; i < end; i = json_next(i)) {
			tal_resize(&fallback_scripts, n+1);
			if (!parse_fallback(cmd, buffer, i,
					    &fallback_scripts[n]))
				return;
			n++;
		}
	}

	struct preimage r;
	struct sha256 rhash;

	if (preimagetok) {
		/* Get secret preimage from user. */
		if (!hex_decode(buffer + preimagetok->start,
				preimagetok->end - preimagetok->start,
				r.r, sizeof(r.r))) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "preimage must be 64 hex digits");
			return;
		}
	} else
		/* Generate random secret preimage. */
		randombytes_buf(r.r, sizeof(r.r));
	/* Generate preimage hash. */
	sha256(&rhash, r.r, sizeof(r.r));

	/* Check duplicate preimage if explicitly specified.
	 * We do not check when it is randomly generated, since
	 * the probability of that matching is very low.
	 */
	if (preimagetok &&
	    wallet_invoice_find_by_rhash(cmd->ld->wallet, &invoice, &rhash)) {
		command_fail(cmd, INVOICE_PREIMAGE_ALREADY_EXISTS,
			     "preimage already used");
		return;
	}

	/* Construct bolt11 string. */
	b11 = new_bolt11(cmd, msatoshi_val);
	b11->chain = get_chainparams(cmd->ld);
	b11->timestamp = time_now().ts.tv_sec;
	b11->payment_hash = rhash;
	b11->receiver_id = cmd->ld->id;
	b11->min_final_cltv_expiry = cmd->ld->config.cltv_final;
	b11->expiry = expiry;
	b11->description = tal_steal(b11, desc_val);
	b11->description_hash = NULL;
	if (fallback_scripts)
		b11->fallbacks = tal_steal(b11, fallback_scripts);

	/* FIXME: add private routes if necessary! */
	b11enc = bolt11_encode(cmd, b11, false, hsm_sign_b11, cmd->ld);

	result = wallet_invoice_create(cmd->ld->wallet,
				       &invoice,
				       take(msatoshi_val),
				       take(label_val),
				       expiry,
				       b11enc,
				       b11->description,
				       &r,
				       &rhash);

	if (!result) {
		command_fail(cmd, LIGHTNINGD,
			     "Failed to create invoice on database");
		   return;
	}

	/* Get details */
	details = wallet_invoice_details(cmd, cmd->ld->wallet, invoice);

	json_object_start(response, NULL);
	json_add_hex(response, "payment_hash", details->rhash.u.u8,
		     sizeof(details->rhash));
	json_add_u64(response, "expires_at", details->expiry_time);
	json_add_string(response, "bolt11", details->bolt11);
	json_object_end(response);

	command_success(cmd, response);
}

static const struct json_command invoice_command = {
    "invoice", json_invoice, "Create an invoice for {msatoshi} with {label} "
			     "and {description} with optional {expiry} seconds "
			     "(default 1 hour) and optional {preimage} "
			     "(default autogenerated)"};
AUTODATA(json_command, &invoice_command);

static void json_add_invoices(struct json_result *response,
			      struct wallet *wallet,
			      const struct json_escaped *label)
{
	struct invoice_iterator it;
	const struct invoice_details *details;

	/* Don't iterate entire db if we're just after one. */
	if (label) {
		struct invoice invoice;
		if (wallet_invoice_find_by_label(wallet, &invoice, label)) {
			details = wallet_invoice_details(response, wallet, invoice);
			json_add_invoice(response, details);
		}
		return;
	}

	memset(&it, 0, sizeof(it));
	while (wallet_invoice_iterate(wallet, &it)) {
		details = wallet_invoice_iterator_deref(response, wallet, &it);
		json_add_invoice(response, details);
	}
}

static void json_listinvoices(struct command *cmd,
			      const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *labeltok;
	struct json_escaped *label;
	struct json_result *response = new_json_result(cmd);
	struct wallet *wallet = cmd->ld->wallet;

	if (!param(cmd, buffer, params,
		   p_opt_tok("label", &labeltok),
		   NULL))
		return;

	if (labeltok) {
		label = json_tok_label(cmd, buffer, labeltok);
		if (!label) {
			command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				     "label '%.*s' is not a string or number",
				     labeltok->end - labeltok->start,
				     buffer + labeltok->start);
			return;
		}
	} else
		label = NULL;

	json_object_start(response, NULL);
	json_array_start(response, "invoices");
	json_add_invoices(response, wallet, label);
	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command listinvoices_command = {
	"listinvoices",
	json_listinvoices,
	"Show invoice {label} (or all, if no {label})"
};
AUTODATA(json_command, &listinvoices_command);

static void json_delinvoice(struct command *cmd,
			    const char *buffer, const jsmntok_t *params)
{
	struct invoice i;
	const struct invoice_details *details;
	const jsmntok_t *labeltok, *statustok;
	struct json_result *response = new_json_result(cmd);
	const char *status, *actual_status;
	struct json_escaped *label;
	struct wallet *wallet = cmd->ld->wallet;

	if (!param(cmd, buffer, params,
		   p_req("label", json_tok_tok, &labeltok),
		   p_req("status", json_tok_tok, &statustok),
		   NULL))
		return;

	label = json_tok_label(cmd, buffer, labeltok);
	if (!label) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "label '%.*s' is not a string or number",
			     labeltok->end - labeltok->start,
			     buffer + labeltok->start);
		return;
	}
	if (!wallet_invoice_find_by_label(wallet, &i, label)) {
		command_fail(cmd, LIGHTNINGD, "Unknown invoice");
		return;
	}

	details = wallet_invoice_details(cmd, cmd->ld->wallet, i);

	status = tal_strndup(cmd, buffer + statustok->start,
			     statustok->end - statustok->start);
	/* This is time-sensitive, so only call once; otherwise error msg
	 * might not make sense if it changed! */
	actual_status = invoice_status_str(details);
	if (!streq(actual_status, status)) {
		command_fail(cmd, LIGHTNINGD, "Invoice status is %s not %s",
			     actual_status, status);
		return;
	}

	/* Get invoice details before attempting to delete, as
	 * otherwise the invoice will be freed. */
	json_add_invoice(response, details);

	if (!wallet_invoice_delete(wallet, i)) {
		log_broken(cmd->ld->log,
			   "Error attempting to remove invoice %"PRIu64,
			   i.id);
		command_fail(cmd, LIGHTNINGD, "Database error");
		return;
	}

	command_success(cmd, response);
}

static const struct json_command delinvoice_command = {
	"delinvoice",
	json_delinvoice,
	"Delete unpaid invoice {label} with {status}",
};
AUTODATA(json_command, &delinvoice_command);

static void json_delexpiredinvoice(struct command *cmd, const char *buffer,
				   const jsmntok_t *params)
{
	u64 maxexpirytime;
	struct json_result *result;

	if (!param(cmd, buffer, params,
		   p_opt_def("maxexpirytime", json_tok_u64, &maxexpirytime,
			     time_now().ts.tv_sec),
		   NULL))
		return;

	wallet_invoice_delete_expired(cmd->ld->wallet, maxexpirytime);

	result = new_json_result(cmd);
	json_object_start(result, NULL);
	json_object_end(result);
	command_success(cmd, result);
}
static const struct json_command delexpiredinvoice_command = {
	"delexpiredinvoice",
	json_delexpiredinvoice,
	"Delete all expired invoices that expired as of given {maxexpirytime} (a UNIX epoch time), or all expired invoices if not specified"
};
AUTODATA(json_command, &delexpiredinvoice_command);

static void json_autocleaninvoice(struct command *cmd,
				  const char *buffer,
				  const jsmntok_t *params)
{
	u64 cycle;
	u64 exby;
	struct json_result *result;

	if (!param(cmd, buffer, params,
		   p_opt_def("cycle_seconds", json_tok_u64, &cycle, 3600),
		   p_opt_def("expired_by", json_tok_u64, &exby, 86400),
		   NULL))
		return;

	wallet_invoice_autoclean(cmd->ld->wallet, cycle, exby);

	result = new_json_result(cmd);
	json_object_start(result, NULL);
	json_object_end(result);
	command_success(cmd, result);
}
static const struct json_command autocleaninvoice_command = {
	"autocleaninvoice",
	json_autocleaninvoice,
	"Set up autoclean of expired invoices. "
	"Perform cleanup every {cycle_seconds} (default 3600), or disable autoclean if 0. "
	"Clean up expired invoices that have expired for {expired_by} seconds (default 86400). "
};
AUTODATA(json_command, &autocleaninvoice_command);

static void json_waitanyinvoice(struct command *cmd,
			    const char *buffer, const jsmntok_t *params)
{
	u64 pay_index;
	struct wallet *wallet = cmd->ld->wallet;

	if (!param(cmd, buffer, params,
		   p_opt_def("lastpay_index", json_tok_u64, &pay_index, 0),
		   NULL))
		return;

	/* Set command as pending. We do not know if
	 * wallet_invoice_waitany will return immediately
	 * or not, so indicating pending is safest.  */
	command_still_pending(cmd);

	/* Find next paid invoice. */
	wallet_invoice_waitany(cmd, wallet, pay_index,
			       &wait_on_invoice, (void*) cmd);
}

static const struct json_command waitanyinvoice_command = {
	"waitanyinvoice",
	json_waitanyinvoice,
	"Wait for the next invoice to be paid, after {lastpay_index} (if supplied)"
};
AUTODATA(json_command, &waitanyinvoice_command);


/* Wait for an incoming payment matching the `label` in the JSON
 * command.  This will either return immediately if the payment has
 * already been received or it may add the `cmd` to the list of
 * waiters, if the payment is still pending.
 */
static void json_waitinvoice(struct command *cmd,
			      const char *buffer, const jsmntok_t *params)
{
	struct invoice i;
	const struct invoice_details *details;
	struct wallet *wallet = cmd->ld->wallet;
	const jsmntok_t *labeltok;
	struct json_escaped *label;

	if (!param(cmd, buffer, params,
		   p_req("label", json_tok_tok, &labeltok),
		   NULL))
		return;

	/* Search for invoice */
	label = json_tok_label(cmd, buffer, labeltok);
	if (!label) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			     "label '%.*s' is not a string or number",
			     labeltok->end - labeltok->start,
			     buffer + labeltok->start);
		return;
	}

	if (!wallet_invoice_find_by_label(wallet, &i, label)) {
		command_fail(cmd, LIGHTNINGD, "Label not found");
		return;
	}
	details = wallet_invoice_details(cmd, cmd->ld->wallet, i);

	/* If paid or expired return immediately */
	if (details->state == PAID || details->state == EXPIRED) {
		tell_waiter(cmd, &i);
		return;
	} else {
		/* There is an unpaid one matching, let's wait... */
		command_still_pending(cmd);
		wallet_invoice_waitone(cmd, wallet, i,
				       &wait_on_invoice, (void *) cmd);
	}
}

static const struct json_command waitinvoice_command = {
	"waitinvoice",
	json_waitinvoice,
	"Wait for an incoming payment matching the invoice with {label}, or if the invoice expires"
};
AUTODATA(json_command, &waitinvoice_command);

static void json_add_fallback(struct json_result *response,
			      const char *fieldname,
			      const u8 *fallback,
			      const struct chainparams *chain)
{
	struct bitcoin_address pkh;
	struct ripemd160 sh;
	struct sha256 wsh;

	json_object_start(response, fieldname);
	if (is_p2pkh(fallback, &pkh)) {
		json_add_string(response, "type", "P2PKH");
		json_add_string(response, "addr",
				bitcoin_to_base58(tmpctx, chain->testnet, &pkh));
	} else if (is_p2sh(fallback, &sh)) {
		json_add_string(response, "type", "P2SH");
		json_add_string(response, "addr",
				p2sh_to_base58(tmpctx, chain->testnet, &sh));
	} else if (is_p2wpkh(fallback, &pkh)) {
		char out[73 + strlen(chain->bip173_name)];
		json_add_string(response, "type", "P2WPKH");
		if (segwit_addr_encode(out, chain->bip173_name, 0,
				       (const u8 *)&pkh, sizeof(pkh)))
			json_add_string(response, "addr", out);
	} else if (is_p2wsh(fallback, &wsh)) {
		char out[73 + strlen(chain->bip173_name)];
		json_add_string(response, "type", "P2WSH");
		if (segwit_addr_encode(out, chain->bip173_name, 0,
				       (const u8 *)&wsh, sizeof(wsh)))
			json_add_string(response, "addr", out);
	}
	json_add_hex_talarr(response, "hex", fallback);
	json_object_end(response);
}

static void json_decodepay(struct command *cmd,
                           const char *buffer, const jsmntok_t *params)
{
	const jsmntok_t *bolt11tok, *desctok;
	struct bolt11 *b11;
	struct json_result *response;
        char *str, *desc, *fail;

	if (!param(cmd, buffer, params,
		   p_req("bolt11", json_tok_tok, &bolt11tok),
		   p_opt_tok("description", &desctok),
		   NULL))
		return;

        str = tal_strndup(cmd, buffer + bolt11tok->start,
                          bolt11tok->end - bolt11tok->start);

        if (desctok)
                desc = tal_strndup(cmd, buffer + desctok->start,
                                   desctok->end - desctok->start);
        else
                desc = NULL;

	b11 = bolt11_decode(cmd, str, desc, &fail);

	if (!b11) {
		command_fail(cmd, LIGHTNINGD, "Invalid bolt11: %s", fail);
		return;
	}

	response = new_json_result(cmd);
	json_object_start(response, NULL);

	json_add_string(response, "currency", b11->chain->bip173_name);
	json_add_u64(response, "created_at", b11->timestamp);
	json_add_u64(response, "expiry", b11->expiry);
	json_add_pubkey(response, "payee", &b11->receiver_id);
        if (b11->msatoshi)
                json_add_u64(response, "msatoshi", *b11->msatoshi);
        if (b11->description) {
		struct json_escaped *esc = json_escape(NULL, b11->description);
                json_add_escaped_string(response, "description", take(esc));
	}
        if (b11->description_hash)
                json_add_hex(response, "description_hash",
                             b11->description_hash,
                             sizeof(*b11->description_hash));
	json_add_num(response, "min_final_cltv_expiry",
		     b11->min_final_cltv_expiry);
        if (tal_count(b11->fallbacks)) {
		json_array_start(response, "fallbacks");
		for (size_t i = 0; i < tal_count(b11->fallbacks); i++)
			json_add_fallback(response, NULL,
					  b11->fallbacks[i], b11->chain);
		json_array_end(response);
        }

        if (tal_count(b11->routes)) {
                size_t i, n;

                json_array_start(response, "routes");
                for (i = 0; i < tal_count(b11->routes); i++) {
                        json_array_start(response, NULL);
                        for (n = 0; n < tal_count(b11->routes[i]); n++) {
                                json_object_start(response, NULL);
                                json_add_pubkey(response, "pubkey",
                                                &b11->routes[i][n].pubkey);
                                json_add_short_channel_id(response,
                                                          "short_channel_id",
                                                          &b11->routes[i][n]
                                                          .short_channel_id);
                                json_add_u64(response, "fee_base_msat",
                                             b11->routes[i][n].fee_base_msat);
                                json_add_u64(response, "fee_proportional_millionths",
                                             b11->routes[i][n].fee_proportional_millionths);
                                json_add_num(response, "cltv_expiry_delta",
                                             b11->routes[i][n]
                                             .cltv_expiry_delta);
                                json_object_end(response);
                        }
                        json_array_end(response);
                }
                json_array_end(response);
        }

        if (!list_empty(&b11->extra_fields)) {
                struct bolt11_field *extra;

                json_array_start(response, "extra");
                list_for_each(&b11->extra_fields, extra, list) {
                        char *data = tal_arr(cmd, char, tal_count(extra->data)+1);
                        size_t i;

                        for (i = 0; i < tal_count(extra->data); i++)
                                data[i] = bech32_charset[extra->data[i]];
                        data[i] = '\0';
                        json_object_start(response, NULL);
                        json_add_string(response, "tag",
                                        tal_fmt(data, "%c", extra->tag));
                        json_add_string(response, "data", data);
                        tal_free(data);
                        json_object_end(response);
                }
                json_array_end(response);
        }

	json_add_hex(response, "payment_hash",
                     &b11->payment_hash, sizeof(b11->payment_hash));

	json_add_string(response, "signature",
                        type_to_string(cmd, secp256k1_ecdsa_signature,
                                       &b11->sig));
	json_object_end(response);
	command_success(cmd, response);
}

static const struct json_command decodepay_command = {
	"decodepay",
	json_decodepay,
	"Decode {bolt11}, using {description} if necessary"
};
AUTODATA(json_command, &decodepay_command);
