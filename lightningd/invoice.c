#include "invoice.h"
#include "json.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include <bitcoin/address.h>
#include <bitcoin/base58.h>
#include <bitcoin/script.h>
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <common/bech32.h>
#include <common/bolt11.h>
#include <common/utils.h>
#include <errno.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <inttypes.h>
#include <lightningd/hsm_control.h>
#include <lightningd/log.h>
#include <lightningd/options.h>
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
			     const struct invoice_details *inv,
			     bool modern)
{
	json_object_start(response, NULL);
	json_add_string(response, "label", inv->label);
	json_add_string(response, "bolt11", inv->bolt11);
	json_add_hex(response, "payment_hash", &inv->rhash, sizeof(inv->rhash));
	if (inv->msatoshi)
		json_add_u64(response, "msatoshi", *inv->msatoshi);
	if (modern)
		json_add_string(response, "status", invoice_status_str(inv));
	else if (deprecated_apis && !modern)
		json_add_bool(response, "complete", inv->state == PAID);
	if (inv->state == PAID) {
		json_add_u64(response, "pay_index", inv->pay_index);
		json_add_u64(response, "msatoshi_received",
			     inv->msatoshi_received);
		if (deprecated_apis)
			json_add_u64(response, "paid_timestamp",
				     inv->paid_timestamp);
		json_add_u64(response, "paid_at", inv->paid_timestamp);
	}
	if (deprecated_apis)
		json_add_u64(response, "expiry_time", inv->expiry_time);
	json_add_u64(response, "expires_at", inv->expiry_time);

	json_object_end(response);
}

static void tell_waiter(struct command *cmd, const struct invoice *inv)
{
	struct json_result *response = new_json_result(cmd);
	struct invoice_details details;

	wallet_invoice_details(cmd, cmd->ld->wallet, *inv, &details);
	json_add_invoice(response, &details, true);
	if (details.state == PAID)
		command_success(cmd, response);
	else
		command_fail_detailed(cmd, -2, response,
				      "invoice expired during wait");
}
static void tell_waiter_deleted(struct command *cmd)
{
	command_fail(cmd, "Invoice deleted during wait");
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
	u8 *msg = towire_hsm_sign_invoice(ld, u5bytes, hrpu8);

	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = hsm_sync_read(ld, ld);
        if (!fromwire_hsm_sign_invoice_reply(msg, rsig))
		fatal("HSM gave bad sign_invoice_reply %s",
		      tal_hex(msg, msg));

	tal_free(msg);
	return true;
}

static void json_invoice(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct invoice invoice;
	struct invoice_details details;
	jsmntok_t *msatoshi, *label, *desc, *exp, *fallback;
	u64 *msatoshi_val;
	const char *label_val;
	const char *desc_val;
	enum address_parse_result fallback_parse;
	struct json_result *response = new_json_result(cmd);
	struct wallet *wallet = cmd->ld->wallet;
	struct bolt11 *b11;
	char *b11enc;
	const u8 *fallback_script;
	u64 expiry = 3600;
	bool result;

	if (!json_get_params(cmd, buffer, params,
			     "msatoshi", &msatoshi,
			     "label", &label,
			     "description", &desc,
			     "?expiry", &exp,
			     "?fallback", &fallback,
			     NULL)) {
		return;
	}

	/* Get arguments. */
	/* msatoshi */
	if (json_tok_streq(buffer, msatoshi, "any"))
		msatoshi_val = NULL;
	else {
		msatoshi_val = tal(cmd, u64);
		if (!json_tok_u64(buffer, msatoshi, msatoshi_val)
		    || *msatoshi_val == 0) {
			command_fail(cmd,
				     "'%.*s' is not a valid positive number",
				     msatoshi->end - msatoshi->start,
				     buffer + msatoshi->start);
			return;
		}
	}
	/* label */
	label_val = tal_strndup(cmd, buffer + label->start,
				label->end - label->start);
	if (wallet_invoice_find_by_label(wallet, &invoice, label_val)) {
		command_fail(cmd, "Duplicate label '%s'", label_val);
		return;
	}
	if (strlen(label_val) > INVOICE_MAX_LABEL_LEN) {
		command_fail(cmd, "Label '%s' over %u bytes", label_val,
			     INVOICE_MAX_LABEL_LEN);
		return;
	}
	/* description */
	if (desc->end - desc->start >= BOLT11_FIELD_BYTE_LIMIT) {
		command_fail(cmd,
			     "Descriptions greater than %d bytes "
			     "not yet supported "
			     "(description length %d)",
			     BOLT11_FIELD_BYTE_LIMIT,
			     desc->end - desc->start);
		return;
	}
	desc_val = tal_strndup(cmd, buffer + desc->start,
			       desc->end - desc->start);
	/* expiry */
	if (exp && !json_tok_u64(buffer, exp, &expiry)) {
		command_fail(cmd, "Expiry '%.*s' invalid seconds",
			     exp->end - exp->start,
			     buffer + exp->start);
		return;
	}

	/* fallback address */
	if (fallback) {
		fallback_parse
			= json_tok_address_scriptpubkey(cmd,
							get_chainparams(cmd->ld),
							buffer, fallback,
							&fallback_script);
		if (fallback_parse == ADDRESS_PARSE_UNRECOGNIZED) {
			command_fail(cmd, "Fallback address not valid");
			return;
		} else if (fallback_parse == ADDRESS_PARSE_WRONG_NETWORK) {
			command_fail(cmd, "Fallback address does not match our network %s",
				     get_chainparams(cmd->ld)->network_name);
			return;
		}
	}

	struct preimage r;
	struct sha256 rhash;

	/* Generate random secret preimage and hash. */
	randombytes_buf(r.r, sizeof(r.r));
	sha256(&rhash, r.r, sizeof(r.r));

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
	if (fallback)
		b11->fallback = tal_steal(b11, fallback_script);

	/* FIXME: add private routes if necessary! */
	b11enc = bolt11_encode(cmd, b11, false, hsm_sign_b11, cmd->ld);

	result = wallet_invoice_create(cmd->ld->wallet,
				       &invoice,
				       take(msatoshi_val),
				       take(label_val),
				       expiry,
				       b11enc,
				       &r,
				       &rhash);

	if (!result) {
		   command_fail(cmd, "Failed to create invoice on database");
		   return;
	}

	/* Get details */
	wallet_invoice_details(cmd, cmd->ld->wallet, invoice, &details);

	json_object_start(response, NULL);
	json_add_hex(response, "payment_hash",
		     &details.rhash, sizeof(details.rhash));
	if (deprecated_apis)
		json_add_u64(response, "expiry_time", details.expiry_time);
	json_add_u64(response, "expires_at", details.expiry_time);
	json_add_string(response, "bolt11", details.bolt11);
	json_object_end(response);

	command_success(cmd, response);
}

static const struct json_command invoice_command = {
	"invoice",
	json_invoice,
	"Create an invoice for {msatoshi} with {label} and {description} with optional {expiry} seconds (default 1 hour)"
};
AUTODATA(json_command, &invoice_command);

static void json_add_invoices(struct json_result *response,
			      struct wallet *wallet,
			      const char *buffer, const jsmntok_t *label,
			      bool modern)
{
	struct invoice_iterator it;
	struct invoice_details details;
	char *lbl = NULL;
	if (label)
		lbl = tal_strndup(response, &buffer[label->start], label->end - label->start);

	memset(&it, 0, sizeof(it));
	while (wallet_invoice_iterate(wallet, &it)) {
		wallet_invoice_iterator_deref(response, wallet, &it, &details);
		if (lbl && !streq(details.label, lbl))
			continue;
		json_add_invoice(response, &details, modern);
	}
}

static void json_listinvoice_internal(struct command *cmd,
				      const char *buffer,
				      const jsmntok_t *params,
				      bool modern)
{
	jsmntok_t *label = NULL;
	struct json_result *response = new_json_result(cmd);
	struct wallet *wallet = cmd->ld->wallet;

	if (!json_get_params(cmd, buffer, params,
			     "?label", &label,
			     NULL)) {
		return;
	}

	if (modern) {
		json_object_start(response, NULL);
		json_array_start(response, "invoices");
	} else
		json_array_start(response, NULL);
	json_add_invoices(response, wallet, buffer, label, modern);
	json_array_end(response);
	if (modern)
		json_object_end(response);
	command_success(cmd, response);
}

/* FIXME: Deprecated! */
static void json_listinvoice(struct command *cmd,
			     const char *buffer, const jsmntok_t *params)
{
	return json_listinvoice_internal(cmd, buffer, params, false);
}

static const struct json_command listinvoice_command = {
	"listinvoice",
	json_listinvoice,
	"(DEPRECATED) Show invoice {label} (or all, if no {label}))",
	.deprecated = true
};
AUTODATA(json_command, &listinvoice_command);

static void json_listinvoices(struct command *cmd,
			     const char *buffer, const jsmntok_t *params)
{
	return json_listinvoice_internal(cmd, buffer, params, true);
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
	struct invoice_details details;
	jsmntok_t *labeltok, *statustok;
	struct json_result *response = new_json_result(cmd);
	const char *label, *status, *actual_status;
	struct wallet *wallet = cmd->ld->wallet;

	if (!json_get_params(cmd, buffer, params,
			     "label", &labeltok,
			     "status", &statustok,
			     NULL)) {
		return;
	}

	label = tal_strndup(cmd, buffer + labeltok->start,
			    labeltok->end - labeltok->start);
	if (!wallet_invoice_find_by_label(wallet, &i, label)) {
		command_fail(cmd, "Unknown invoice");
		return;
	}
	wallet_invoice_details(cmd, cmd->ld->wallet, i, &details);

	status = tal_strndup(cmd, buffer + statustok->start,
			     statustok->end - statustok->start);
	/* This is time-sensitive, so only call once; otherwise error msg
	 * might not make sense if it changed! */
	actual_status = invoice_status_str(&details);
	if (!streq(actual_status, status)) {
		command_fail(cmd, "Invoice status is %s not %s",
			     actual_status, status);
		return;
	}

	/* Get invoice details before attempting to delete, as
	 * otherwise the invoice will be freed. */
	json_add_invoice(response, &details, true);

	if (!wallet_invoice_delete(wallet, i)) {
		log_broken(cmd->ld->log,
			   "Error attempting to remove invoice %"PRIu64,
			   i.id);
		command_fail(cmd, "Database error");
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
	jsmntok_t *maxexpirytimetok;
	u64 maxexpirytime = time_now().ts.tv_sec;
	struct json_result *result;

	if (!json_get_params(cmd, buffer, params,
			     "?maxexpirytime", &maxexpirytimetok,
			     NULL)) {
		return;
	}

	if (maxexpirytimetok) {
		if (!json_tok_u64(buffer, maxexpirytimetok, &maxexpirytime)) {
			command_fail(cmd, "'%.*s' is not a valid number",
				     maxexpirytimetok->end - maxexpirytimetok->start,
				     buffer + maxexpirytimetok->start);
			return;
		}
	}

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
	jsmntok_t *cycletok;
	jsmntok_t *exbytok;
	u64 cycle = 3600;
	u64 exby = 86400;
	struct json_result *result;

	if (!json_get_params(cmd, buffer, params,
			     "?cycle_seconds", &cycletok,
			     "?expired_by", &exbytok,
			     NULL)) {
		return;
	}

	if (cycletok) {
		if (!json_tok_u64(buffer, cycletok, &cycle)) {
			command_fail(cmd, "'%.*s' is not a valid number",
				     cycletok->end - cycletok->start,
				     buffer + cycletok->start);
			return;
		}
	}
	if (exbytok) {
		if (!json_tok_u64(buffer, exbytok, &exby)) {
			command_fail(cmd, "'%.*s' is not a valid number",
				     exbytok->end - exbytok->start,
				     buffer + exbytok->start);
			return;
		}
	}

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
	jsmntok_t *pay_indextok;
	u64 pay_index;
	struct wallet *wallet = cmd->ld->wallet;

	if (!json_get_params(cmd, buffer, params,
			     "?lastpay_index", &pay_indextok,
			     NULL)) {
		return;
	}

	if (!pay_indextok) {
		pay_index = 0;
	} else {
		if (!json_tok_u64(buffer, pay_indextok, &pay_index)) {
			command_fail(cmd, "'%.*s' is not a valid number",
				     pay_indextok->end - pay_indextok->start,
				     buffer + pay_indextok->start);
			return;
		}
	}

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
	struct invoice_details details;
	struct wallet *wallet = cmd->ld->wallet;
	jsmntok_t *labeltok;
	const char *label = NULL;

	if (!json_get_params(cmd, buffer, params, "label", &labeltok, NULL)) {
		return;
	}

	/* Search for invoice */
	label = tal_strndup(cmd, buffer + labeltok->start, labeltok->end - labeltok->start);
	if (!wallet_invoice_find_by_label(wallet, &i, label)) {
		command_fail(cmd, "Label not found");
		return;
	}
	wallet_invoice_details(cmd, cmd->ld->wallet, i, &details);

	/* If paid or expired return immediately */
	if (details.state == PAID || details.state == EXPIRED) {
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

static void json_decodepay(struct command *cmd,
                           const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *bolt11tok, *desctok;
	struct bolt11 *b11;
	struct json_result *response;
        char *str, *desc, *fail;

	if (!json_get_params(cmd, buffer, params,
			     "bolt11", &bolt11tok,
			     "?description", &desctok,
			     NULL)) {
		return;
	}

        str = tal_strndup(cmd, buffer + bolt11tok->start,
                          bolt11tok->end - bolt11tok->start);

        if (desctok)
                desc = tal_strndup(cmd, buffer + desctok->start,
                                   desctok->end - desctok->start);
        else
                desc = NULL;

	b11 = bolt11_decode(cmd, str, desc, &fail);

	if (!b11) {
		command_fail(cmd, "Invalid bolt11: %s", fail);
		return;
	}

	response = new_json_result(cmd);
	json_object_start(response, NULL);

	json_add_string(response, "currency", b11->chain->bip173_name);
	if (deprecated_apis)
		json_add_u64(response, "timestamp", b11->timestamp);
	json_add_u64(response, "created_at", b11->timestamp);
	json_add_u64(response, "expiry", b11->expiry);
	json_add_pubkey(response, "payee", &b11->receiver_id);
        if (b11->msatoshi)
                json_add_u64(response, "msatoshi", *b11->msatoshi);
        if (b11->description)
                json_add_string(response, "description", b11->description);
        if (b11->description_hash)
                json_add_hex(response, "description_hash",
                             b11->description_hash,
                             sizeof(*b11->description_hash));
	json_add_num(response, "min_final_cltv_expiry",
		     b11->min_final_cltv_expiry);
        if (tal_len(b11->fallback)) {
                struct bitcoin_address pkh;
                struct ripemd160 sh;
                struct sha256 wsh;

                json_object_start(response, "fallback");
                if (is_p2pkh(b11->fallback, &pkh)) {
                        json_add_string(response, "type", "P2PKH");
                        json_add_string(response, "addr",
                                        bitcoin_to_base58(cmd,
                                                          b11->chain->testnet,
                                                          &pkh));
                } else if (is_p2sh(b11->fallback, &sh)) {
                        json_add_string(response, "type", "P2SH");
                        json_add_string(response, "addr",
                                        p2sh_to_base58(cmd,
                                                       b11->chain->testnet,
                                                       &sh));
                } else if (is_p2wpkh(b11->fallback, &pkh)) {
                        char out[73 + strlen(b11->chain->bip173_name)];
                        json_add_string(response, "type", "P2WPKH");
                        if (segwit_addr_encode(out, b11->chain->bip173_name, 0,
                                               (const u8 *)&pkh, sizeof(pkh)))
                                json_add_string(response, "addr", out);
                } else if (is_p2wsh(b11->fallback, &wsh)) {
                        char out[73 + strlen(b11->chain->bip173_name)];
                        json_add_string(response, "type", "P2WSH");
                        if (segwit_addr_encode(out, b11->chain->bip173_name, 0,
                                               (const u8 *)&wsh, sizeof(wsh)))
                                json_add_string(response, "addr", out);
                }
                json_add_hex(response, "hex",
                             b11->fallback, tal_len(b11->fallback));
                json_object_end(response);
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
                        char *data = tal_arr(cmd, char, tal_len(extra->data)+1);
                        size_t i;

                        for (i = 0; i < tal_len(extra->data); i++)
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
