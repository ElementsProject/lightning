#include "invoice.h"
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
#include <sodium/randombytes.h>
#include <wire/wire_sync.h>

static void json_add_invoice(struct json_result *response,
			     const struct invoice *inv)
{
	json_object_start(response, NULL);
	json_add_string(response, "label", inv->label);
	json_add_hex(response, "payment_hash", &inv->rhash, sizeof(inv->rhash));
	if (inv->msatoshi)
		json_add_u64(response, "msatoshi", *inv->msatoshi);
	json_add_bool(response, "complete", inv->state == PAID);
	if (inv->state == PAID) {
		json_add_u64(response, "pay_index", inv->pay_index);
		json_add_u64(response, "msatoshi_received",
			     inv->msatoshi_received);
		json_add_u64(response, "paid_timestamp",
			     inv->paid_timestamp);
	}
	json_add_u64(response, "expiry_time", inv->expiry_time);
	json_object_end(response);
}

static void tell_waiter(struct command *cmd, const struct invoice *paid)
{
	struct json_result *response = new_json_result(cmd);

	json_add_invoice(response, paid);
	command_success(cmd, response);
}
static void tell_waiter_deleted(struct command *cmd)
{
	command_fail(cmd, "invoice deleted during wait");
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
        if (!fromwire_hsm_sign_invoice_reply(msg, NULL, rsig))
		fatal("HSM gave bad sign_invoice_reply %s",
		      tal_hex(msg, msg));

	tal_free(msg);
	return true;
}

static void json_invoice(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	const struct invoice *invoice;
	jsmntok_t *msatoshi, *label, *desc, *exp;
	u64 *msatoshi_val;
	const char *label_val;
	struct json_result *response = new_json_result(cmd);
	struct wallet *wallet = cmd->ld->wallet;
	struct bolt11 *b11;
	char *b11enc;
	u64 expiry = 3600;

	if (!json_get_params(buffer, params,
			     "msatoshi", &msatoshi,
			     "label", &label,
			     "description", &desc,
			     "?expiry", &exp,
			     NULL)) {
		command_fail(cmd, "Need {msatoshi}, {label} and {description}");
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
	if (wallet_invoice_find_by_label(wallet, label_val)) {
		command_fail(cmd, "Duplicate label '%s'", label_val);
		return;
	}
	if (strlen(label_val) > INVOICE_MAX_LABEL_LEN) {
		command_fail(cmd, "label '%s' over %u bytes", label_val,
			     INVOICE_MAX_LABEL_LEN);
		return;
	}
	if (exp && !json_tok_u64(buffer, exp, &expiry)) {
		command_fail(cmd, "expiry '%.*s' invalid seconds",
			     exp->end - exp->start,
			     buffer + exp->start);
		return;
	}

	invoice = wallet_invoice_create(cmd->ld->wallet,
					take(msatoshi_val),
					take(label_val),
					expiry);
	if (!invoice) {
		command_fail(cmd, "Failed to create invoice on database");
		return;
	}

	/* Construct bolt11 string. */
	b11 = new_bolt11(cmd, invoice->msatoshi);
	b11->chain = get_chainparams(cmd->ld);
	b11->timestamp = time_now().ts.tv_sec;
	b11->payment_hash = invoice->rhash;
	b11->receiver_id = cmd->ld->id;
	b11->min_final_cltv_expiry = cmd->ld->config.cltv_final;
	b11->expiry = expiry;
	if (desc->end - desc->start >= BOLT11_FIELD_BYTE_LIMIT) {
		b11->description_hash = tal(b11, struct sha256);
		sha256(b11->description_hash, buffer + desc->start,
		       desc->end - desc->start);
	} else
		b11->description = tal_strndup(b11, buffer + desc->start,
					       desc->end - desc->start);

	/* FIXME: add private routes if necessary! */
	b11enc = bolt11_encode(cmd, b11, false, hsm_sign_b11, cmd->ld);

	json_object_start(response, NULL);
	json_add_hex(response, "payment_hash",
		     &invoice->rhash, sizeof(invoice->rhash));
	json_add_u64(response, "expiry_time", invoice->expiry_time);
	json_add_string(response, "bolt11", b11enc);
	if (b11->description_hash)
		json_add_string(response, "description", b11->description);
	json_object_end(response);

	command_success(cmd, response);
}

static const struct json_command invoice_command = {
	"invoice",
	json_invoice,
	"Create invoice for {msatoshi} with {label} and {description} with optional {expiry} seconds (default 1 hour)",
	"Returns the {payment_hash}, {expiry_time} and {bolt11} on success, and {description} if too large for {bolt11}. "
};
AUTODATA(json_command, &invoice_command);

static void json_add_invoices(struct json_result *response,
			      struct wallet *wallet,
			      const char *buffer, const jsmntok_t *label)
{
	const struct invoice *i;
	char *lbl = NULL;
	if (label)
		lbl = tal_strndup(response, &buffer[label->start], label->end - label->start);

	i = NULL;
	while ((i = wallet_invoice_iterate(wallet, i)) != NULL) {
		if (lbl && !streq(i->label, lbl))
			continue;
		json_add_invoice(response, i);
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

	if (!json_get_params(buffer, params,
			     "?label", &label,
			     NULL)) {
		command_fail(cmd, "Invalid arguments");
		return;
	}

	if (modern) {
		json_object_start(response, NULL);
		json_array_start(response, "invoices");
	} else
		json_array_start(response, NULL);
	json_add_invoices(response, wallet, buffer, label);
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
	"Returns an array of {label}, {payment_hash}, {msatoshi} (if set), {complete}, {pay_index} (if paid) and {expiry_time} on success. ",
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
	"Show invoice {label} (or all, if no {label}))",
	"Returns an array of {label}, {payment_hash}, {msatoshi} (if set), {complete}, {pay_index} (if paid) and {expiry_time} on success. ",
};
AUTODATA(json_command, &listinvoices_command);

static void json_delinvoice(struct command *cmd,
			    const char *buffer, const jsmntok_t *params)
{
	const struct invoice *i;
	jsmntok_t *labeltok;
	struct json_result *response = new_json_result(cmd);
	const char *label;
	struct wallet *wallet = cmd->ld->wallet;
	bool error;

	if (!json_get_params(buffer, params,
			     "label", &labeltok,
			     NULL)) {
		command_fail(cmd, "Invalid arguments");
		return;
	}

	label = tal_strndup(cmd, buffer + labeltok->start,
			    labeltok->end - labeltok->start);
	i = wallet_invoice_find_by_label(wallet, label);
	if (!i) {
		command_fail(cmd, "Unknown invoice");
		return;
	}

	/* Get invoice details before attempting to delete, as
	 * otherwise the invoice will be freed. */
	json_add_invoice(response, i);

	error = wallet_invoice_delete(wallet, i);

	if (error) {
		log_broken(cmd->ld->log, "Error attempting to remove invoice %"PRIu64,
			   i->id);
		command_fail(cmd, "Database error");
		return;
	}

	command_success(cmd, response);
}

static const struct json_command delinvoice_command = {
	"delinvoice",
	json_delinvoice,
	"Delete unpaid invoice {label}))",
	"Returns {label}, {payment_hash}, {msatoshi} (if set), {complete}, {pay_index} (if paid) and {expiry_time} on success. "
};
AUTODATA(json_command, &delinvoice_command);

static void json_waitanyinvoice(struct command *cmd,
			    const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *pay_indextok;
	u64 pay_index;
	struct wallet *wallet = cmd->ld->wallet;

	if (!json_get_params(buffer, params,
			     "?lastpay_index", &pay_indextok,
			     NULL)) {
		command_fail(cmd, "Invalid arguments");
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
	"Wait for the next invoice to be paid, after {lastpay_index} (if supplied)))",
	"Returns {label}, {payment_hash}, {msatoshi} (if set), {complete}, {pay_index} and {expiry_time} on success. "
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
	const struct invoice *i;
	struct wallet *wallet = cmd->ld->wallet;
	jsmntok_t *labeltok;
	const char *label = NULL;

	if (!json_get_params(buffer, params, "label", &labeltok, NULL)) {
		command_fail(cmd, "Missing {label}");
		return;
	}

	/* Search in paid invoices, if found return immediately */
	label = tal_strndup(cmd, buffer + labeltok->start, labeltok->end - labeltok->start);
	i = wallet_invoice_find_by_label(wallet, label);

	if (!i) {
		command_fail(cmd, "Label not found");
		return;
	} else if (i->state == PAID) {
		tell_waiter(cmd, i);
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
	"Wait for an incoming payment matching the invoice with {label}",
	"Returns {label}, {payment_hash}, {msatoshi} (if set), {complete}, {pay_index} and {expiry_time} on success"
};
AUTODATA(json_command, &waitinvoice_command);

static void json_decodepay(struct command *cmd,
                           const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *bolt11tok, *desctok;
	struct bolt11 *b11;
	struct json_result *response;
        char *str, *desc, *fail;

	if (!json_get_params(buffer, params,
			     "bolt11", &bolt11tok,
			     "?description", &desctok,
			     NULL)) {
		command_fail(cmd, "Need bolt11 string");
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
	json_add_u64(response, "timestamp", b11->timestamp);
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
	"Parse and decode {bolt11} if possible, using {description} if necessary",
	"Returns a verbose description on success"
};
AUTODATA(json_command, &decodepay_command);
