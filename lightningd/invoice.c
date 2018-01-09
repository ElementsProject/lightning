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

struct invoice_waiter {
	struct list_node list;
	struct command *cmd;
};

/* FIXME: remove this, just use database ops. */
struct invoices {
	/* Payments for r values we know about. */
	struct list_head invlist;
	/* Waiting for new invoices to be paid. */
	struct list_head waitany_waiters;
};

struct invoice *find_unpaid(struct invoices *invs, const struct sha256 *rhash)
{
	struct invoice *i;

	list_for_each(&invs->invlist, i, list) {
		if (structeq(rhash, &i->rhash) && i->state == UNPAID) {
			if (time_now().ts.tv_sec > i->expiry_time)
				break;
			return i;
		}
	}
	return NULL;
}

static struct invoice *find_invoice_by_label(const struct invoices *invs,
					     const char *label)
{
	struct invoice *i;

	list_for_each(&invs->invlist, i, list) {
		if (streq(i->label, label))
			return i;
	}
	return NULL;
}

void invoice_add(struct invoices *invs,
		 struct invoice *inv)
{
	sha256(&inv->rhash, inv->r.r, sizeof(inv->r.r));
	list_add(&invs->invlist, &inv->list);
}

struct invoices *invoices_init(const tal_t *ctx)
{
	struct invoices *invs = tal(ctx, struct invoices);

	list_head_init(&invs->invlist);
	list_head_init(&invs->waitany_waiters);

	return invs;
}

static void tell_waiter(struct command *cmd, const struct invoice *paid)
{
	struct json_result *response = new_json_result(cmd);

	json_object_start(response, NULL);
	json_add_string(response, "label", paid->label);
	json_add_hex(response, "rhash", &paid->rhash, sizeof(paid->rhash));
	if (paid->msatoshi)
		json_add_u64(response, "msatoshi", *paid->msatoshi);
	json_add_bool(response, "complete", paid->state == PAID);
	if (paid->state == PAID)
		json_add_u64(response, "pay_index", paid->pay_index);
	json_object_end(response);
	command_success(cmd, response);
}
static void tell_waiter_deleted(struct command *cmd, const struct invoice *paid)
{
	command_fail(cmd, "invoice deleted during wait");
}

void resolve_invoice(struct lightningd *ld, struct invoice *invoice)
{
	struct invoice_waiter *w;
	struct invoices *invs = ld->invoices;

	invoice->state = PAID;

	/* wallet_invoice_save updates pay_index member,
	 * which tell_waiter needs. */
	wallet_invoice_save(ld->wallet, invoice);

	/* Yes, there are two loops: the first is for wait*any*invoice,
	 * the second is for waitinvoice (without any). */
	/* Tell all the waitanyinvoice waiters about the new paid invoice */
	while ((w = list_pop(&invs->waitany_waiters,
			     struct invoice_waiter,
			     list)) != NULL)
		tell_waiter(w->cmd, invoice);
	/* Tell any waitinvoice waiters about the invoice getting paid. */
	while ((w = list_pop(&invoice->waitone_waiters,
			     struct invoice_waiter,
			     list)) != NULL)
		tell_waiter(w->cmd, invoice);

	/* Also mark the payment in the history table as complete */
	wallet_payment_set_status(ld->wallet, &invoice->rhash, PAYMENT_COMPLETE);
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

/* Return NULL if no error, or an error string otherwise. */
static char *delete_invoice(const tal_t *cxt,
			    struct wallet *wallet,
			    struct invoices *invs,
			    struct invoice *i)
{
	struct invoice_waiter *w;
	if (!wallet_invoice_remove(wallet, i)) {
		return tal_strdup(cxt, "Database error");
	}
	list_del_from(&invs->invlist, &i->list);

	/* Tell all the waiters about the fact that it was deleted. */
	while ((w = list_pop(&i->waitone_waiters,
			     struct invoice_waiter,
			     list)) != NULL) {
		tell_waiter_deleted(w->cmd, i);
		/* No need to free w: w is a sub-object of cmd,
		 * and tell_waiter_deleted also deletes the cmd. */
	}

	tal_free(i);
	return NULL;
}

static void json_invoice(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct invoice *invoice;
	jsmntok_t *msatoshi, *label, *desc, *exp;
	struct json_result *response = new_json_result(cmd);
	struct invoices *invs = cmd->ld->invoices;
	struct bolt11 *b11;
	char *b11enc;
	struct wallet_payment payment;
	u64 expiry = 3600;

	if (!json_get_params(buffer, params,
			     "amount", &msatoshi,
			     "label", &label,
			     "description", &desc,
			     "?expiry", &exp,
			     NULL)) {
		command_fail(cmd, "Need {amount}, {label} and {description}");
		return;
	}

	invoice = tal(cmd, struct invoice);
	invoice->id = 0;
	invoice->state = UNPAID;
	invoice->pay_index = 0;
	list_head_init(&invoice->waitone_waiters);
	randombytes_buf(invoice->r.r, sizeof(invoice->r.r));

	sha256(&invoice->rhash, invoice->r.r, sizeof(invoice->r.r));

	invoice->msatoshi = tal(invoice, u64);
	if (!json_tok_u64(buffer, msatoshi, invoice->msatoshi)
	    || *invoice->msatoshi == 0) {
		command_fail(cmd, "'%.*s' is not a valid positive number",
			     msatoshi->end - msatoshi->start,
			     buffer + msatoshi->start);
		return;
	}

	invoice->label = tal_strndup(invoice, buffer + label->start,
				     label->end - label->start);
	if (find_invoice_by_label(invs, invoice->label)) {
		command_fail(cmd, "Duplicate label '%s'", invoice->label);
		return;
	}
	if (strlen(invoice->label) > INVOICE_MAX_LABEL_LEN) {
		command_fail(cmd, "label '%s' over %u bytes", invoice->label,
			     INVOICE_MAX_LABEL_LEN);
		return;
	}

	if (exp && !json_tok_u64(buffer, exp, &expiry)) {
		command_fail(cmd, "expiry '%.*s' invalid seconds",
			     exp->end - exp->start,
			     buffer + exp->start);
		return;
	}

	/* Expires at this absolute time. */
	invoice->expiry_time = time_now().ts.tv_sec + expiry;

	wallet_invoice_save(cmd->ld->wallet, invoice);

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

	/* OK, connect it to main state, respond with hash */
	tal_steal(invs, invoice);
	list_add_tail(&invs->invlist, &invoice->list);

	/* Store the payment so we can later show it in the history */
	payment.id = 0;
	payment.incoming = true;
	payment.payment_hash = invoice->rhash;
	payment.destination = NULL;
	payment.status = PAYMENT_PENDING;
	payment.msatoshi = *invoice->msatoshi;
	payment.timestamp = b11->timestamp;

	if (!wallet_payment_add(cmd->ld->wallet, &payment)) {
		command_fail(cmd, "Unable to record payment in the database.");
		return;
	}

	json_object_start(response, NULL);
	json_add_hex(response, "rhash",
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
	"Returns the {rhash}, {expiry_time} and {bolt11} on success, and {description} if too alrge for {bolt11}. "
};
AUTODATA(json_command, &invoice_command);

static void json_add_invoices(struct json_result *response,
			      const struct list_head *list,
			      const char *buffer, const jsmntok_t *label)
{
	struct invoice *i;
	char *lbl = NULL;
	if (label)
		lbl = tal_strndup(response, &buffer[label->start], label->end - label->start);

	list_for_each(list, i, list) {
		if (lbl && !streq(i->label, lbl))
			continue;
		json_object_start(response, NULL);
		json_add_string(response, "label", i->label);
		json_add_hex(response, "rhash", &i->rhash, sizeof(i->rhash));
		if (i->msatoshi)
			json_add_u64(response, "msatoshi", *i->msatoshi);
		json_add_bool(response, "complete", i->state == PAID);
		json_add_u64(response, "expiry_time", i->expiry_time);
		json_object_end(response);
	}
}

static void json_listinvoice(struct command *cmd,
			     const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *label = NULL;
	struct json_result *response = new_json_result(cmd);
	struct invoices *invs = cmd->ld->invoices;

	if (!json_get_params(buffer, params,
			     "?label", &label,
			     NULL)) {
		command_fail(cmd, "Invalid arguments");
		return;
	}


	json_array_start(response, NULL);
	json_add_invoices(response, &invs->invlist, buffer, label);
	json_array_end(response);
	command_success(cmd, response);
}

static const struct json_command listinvoice_command = {
	"listinvoice",
	json_listinvoice,
	"Show invoice {label} (or all, if no {label}))",
	"Returns an array of {label}, {rhash}, {msatoshi} and {complete} on success. "
};
AUTODATA(json_command, &listinvoice_command);

static void json_delinvoice(struct command *cmd,
			    const char *buffer, const jsmntok_t *params)
{
	struct invoice *i;
	jsmntok_t *labeltok;
	struct json_result *response = new_json_result(cmd);
	const char *label;
	struct invoices *invs = cmd->ld->invoices;
	char *error;

	if (!json_get_params(buffer, params,
			     "label", &labeltok,
			     NULL)) {
		command_fail(cmd, "Invalid arguments");
		return;
	}

	label = tal_strndup(cmd, buffer + labeltok->start,
			    labeltok->end - labeltok->start);
	i = find_invoice_by_label(invs, label);
	if (!i) {
		command_fail(cmd, "Unknown invoice");
		return;
	}

	/* Get invoice details before attempting to delete, as
	 * otherwise the invoice will be freed. */
	json_object_start(response, NULL);
	json_add_string(response, "label", i->label);
	json_add_hex(response, "rhash", &i->rhash, sizeof(i->rhash));
	if (i->msatoshi)
		json_add_u64(response, "msatoshi", *i->msatoshi);
	json_object_end(response);

	error = delete_invoice(cmd, cmd->ld->wallet, invs, i);

	if (error) {
		log_broken(cmd->ld->log, "Error attempting to remove invoice %"PRIu64,
			   i->id);
		command_fail(cmd, "%s", error);
		/* Both error and response are sub-objects of cmd,
		 * and command_fail will free cmd (and also error
		 * and response). */
		return;
	}

	command_success(cmd, response);
}

static const struct json_command delinvoice_command = {
	"delinvoice",
	json_delinvoice,
	"Delete unpaid invoice {label}))",
	"Returns {label}, {rhash} and {msatoshi} on success. "
};
AUTODATA(json_command, &delinvoice_command);

static void json_waitanyinvoice(struct command *cmd,
			    const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *pay_indextok;
	u64 pay_index;
	struct invoice_waiter *w;
	struct invoices *invs = cmd->ld->invoices;
	bool res;
	struct wallet *wallet = cmd->ld->wallet;
	char* outlabel;
	struct sha256 outrhash;
	u64 outmsatoshi;
	u64 outpay_index;
	struct json_result *response;

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

	/* Find next paid invoice. */
	res = wallet_invoice_nextpaid(cmd, wallet, pay_index,
				      &outlabel, &outrhash,
				      &outmsatoshi, &outpay_index);

	/* If we found one, return it. */
	if (res) {
		response = new_json_result(cmd);

		json_object_start(response, NULL);
		json_add_string(response, "label", outlabel);
		json_add_hex(response, "rhash", &outrhash, sizeof(outrhash));
		json_add_u64(response, "msatoshi", outmsatoshi);
		json_add_bool(response, "complete", true);
		json_add_u64(response, "pay_index", outpay_index);
		json_object_end(response);

		command_success(cmd, response);

		/* outlabel is freed when cmd is freed, and command_success
		 * also frees cmd. */
		return;
	}

	/* Otherwise, wait. */
	/* FIXME: Better to use io_wait directly? */
	w = tal(cmd, struct invoice_waiter);
	w->cmd = cmd;
	list_add_tail(&invs->waitany_waiters, &w->list);
	command_still_pending(cmd);
}

static const struct json_command waitanyinvoice_command = {
	"waitanyinvoice",
	json_waitanyinvoice,
	"Wait for the next invoice to be paid, after {lastpay_index} (if supplied)))",
	"Returns {label}, {rhash}, {msatoshi}, and {pay_index} on success. "
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
	struct invoice *i;
	jsmntok_t *labeltok;
	const char *label = NULL;
	struct invoice_waiter *w;
	struct invoices *invs = cmd->ld->invoices;

	if (!json_get_params(buffer, params, "label", &labeltok, NULL)) {
		command_fail(cmd, "Missing {label}");
		return;
	}

	/* Search in paid invoices, if found return immediately */
	label = tal_strndup(cmd, buffer + labeltok->start, labeltok->end - labeltok->start);
	i = find_invoice_by_label(invs, label);

	if (!i) {
		command_fail(cmd, "Label not found");
		return;
	} else if (i->state == PAID) {
		tell_waiter(cmd, i);
		return;
	} else {
		/* There is an unpaid one matching, let's wait... */
		w = tal(cmd, struct invoice_waiter);
		w->cmd = cmd;
		list_add_tail(&i->waitone_waiters, &w->list);
		command_still_pending(cmd);
	}
}

static const struct json_command waitinvoice_command = {
	"waitinvoice",
	json_waitinvoice,
	"Wait for an incoming payment matching the invoice with {label}",
	"Returns {label}, {rhash} and {msatoshi} on success"
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
	"Parse and decode {bolt11} if possible",
	"Returns a verbose description on success"
};
AUTODATA(json_command, &decodepay_command);
