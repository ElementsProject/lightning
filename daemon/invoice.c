#include "db.h"
#include "invoice.h"
#include "jsonrpc.h"
#include "lightningd.h"
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <sodium/randombytes.h>

struct invoice *find_invoice(struct lightningd_state *dstate,
			     const struct sha256 *rhash)
{
	struct invoice *i;

	list_for_each(&dstate->invoices, i, list) {
		if (structeq(rhash, &i->rhash))
			return i;
	}
	return NULL;
}

static struct invoice *find_invoice_by_label(struct lightningd_state *dstate,
					     const char *label)
{
	struct invoice *i;

	list_for_each(&dstate->invoices, i, list) {
		if (streq(i->label, label))
			return i;
	}
	return NULL;
}

void invoice_add(struct lightningd_state *dstate,
		 const struct rval *r,
		 u64 msatoshi,
		 const char *label,
		 bool complete)
{
	struct invoice *invoice = tal(dstate, struct invoice);

	invoice->msatoshi = msatoshi;
	invoice->r = *r;
	invoice->complete = complete;
	invoice->label = tal_strdup(invoice, label);
	sha256(&invoice->rhash, invoice->r.r, sizeof(invoice->r.r));
	list_add(&dstate->invoices, &invoice->list);
}

static void json_invoice(struct command *cmd,
			 const char *buffer, const jsmntok_t *params)
{
	struct invoice *invoice;
	jsmntok_t *msatoshi, *r, *label;
	struct json_result *response = new_json_result(cmd);	

	if (!json_get_params(buffer, params,
			     "amount", &msatoshi,
			     "label", &label,
			     "?r", &r,
			     NULL)) {
		command_fail(cmd, "Need {amount} and {label}");
		return;
	}

	invoice = tal(cmd, struct invoice);
	if (r) {
		if (!hex_decode(buffer + r->start, r->end - r->start,
				invoice->r.r, sizeof(invoice->r.r))) {
			command_fail(cmd, "Invalid hex r '%.*s'",
				     r->end - r->start, buffer + r->start);
			return;
		}
	} else
		randombytes_buf(invoice->r.r, sizeof(invoice->r.r));

	sha256(&invoice->rhash, invoice->r.r, sizeof(invoice->r.r));
	if (find_invoice(cmd->dstate, &invoice->rhash)) {
		command_fail(cmd, "Duplicate r value '%.*s'",
			     r->end - r->start, buffer + r->start);
		return;
	}

	if (!json_tok_u64(buffer, msatoshi, &invoice->msatoshi)
	    || invoice->msatoshi == 0) {
		command_fail(cmd, "'%.*s' is not a valid positive number",
			     msatoshi->end - msatoshi->start,
			     buffer + msatoshi->start);
		return;
	}

	invoice->label = tal_strndup(invoice, buffer + label->start,
				     label->end - label->start);
	if (find_invoice_by_label(cmd->dstate, invoice->label)) {
		command_fail(cmd, "Duplicate label '%s'", invoice->label);
		return;
	}
	if (strlen(invoice->label) > INVOICE_MAX_LABEL_LEN) {
		command_fail(cmd, "label '%s' over %u bytes", invoice->label,
			     INVOICE_MAX_LABEL_LEN);
		return;
	}
	invoice->complete = false;

	if (!db_new_invoice(cmd->dstate, invoice->msatoshi, invoice->label,
			    &invoice->r)) {
		command_fail(cmd, "database error");
		return;
	}		
	/* OK, connect it to main state, respond with hash */
	tal_steal(cmd->dstate, invoice);
	list_add(&cmd->dstate->invoices, &invoice->list);

	json_object_start(response, NULL);
	json_add_hex(response, "rhash",
		     &invoice->rhash, sizeof(invoice->rhash));
	json_object_end(response);

	command_success(cmd, response);
}

const struct json_command invoice_command = {
	"invoice",
	json_invoice,
	"Create invoice for {msatoshi} with {label} (with a set {r}, otherwise generate one)",
	"Returns the {rhash} on success. "
};
