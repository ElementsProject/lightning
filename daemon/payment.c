#include "jsonrpc.h"
#include "lightningd.h"
#include "payment.h"
#include <ccan/str/hex/hex.h>
#include <ccan/structeq/structeq.h>
#include <sodium/randombytes.h>

struct payment *find_payment(struct lightningd_state *dstate,
			     const struct sha256 *rhash)
{
	struct payment *i;

	list_for_each(&dstate->payments, i, list) {
		if (structeq(rhash, &i->rhash))
			return i;
	}
	return NULL;
}

static void json_accept_payment(struct command *cmd,
				const char *buffer, const jsmntok_t *params)
{
	struct payment *payment;
	jsmntok_t *msatoshis, *r;
	struct json_result *response = new_json_result(cmd);	

	if (!json_get_params(buffer, params,
			     "amount", &msatoshis,
			     "?r", &r,
			     NULL)) {
		command_fail(cmd, "Need {amount}");
		return;
	}

	payment = tal(cmd, struct payment);
	if (r) {
		if (!hex_decode(buffer + r->start, r->end - r->start,
				payment->r.r, sizeof(payment->r.r))) {
			command_fail(cmd, "Invalid hex r '%.*s'",
				     r->end - r->start, buffer + r->start);
			return;
		}
	} else
		randombytes_buf(payment->r.r, sizeof(payment->r.r));

	sha256(&payment->rhash, payment->r.r, sizeof(payment->r.r));
	if (find_payment(cmd->dstate, &payment->rhash)) {
		command_fail(cmd, "Duplicate r value '%.*s'",
			     r->end - r->start, buffer + r->start);
		return;
	}

	if (!json_tok_u64(buffer, msatoshis, &payment->msatoshis)
	    || payment->msatoshis == 0) {
		command_fail(cmd, "'%.*s' is not a valid positive number",
			     msatoshis->end - msatoshis->start,
			     buffer + msatoshis->start);
		return;
	}

	/* OK, connect it to main state, respond with hash */
	tal_steal(cmd->dstate, payment);
	list_add(&cmd->dstate->payments, &payment->list);

	json_object_start(response, NULL);
	json_add_hex(response, "rhash",
		     &payment->rhash, sizeof(payment->rhash));
	json_object_end(response);

	command_success(cmd, response);
}

const struct json_command accept_payment_command = {
	"accept-payment",
	json_accept_payment,
	"Accept payment for {amount} (with a set {r}, otherwise generate one)",
	"Returns the {rhash} on success. "
};
