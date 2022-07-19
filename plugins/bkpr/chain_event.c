#include "config.h"

#include <common/json_stream.h>
#include <plugins/bkpr/chain_event.h>

void json_add_chain_event(struct json_stream *out, struct chain_event *ev)
{
	json_object_start(out, NULL);
	json_add_string(out, "account", ev->acct_name);
	if (ev->origin_acct)
		json_add_string(out, "origin", ev->origin_acct);
	json_add_string(out, "type", "chain");
	json_add_string(out, "tag", ev->tag);
	json_add_amount_msat_only(out, "credit_msat", ev->credit);
	json_add_amount_msat_only(out, "debit_msat", ev->debit);
	json_add_string(out, "currency", ev->currency);
	json_add_outpoint(out, "outpoint", &ev->outpoint);

	if (ev->spending_txid)
		json_add_txid(out, "txid", ev->spending_txid);
	if (ev->payment_id)
		json_add_sha256(out, "payment_id", ev->payment_id);
	json_add_u64(out, "timestamp", ev->timestamp);
	json_add_u32(out, "blockheight", ev->blockheight);
	if (ev->desc)
		json_add_string(out, "description", ev->desc);
	json_object_end(out);
}
