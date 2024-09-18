#include "config.h"

#include <ccan/crypto/sha256/sha256.h>
#include <ccan/tal/str/str.h>
#include <common/amount.h>
#include <common/json_stream.h>
#include <plugins/bkpr/channel_event.h>

struct channel_event *new_channel_event(const tal_t *ctx,
					const char *tag,
					struct amount_msat credit,
					struct amount_msat debit,
					struct amount_msat fees,
					const char *currency,
					struct sha256 *payment_id STEALS,
					u32 part_id,
					u64 timestamp)
{
	struct channel_event *ev = tal(ctx, struct channel_event);

	ev->tag = tal_strdup(ev, tag);
	ev->credit = credit;
	ev->debit = debit;
	ev->fees = fees;
	ev->currency = tal_strdup(ev, currency);
	ev->payment_id = tal_steal(ev, payment_id);
	ev->part_id = part_id;
	ev->timestamp = timestamp;
	ev->desc = NULL;
	ev->rebalance_id = NULL;

	return ev;
}

void json_add_channel_event(struct json_stream *out,
			    struct channel_event *ev)
{
	json_object_start(out, NULL);
	json_add_string(out, "account", ev->acct_name);
	json_add_string(out, "type", "channel");
	json_add_string(out, "tag", ev->tag);
	json_add_amount_msat(out, "credit_msat", ev->credit);
	json_add_amount_msat(out, "debit_msat", ev->debit);
	if (!amount_msat_is_zero(ev->fees))
		json_add_amount_msat(out, "fees_msat", ev->fees);
	json_add_string(out, "currency", ev->currency);
	if (ev->payment_id) {
		json_add_sha256(out, "payment_id", ev->payment_id);
		json_add_u32(out, "part_id", ev->part_id);
	}
	json_add_u64(out, "timestamp", ev->timestamp);
	if (ev->desc)
		json_add_string(out, "description", ev->desc);
	json_add_bool(out, "is_rebalance", ev->rebalance_id != NULL);
	json_object_end(out);
}
