#include "config.h"

#include <ccan/crypto/sha256/sha256.h>
#include <ccan/tal/str/str.h>
#include <common/amount.h>
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

	return ev;
}
