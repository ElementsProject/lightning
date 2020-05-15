#ifndef LIGHTNING_COMMON_CHANNEL_ID_H
#define LIGHTNING_COMMON_CHANNEL_ID_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/structeq/structeq.h>

struct bitcoin_txid;

/* BOLT #2:
 *
 * This message introduces the `channel_id` to identify the channel.  It's
 * derived from the funding transaction by combining the `funding_txid` and
 * the `funding_output_index`, using big-endian exclusive-OR
 * (i.e. `funding_output_index` alters the last 2 bytes).
 */
struct channel_id {
	u8 id[32];
};
/* Define channel_id_eq (no padding) */
STRUCTEQ_DEF(channel_id, 0, id);

void derive_channel_id(struct channel_id *channel_id,
		       const struct bitcoin_txid *txid, u16 txout);

/* Marshalling/unmarshalling functions */
void towire_channel_id(u8 **pptr, const struct channel_id *channel_id);
void fromwire_channel_id(const u8 **cursor, size_t *max,
			 struct channel_id *channel_id);
#endif /* LIGHTNING_COMMON_CHANNEL_ID_H */
