#ifndef LIGHTNING_COMMON_CHANNEL_ID_H
#define LIGHTNING_COMMON_CHANNEL_ID_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/tal.h>

struct bitcoin_outpoint;
struct pubkey;

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

/* For v1 channel establishment */
void derive_channel_id(struct channel_id *channel_id,
		       const struct bitcoin_outpoint *outpoint);

/* For v1 channel establishment */
void temporary_channel_id(struct channel_id *channel_id);

/* For v2 channel establishment */
void derive_channel_id_v2(struct channel_id *channel_id,
			  const struct pubkey *basepoint_1,
			  const struct pubkey *basepoint_2);

/* For v2 channel establishment */
void derive_tmp_channel_id(struct channel_id *channel_id,
			   const struct pubkey *opener_basepoint);

char *fmt_channel_id(const tal_t *ctx, const struct channel_id *channel_id);

/* Marshalling/unmarshalling functions */
void towire_channel_id(u8 **pptr, const struct channel_id *channel_id);
bool fromwire_channel_id(const u8 **cursor, size_t *max,
			 struct channel_id *channel_id);
#endif /* LIGHTNING_COMMON_CHANNEL_ID_H */
