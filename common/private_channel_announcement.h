#ifndef LIGHTNING_COMMON_PRIVATE_CHANNEL_ANNOUNCEMENT_H
#define LIGHTNING_COMMON_PRIVATE_CHANNEL_ANNOUNCEMENT_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct short_channel_id;
struct node_id;

/* Helper to create a fake channel announcement for local channels. */
const u8 *private_channel_announcement(const tal_t *ctx,
				       const struct short_channel_id *scid,
				       const struct node_id *local_node_id,
				       const struct node_id *remote_node_id,
				       const u8 *features);

#endif /* LIGHTNING_COMMON_PRIVATE_CHANNEL_ANNOUNCEMENT_H */
