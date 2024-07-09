#ifndef LIGHTNING_CONNECTD_QUERIES_H
#define LIGHTNING_CONNECTD_QUERIES_H
#include "config.h"

/* See if there's a query to respond to: if so, return some msgs */
const u8 **maybe_create_query_responses(const tal_t *ctx,
					struct peer *peer,
					struct gossmap *gossmap);

void handle_query_short_channel_ids(struct peer *peer, const u8 *msg);
void handle_query_channel_range(struct peer *peer, const u8 *msg);

void dev_set_max_scids_encode_size(struct daemon *daemon, const u8 *msg);
#endif /* LIGHTNING_CONNECTD_QUERIES_H */
