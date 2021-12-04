/* This implements a cheap gossip cache, so we can recognize what gossip
 * msgs this peer sent us, thus avoid retransmitting gossip it sent. */
#ifndef LIGHTNING_COMMON_GOSSIP_RCVD_FILTER_H
#define LIGHTNING_COMMON_GOSSIP_RCVD_FILTER_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct gossip_rcvd_filter;

struct gossip_rcvd_filter *new_gossip_rcvd_filter(const tal_t *ctx);

/* Add a gossip msg to the received map */
void gossip_rcvd_filter_add(struct gossip_rcvd_filter *map, const u8 *msg);

/* Is a gossip msg in the received map? (Removes it) */
bool gossip_rcvd_filter_del(struct gossip_rcvd_filter *map, const u8 *msg);

/* Flush out old entries. */
void gossip_rcvd_filter_age(struct gossip_rcvd_filter *map);

#endif /* LIGHTNING_COMMON_GOSSIP_RCVD_FILTER_H */
