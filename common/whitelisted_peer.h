#ifndef LIGHTNING_COMMON_WHITELISTED_PEER_H
#define LIGHTNING_COMMON_WHITELISTED_PEER_H
#include "config.h"
#include <ccan/htable/htable_type.h>
#include <ccan/tal/tal.h>
#include <common/node_id.h>
#include <common/wireaddr.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct daemon;

struct whitelisted_peer {
	struct node_id id;
	struct wireaddr_internal *my_alt_addrs;
};

/* Function for populating the hashtable */
void populate_whitelist_table(struct daemon *daemon,
			      struct whitelisted_peer *peers);

void towire_whitelisted_peer(uint8_t **p,
			     const struct whitelisted_peer *whitelisted_peer);

bool fromwire_whitelisted_peer(const uint8_t **cursor, size_t *plen,
			       struct whitelisted_peer *whitelisted_peer);

#endif /* LIGHTNING_COMMON_WHITELISTED_PEER_H */
