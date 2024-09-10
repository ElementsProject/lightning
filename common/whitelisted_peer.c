#include "config.h"
#include <common/whitelisted_peer.h>
#include <connectd/connectd.h>
#include <wire/wire.h>

static void destroy_whitelisted_peer(struct whitelisted_peer *peer)
{
	if (peer->my_alt_addrs)
		tal_free(peer->my_alt_addrs);
	tal_free(peer);
}

void populate_whitelist_table(struct daemon *daemon,
			      struct whitelisted_peer *wp)
{
	if (wp) {
		size_t num_whitelisted = tal_count(wp);
		for (size_t i = 0; i < num_whitelisted; i++) {
			if (whitelisted_peer_htable_get(daemon->whitelisted_peer_htable,
							&wp[i].id)) {
				tal_free(&wp[i]);
				continue;
			}

			struct whitelisted_peer *new_peer = tal_steal(daemon,
								      &wp[i]);

			whitelisted_peer_htable_add(daemon->whitelisted_peer_htable,
						    new_peer);

			tal_add_destructor(new_peer, destroy_whitelisted_peer);
		}
	}
}

void towire_whitelisted_peer(uint8_t **p, const struct whitelisted_peer *wp)
{
	/* Serialize the node_id */
	towire_node_id(p, &wp->id);

	/* Serialize the num of addrs */
	uint16_t num_alt_addrs = tal_count(wp->my_alt_addrs);
	towire_u16(p, num_alt_addrs);

	/* Serialize each alternate address */
	for (size_t i = 0; i < num_alt_addrs; i++)
		towire_wireaddr_internal(p, &wp->my_alt_addrs[i]);
}

bool fromwire_whitelisted_peer(const uint8_t **cursor,
			       size_t *plen,
			       struct whitelisted_peer *wp)
{
	/* Deserialize the node_id */
	fromwire_node_id(cursor, plen, &wp->id);

	/* Deserialize the number of alternate addresses */
	uint16_t num_alt_addrs = fromwire_u16(cursor, plen);

	wp->my_alt_addrs = tal_arr(wp, struct wireaddr_internal, num_alt_addrs);

	/* Deserialize each alternate address */
	for (size_t i = 0; i < num_alt_addrs; i++)
		if (!fromwire_wireaddr_internal(cursor, plen, &wp->my_alt_addrs[i]))
			return false;

	return *cursor != NULL;
}
