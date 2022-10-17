#include <bitcoin/pubkey.h>
#include <common/gossmap.h>
#include <common/node_id.h>
#include <plugins/pay_point32.h>

/* There are two 33-byte pubkeys possible: choose the one which appears
 * in the graph (otherwise payment will fail anyway). */
void gossmap_guess_node_id(const struct gossmap *map,
			   const struct point32 *point32,
			   struct node_id *id)
{
	struct pubkey pk;
	pk.pubkey = point32->pubkey;
	node_id_from_pubkey(id, &pk);

	/* If we don't find this, let's assume it's the alternate. */
	if (!gossmap_find_node(map, id))
		id->k[0] |= 1;
}

