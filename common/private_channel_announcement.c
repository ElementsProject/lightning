#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <common/private_channel_announcement.h>
#include <wire/peer_wire.h>

const u8 *private_channel_announcement(const tal_t *ctx,
				       const struct short_channel_id *scid,
				       const struct node_id *local_node_id,
				       const struct node_id *remote_node_id,
				       const u8 *features)
{
	struct pubkey dummy_pubkey;
	const struct node_id *node[2];
	struct secret not_a_secret;

	/* Make an all-zero sig. */
	static const u8 zeros[64];
	size_t zlen = sizeof(zeros);
	const u8 *zerop = zeros;
	secp256k1_ecdsa_signature zerosig;
	fromwire_secp256k1_ecdsa_signature(&zerop, &zlen, &zerosig);
	assert(zerop != NULL);

	memset(&not_a_secret, 1, sizeof(not_a_secret));
	if (!pubkey_from_secret(&not_a_secret, &dummy_pubkey))
		abort();

	/* node ids are in ascending order. */
	if (node_id_cmp(remote_node_id, local_node_id) > 0) {
		node[0] = local_node_id;
		node[1] = remote_node_id;
	} else {
		node[0] = remote_node_id;
		node[1] = local_node_id;
	}

	return towire_channel_announcement(ctx,
					    &zerosig, &zerosig,
					    &zerosig, &zerosig,
					    features,
					    &chainparams->genesis_blockhash,
					    scid,
					    node[0],
					    node[1],
					    &dummy_pubkey,
					    &dummy_pubkey);
}
