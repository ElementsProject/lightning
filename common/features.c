#include "features.h"
#include <wire/peer_wire.h>

static const u8 supported_local_features[]
= {LOCALFEATURES_INITIAL_ROUTING_SYNC};
static const u8 supported_global_features[]
= {};

u8 *get_supported_global_features(const tal_t *ctx)
{
	return tal_dup_arr(ctx, u8, supported_global_features,
			   sizeof(supported_global_features), 0);
}

u8 *get_supported_local_features(const tal_t *ctx)
{
	return tal_dup_arr(ctx, u8, supported_local_features,
			   sizeof(supported_local_features), 0);
}

/**
 * requires_unsupported_features - Check if we support what's being asked
 *
 * Given the features vector that the remote connection is expecting
 * from us, we check to see if we support all even bit features, i.e.,
 * the required features. We do so by subtracting our own features in
 * the provided positions and see if even bits remain.
 *
 * @bitmap: the features bitmap the peer is asking for
 * @supportmap: what do we support
 * @smlen: how long is our supportmap
 */
static bool requires_unsupported_features(const u8 *bitmap,
					  const u8 *supportmap,
					  size_t smlen)
{
	size_t len = tal_count(bitmap);
	u8 support;
	for (size_t i=0; i<len; i++) {
		/* Find matching bitmap byte in supportmap, 0x00 if none */
		if (len > smlen) {
			support = 0x00;
		} else {
			support = supportmap[smlen-1];
		}

		/* Cancel out supported bits, check for even bits */
		if ((~support & bitmap[i]) & 0x55)
			return true;
	}
	return false;
}

bool unsupported_features(const u8 *gfeatures, const u8 *lfeatures)
{
	return requires_unsupported_features(gfeatures,
					     supported_global_features,
					     sizeof(supported_global_features))
		|| requires_unsupported_features(lfeatures,
						 supported_local_features,
						 sizeof(supported_local_features));
}
