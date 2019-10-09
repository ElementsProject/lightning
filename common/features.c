#include "features.h"
#include <assert.h>
#include <ccan/array_size/array_size.h>
#include <common/utils.h>
#include <wire/peer_wire.h>

static const u32 our_features[] = {
	OPTIONAL_FEATURE(OPT_DATA_LOSS_PROTECT),
	OPTIONAL_FEATURE(OPT_UPFRONT_SHUTDOWN_SCRIPT),
	OPTIONAL_FEATURE(OPT_GOSSIP_QUERIES),
	OPTIONAL_FEATURE(OPT_GOSSIP_QUERIES_EX),
	OPTIONAL_FEATURE(OPT_STATIC_REMOTEKEY),
};

/* BOLT #1:
 *
 * All data fields are unsigned big-endian unless otherwise specified.
 */
void set_feature_bit(u8 **ptr, u32 bit)
{
	size_t len = tal_count(*ptr);
	if (bit / 8 >= len) {
		size_t newlen = (bit / 8) + 1;
		u8 *newarr = tal_arrz(tal_parent(*ptr), u8, newlen);
		memcpy(newarr + (newlen - len), *ptr, len);
		tal_free(*ptr);
		*ptr = newarr;
		len = newlen;
	}
	(*ptr)[len - 1 - bit / 8] |= (1 << (bit % 8));
}

static bool test_bit(const u8 *features, size_t byte, unsigned int bit)
{
	assert(byte < tal_count(features));
	return features[tal_count(features) - 1 - byte] & (1 << (bit % 8));
}

static u8 *mkfeatures(const tal_t *ctx, const u32 *arr, size_t n)
{
	u8 *f = tal_arr(ctx, u8, 0);

	for (size_t i = 0; i < n; i++)
		set_feature_bit(&f, arr[i]);
	return f;
}

/* We currently advertize everything in node_announcement, except
 * initial_routing_sync which the spec says not to (and we don't set
 * any more anyway).
 *
 * FIXME: Add bolt ref when finalized!
 */
u8 *get_offered_nodefeatures(const tal_t *ctx)
{
	return mkfeatures(ctx,
			  our_features, ARRAY_SIZE(our_features));
}

u8 *get_offered_features(const tal_t *ctx)
{
	return mkfeatures(ctx,
			  our_features, ARRAY_SIZE(our_features));
}

bool feature_is_set(const u8 *features, size_t bit)
{
	size_t bytenum = bit / 8;

	if (bytenum >= tal_count(features))
		return false;

	return test_bit(features, bytenum, bit % 8);
}

bool feature_offered(const u8 *features, size_t f)
{
	return feature_is_set(features, COMPULSORY_FEATURE(f))
		|| feature_is_set(features, OPTIONAL_FEATURE(f));
}

static bool feature_supported(int feature_bit,
			      const u32 *supported,
			      size_t num_supported)
{
	for (size_t i = 0; i < num_supported; i++) {
		if (OPTIONAL_FEATURE(supported[i])
		    == OPTIONAL_FEATURE(feature_bit))
			return true;
	}
	return false;
}

bool feature_negotiated(const u8 *lfeatures, size_t f)
{
	if (!feature_offered(lfeatures, f))
		return false;
	return feature_supported(f, our_features, ARRAY_SIZE(our_features));
}

/**
 * all_supported_features - Check if we support what's being asked
 *
 * Given the features vector that the remote connection is expecting
 * from us, we check to see if we support all even bit features, i.e.,
 * the required features.
 *
 * @bitmap: the features bitmap the peer is asking for
 * @supported: array of features we support
 * @num_supported: how many elements in supported
 */
static bool all_supported_features(const u8 *bitmap,
				   const u32 *supported,
				   size_t num_supported)
{
	size_t len = tal_count(bitmap) * 8;

	/* It's OK to be odd: only check even bits. */
	for (size_t bitnum = 0; bitnum < len; bitnum += 2) {
		if (!test_bit(bitmap, bitnum/8, bitnum%8))
			continue;

		if (feature_supported(bitnum, supported, num_supported))
			continue;

		return false;
	}
	return true;
}

bool features_supported(const u8 *features)
{
	/* BIT 2 would logically be "compulsory initial_routing_sync", but
	 * that does not exist, so we special case it. */
	if (feature_is_set(features,
			   COMPULSORY_FEATURE(OPT_INITIAL_ROUTING_SYNC)))
		return false;

	return all_supported_features(features,
				      our_features,
				      ARRAY_SIZE(our_features));
}

static const char *feature_name(const tal_t *ctx, size_t f)
{
	static const char *fnames[] = {
		"option_data_loss_protect",
		"option_initial_routing_sync",
		"option_upfront_shutdown_script",
		"option_gossip_queries",
		"option_var_onion_optin",
		"option_gossip_queries_ex",
		"option_static_remotekey" };

	assert(f / 2 < ARRAY_SIZE(fnames));
	return tal_fmt(ctx, "%s/%s",
		       fnames[f / 2], (f & 1) ? "odd" : "even");
}

const char **list_supported_features(const tal_t *ctx)
{
	const char **list = tal_arr(ctx, const char *, 0);

	for (size_t i = 0; i < ARRAY_SIZE(our_features); i++)
		tal_arr_expand(&list, feature_name(list, our_features[i]));

	return list;
}
