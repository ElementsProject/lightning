#include "features.h"
#include <assert.h>
#include <ccan/array_size/array_size.h>
#include <common/utils.h>
#include <wire/peer_wire.h>

static const u32 our_features[] = {
	OPTIONAL_FEATURE(OPT_DATA_LOSS_PROTECT),
	OPTIONAL_FEATURE(OPT_UPFRONT_SHUTDOWN_SCRIPT),
	OPTIONAL_FEATURE(OPT_GOSSIP_QUERIES),
#if EXPERIMENTAL_FEATURES
	OPTIONAL_FEATURE(OPT_VAR_ONION),
	OPTIONAL_FEATURE(OPT_PAYMENT_SECRET),
#endif
	OPTIONAL_FEATURE(OPT_GOSSIP_QUERIES_EX),
	OPTIONAL_FEATURE(OPT_STATIC_REMOTEKEY),
};

enum feature_copy_style {
	/* Feature is not exposed (importantly, being 0, this is the default!). */
	FEATURE_DONT_REPRESENT,
	/* Feature is exposed. */
	FEATURE_REPRESENT,
	/* Feature is exposed, but always optional. */
	FEATURE_REPRESENT_AS_OPTIONAL,
};

enum feature_place {
	INIT_FEATURE,
	GLOBAL_INIT_FEATURE,
	NODE_ANNOUNCE_FEATURE,
	BOLT11_FEATURE,
};
#define NUM_FEATURE_PLACE (BOLT11_FEATURE+1)

struct feature_style {
	u32 bit;
	enum feature_copy_style copy_style[NUM_FEATURE_PLACE];
};

static const struct feature_style feature_styles[] = {
	{ OPT_DATA_LOSS_PROTECT,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT } },
	{ OPT_INITIAL_ROUTING_SYNC,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT_AS_OPTIONAL,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_DONT_REPRESENT } },
	{ OPT_UPFRONT_SHUTDOWN_SCRIPT,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT } },
	{ OPT_GOSSIP_QUERIES,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT } },
	{ OPT_GOSSIP_QUERIES_EX,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT } },
	{ OPT_VAR_ONION,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [GLOBAL_INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT,
			  [BOLT11_FEATURE] = FEATURE_REPRESENT } },
	{ OPT_STATIC_REMOTEKEY,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [GLOBAL_INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT } },
	{ OPT_PAYMENT_SECRET,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT,
			  [BOLT11_FEATURE] = FEATURE_REPRESENT } },
	{ OPT_BASIC_MPP,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT,
			  [BOLT11_FEATURE] = FEATURE_REPRESENT } },
};

static enum feature_copy_style feature_copy_style(u32 f, enum feature_place p)
{
	for (size_t i = 0; i < ARRAY_SIZE(feature_styles); i++) {
		if (feature_styles[i].bit == COMPULSORY_FEATURE(f))
			return feature_styles[i].copy_style[p];
	}
	abort();
}

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

static u8 *mkfeatures(const tal_t *ctx, enum feature_place place)
{
	u8 *f = tal_arr(ctx, u8, 0);

	for (size_t i = 0; i < ARRAY_SIZE(our_features); i++) {
		switch (feature_copy_style(our_features[i], place)) {
		case FEATURE_DONT_REPRESENT:
			continue;
		case FEATURE_REPRESENT:
			set_feature_bit(&f, our_features[i]);
			continue;
		case FEATURE_REPRESENT_AS_OPTIONAL:
			set_feature_bit(&f, OPTIONAL_FEATURE(our_features[i]));
			continue;
		}
		abort();
	}
	return f;
}

u8 *get_offered_nodefeatures(const tal_t *ctx)
{
	return mkfeatures(ctx, NODE_ANNOUNCE_FEATURE);
}

u8 *get_offered_initfeatures(const tal_t *ctx)
{
	return mkfeatures(ctx, INIT_FEATURE);
}

u8 *get_offered_globalinitfeatures(const tal_t *ctx)
{
	return mkfeatures(ctx, GLOBAL_INIT_FEATURE);
}

u8 *get_offered_bolt11features(const tal_t *ctx)
{
	return mkfeatures(ctx, BOLT11_FEATURE);
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
 *
 * Returns -1 on success, or first unsupported feature.
 */
static int all_supported_features(const u8 *bitmap,
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

		return bitnum;
	}
	return -1;
}

int features_unsupported(const u8 *features)
{
	/* BIT 2 would logically be "compulsory initial_routing_sync", but
	 * that does not exist, so we special case it. */
	if (feature_is_set(features,
			   COMPULSORY_FEATURE(OPT_INITIAL_ROUTING_SYNC)))
		return COMPULSORY_FEATURE(OPT_INITIAL_ROUTING_SYNC);

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
		"option_static_remotekey",
		"option_payment_secret",
		"option_basic_mpp",
	};

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
