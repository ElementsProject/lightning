#include "features.h"
#include <assert.h>
#include <ccan/array_size/array_size.h>
#include <common/memleak.h>
#include <common/utils.h>
#include <wire/peer_wire.h>

/* We keep a map of our features for each context, with the assumption that
 * the init features is a superset of the others. */
static struct feature_set *our_features;

/* FIXME: Remove once all subdaemons call features_init() */
static const u8 *our_feature_bits(enum feature_place place)
{
	if (!our_features) {
		static const u32 our_features[] = {
			OPTIONAL_FEATURE(OPT_DATA_LOSS_PROTECT),
			OPTIONAL_FEATURE(OPT_UPFRONT_SHUTDOWN_SCRIPT),
			OPTIONAL_FEATURE(OPT_GOSSIP_QUERIES),
			OPTIONAL_FEATURE(OPT_VAR_ONION),
			OPTIONAL_FEATURE(OPT_PAYMENT_SECRET),
			OPTIONAL_FEATURE(OPT_BASIC_MPP),
			OPTIONAL_FEATURE(OPT_GOSSIP_QUERIES_EX),
			OPTIONAL_FEATURE(OPT_STATIC_REMOTEKEY),
		};
		u8 *f = tal_arr(NULL, u8, 0);

		for (size_t i = 0; i < ARRAY_SIZE(our_features); i++)
			set_feature_bit(&f, our_features[i]);

		features_core_init(take(f));
	}

	/* This is currently always a superset of other bits */
	return our_features->bits[place];
}

enum feature_copy_style {
	/* Feature is not exposed (importantly, being 0, this is the default!). */
	FEATURE_DONT_REPRESENT,
	/* Feature is exposed. */
	FEATURE_REPRESENT,
	/* Feature is exposed, but always optional. */
	FEATURE_REPRESENT_AS_OPTIONAL,
};

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

static u8 *mkfeatures(const tal_t *ctx, enum feature_place place)
{
	u8 *f = tal_arr(ctx, u8, 0);
	const u8 *base = our_features->bits[INIT_FEATURE];

	assert(place != INIT_FEATURE);
	for (size_t i = 0; i < tal_bytelen(base)*8; i++) {
		if (!feature_is_set(base, i))
			continue;

		switch (feature_copy_style(i, place)) {
		case FEATURE_DONT_REPRESENT:
			continue;
		case FEATURE_REPRESENT:
			set_feature_bit(&f, i);
			continue;
		case FEATURE_REPRESENT_AS_OPTIONAL:
			set_feature_bit(&f, OPTIONAL_FEATURE(i));
			continue;
		}
		abort();
	}
	return f;
}

struct feature_set *features_core_init(const u8 *feature_bits)
{
	assert(!our_features);
	our_features = notleak(tal(NULL, struct feature_set));

	our_features->bits[INIT_FEATURE]
		= tal_dup_talarr(our_features, u8, feature_bits);

	/* Make other masks too */
	for (enum feature_place f = INIT_FEATURE+1; f < NUM_FEATURE_PLACE; f++)
		our_features->bits[f] = mkfeatures(our_features, f);

	return our_features;
}

void features_cleanup(void)
{
	our_features = tal_free(our_features);
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

u8 *get_offered_nodefeatures(const tal_t *ctx)
{
	return tal_dup_talarr(ctx, u8, our_feature_bits(NODE_ANNOUNCE_FEATURE));
}

u8 *get_offered_initfeatures(const tal_t *ctx)
{
	return tal_dup_talarr(ctx, u8, our_feature_bits(INIT_FEATURE));
}

u8 *get_offered_globalinitfeatures(const tal_t *ctx)
{
	return tal_dup_talarr(ctx, u8, our_feature_bits(GLOBAL_INIT_FEATURE));
}

static void clear_feature_bit(u8 *features, u32 bit)
{
	size_t bytenum = bit / 8, bitnum = bit % 8, len = tal_count(features);

	if (bytenum >= len)
		return;

	features[len - 1 - bytenum] &= ~(1 << bitnum);
}

/* BOLT #7:
 *
 *   - MUST set `features` based on what features were negotiated for this channel, according to [BOLT #9](09-features.md#assigned-features-flags)
 *  - MUST set `len` to the minimum length required to hold the `features` bits
 *  it sets.
 */
u8 *get_agreed_channelfeatures(const tal_t *ctx, const u8 *theirfeatures)
{
	u8 *f = tal_dup_talarr(ctx, u8, our_feature_bits(CHANNEL_FEATURE));
	size_t max_len = 0;

	/* Clear any features which they didn't offer too */
	for (size_t i = 0; i < 8 * tal_count(f); i += 2) {
		if (!feature_offered(f, i))
			continue;
		if (!feature_offered(theirfeatures, i)) {
			clear_feature_bit(f, COMPULSORY_FEATURE(i));
			clear_feature_bit(f, OPTIONAL_FEATURE(i));
			continue;
		}
		max_len = (i / 8) + 1;
	}

	/* Trim to length */
	tal_resize(&f, max_len);
	return f;
}

u8 *get_offered_bolt11features(const tal_t *ctx)
{
	return tal_dup_talarr(ctx, u8, our_feature_bits(BOLT11_FEATURE));
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

bool feature_negotiated(const u8 *lfeatures, size_t f)
{
	return feature_offered(lfeatures, f)
		&& feature_offered(our_feature_bits(INIT_FEATURE), f);
}

/**
 * all_supported_features - Check if we support what's being asked
 *
 * Given the features vector that the remote connection is expecting
 * from us, we check to see if we support all even bit features, i.e.,
 * the required features.
 *
 * @bitmap: the features bitmap the peer is asking for
 *
 * Returns -1 on success, or first unsupported feature.
 */
static int all_supported_features(const u8 *bitmap)
{
	size_t len = tal_count(bitmap) * 8;

	/* It's OK to be odd: only check even bits. */
	for (size_t bitnum = 0; bitnum < len; bitnum += 2) {
		if (!test_bit(bitmap, bitnum/8, bitnum%8))
			continue;

		if (feature_offered(our_feature_bits(INIT_FEATURE), bitnum))
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

	return all_supported_features(features);
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

	if (f / 2 >= ARRAY_SIZE(fnames))
		return tal_fmt(ctx, "option_unknown_%zu/%s",
			       COMPULSORY_FEATURE(f), (f & 1) ? "odd" : "even");

	return tal_fmt(ctx, "%s/%s",
		       fnames[f / 2], (f & 1) ? "odd" : "even");
}

const char **list_supported_features(const tal_t *ctx)
{
	const char **list = tal_arr(ctx, const char *, 0);

	for (size_t i = 0; i < tal_bytelen(our_feature_bits(INIT_FEATURE)) * 8; i++) {
		if (test_bit(our_feature_bits(INIT_FEATURE), i / 8, i % 8))
			tal_arr_expand(&list, feature_name(list, i));
	}

	return list;
}

u8 *featurebits_or(const tal_t *ctx, const u8 *f1 TAKES, const u8 *f2 TAKES)
{
	size_t l1 = tal_bytelen(f1), l2 = tal_bytelen(f2);
	u8 *result;

	/* Easier if f2 is shorter. */
	if (l1 < l2)
		return featurebits_or(ctx, f2, f1);

	assert(l2 <= l1);
	result = tal_dup_arr(ctx, u8, f1, l1, 0);

	/* Note: features are packed to the end of the bitmap */
	for (size_t i = 0; i < l2; i++)
		result[l1 - l2 + i] |= f2[i];

	/* Cleanup the featurebits if we were told to do so. */
	if (taken(f2))
		tal_free(f2);

	return result;
}

