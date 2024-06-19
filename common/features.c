#include "config.h"
#include <assert.h>
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/features.h>
#include <wire/peer_wire.h>

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

const char *feature_place_names[] = {
	"init",
	NULL,
	"node",
	"channel",
	"invoice"
};

static const struct feature_style feature_styles[] = {
	{ OPT_DATA_LOSS_PROTECT,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT } },
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
			  [BOLT11_FEATURE] = FEATURE_REPRESENT,
			  [BOLT12_INVOICE_FEATURE] = FEATURE_REPRESENT } },
	/* BOLT #9:
	 * | 18/19 | `option_support_large_channel` |... IN ...
	 */
	{ OPT_LARGE_CHANNELS,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT,
			  [CHANNEL_FEATURE] = FEATURE_DONT_REPRESENT } },
	{ OPT_ONION_MESSAGES,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT,
			  [BOLT11_FEATURE] = FEATURE_DONT_REPRESENT,
			  [CHANNEL_FEATURE] = FEATURE_DONT_REPRESENT} },
	{ OPT_SHUTDOWN_WRONG_FUNDING,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT,
			  [CHANNEL_FEATURE] = FEATURE_DONT_REPRESENT} },
	{ OPT_ANCHORS_ZERO_FEE_HTLC_TX,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT,
			  [CHANNEL_FEATURE] = FEATURE_DONT_REPRESENT } },
	{ OPT_DUAL_FUND,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT,
			  [BOLT11_FEATURE] = FEATURE_DONT_REPRESENT,
			  [CHANNEL_FEATURE] = FEATURE_DONT_REPRESENT} },
	/* FIXME: Currently not explicitly signalled, but we do
	 * support it for zeroconf */
	{ OPT_SCID_ALIAS,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT,
			  [BOLT11_FEATURE] = FEATURE_DONT_REPRESENT,
			  [CHANNEL_FEATURE] = FEATURE_DONT_REPRESENT} },

	/* Zeroconf is always signalled in `init`, but we still
	 * negotiate on a per-channel basis when calling `fundchannel`
	 * with the `mindepth` parameter, and accept a channel with
	 * the `open_channel` hook and its return value for
	 * `mindepth`.
	 */
	{ OPT_ZEROCONF,
	  .copy_style = {
		          [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT,
			  [BOLT11_FEATURE] = FEATURE_DONT_REPRESENT,
			  [CHANNEL_FEATURE] = FEATURE_DONT_REPRESENT} },
	{ OPT_ROUTE_BLINDING,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT,
			  [BOLT11_FEATURE] = FEATURE_REPRESENT,
			  [CHANNEL_FEATURE] = FEATURE_DONT_REPRESENT } },
	{ OPT_SHUTDOWN_ANYSEGWIT,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT,
			  [CHANNEL_FEATURE] = FEATURE_DONT_REPRESENT } },
	{ OPT_QUIESCE,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT,
			  [CHANNEL_FEATURE] = FEATURE_DONT_REPRESENT } },
	{ OPT_PAYMENT_METADATA,
	  .copy_style = { [INIT_FEATURE] = FEATURE_DONT_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_DONT_REPRESENT,
			  /* Note: we don't actually set this in invoices, since
			   * we don't need to use it, but if we don't set it here
			   * we refuse to parse it. */
			  [BOLT11_FEATURE] = FEATURE_REPRESENT,
			  [CHANNEL_FEATURE] = FEATURE_DONT_REPRESENT } },
	{ OPT_CHANNEL_TYPE,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT,
			  [BOLT11_FEATURE] = FEATURE_DONT_REPRESENT,
			  [CHANNEL_FEATURE] = FEATURE_DONT_REPRESENT } },
	{ OPT_WANT_PEER_BACKUP_STORAGE,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT } },
	{ OPT_PROVIDE_PEER_BACKUP_STORAGE,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT } },
	{ OPT_SPLICE,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT,
			  [CHANNEL_FEATURE] = FEATURE_DONT_REPRESENT} },
	{ OPT_EXPERIMENTAL_SPLICE,
	  .copy_style = { [INIT_FEATURE] = FEATURE_REPRESENT,
			  [NODE_ANNOUNCE_FEATURE] = FEATURE_REPRESENT,
			  [CHANNEL_FEATURE] = FEATURE_DONT_REPRESENT} },
};

struct dependency {
	size_t depender;
	size_t must_also_have;
};

static const struct dependency feature_deps[] = {
	/* BOLT #9:
	 * Name                | Description  | Context  | Dependencies  |
	 *...
	 * `basic_mpp`         | ...          | ...      | `payment_secret` |
	 */
	{ OPT_BASIC_MPP, OPT_PAYMENT_SECRET },
};

static void trim_features(u8 **features)
{
	size_t trim, len = tal_bytelen(*features);

	/* Don't try to tal_resize a NULL array */
	if (len == 0)
		return;

	/* Big-endian bitfields are weird, but it means we trim
	 * from the front: */
	for (trim = 0; trim < len && (*features)[trim] == 0; trim++);
	memmove(*features, *features + trim, len - trim);
	tal_resize(features, len - trim);
}

static void clear_feature_bit(u8 *features, u32 bit)
{
	size_t bytenum = bit / 8, bitnum = bit % 8, len = tal_count(features);

	if (bytenum >= len)
		return;

	features[len - 1 - bytenum] &= ~(1 << bitnum);
}

static enum feature_copy_style feature_copy_style(u32 f, enum feature_place p)
{
	for (size_t i = 0; i < ARRAY_SIZE(feature_styles); i++) {
		if (feature_styles[i].bit == COMPULSORY_FEATURE(f))
			return feature_styles[i].copy_style[p];
	}
	abort();
}

struct feature_set *feature_set_for_feature(const tal_t *ctx, int feature)
{
	struct feature_set *fs = tal(ctx, struct feature_set);

	for (size_t i = 0; i < ARRAY_SIZE(fs->bits); i++) {
		fs->bits[i] = tal_arr(fs, u8, 0);
		switch (feature_copy_style(feature, i)) {
		case FEATURE_DONT_REPRESENT:
			continue;
		case FEATURE_REPRESENT:
			set_feature_bit(&fs->bits[i], feature);
			continue;
		case FEATURE_REPRESENT_AS_OPTIONAL:
			set_feature_bit(&fs->bits[i], OPTIONAL_FEATURE(feature));
			continue;
		}
		abort();
	}
	return fs;
}

bool feature_set_or(struct feature_set *a,
		    const struct feature_set *b TAKES)
{
	/* Check first, before we change anything! */
	for (size_t i = 0; i < ARRAY_SIZE(b->bits); i++) {
		/* FIXME: We could allow a plugin to upgrade an optional feature
		 * to a compulsory one? */
		for (size_t j = 0; j < tal_bytelen(b->bits[i])*8; j++) {
			if (feature_is_set(b->bits[i], j)
			    && feature_offered(a->bits[i], j)) {
				if (taken(b))
					tal_free(b);
				return false;
			}
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(a->bits); i++) {
		for (size_t j = 0; j < tal_bytelen(b->bits[i])*8; j++) {
			if (feature_is_set(b->bits[i], j))
				set_feature_bit(&a->bits[i], j);
		}
	}

	if (taken(b))
		tal_free(b);
	return true;
}

bool feature_set_sub(struct feature_set *a,
		     const struct feature_set *b TAKES)
{
	/* Check first, before we change anything! */
	for (size_t i = 0; i < ARRAY_SIZE(b->bits); i++) {
		for (size_t j = 0; j < tal_bytelen(b->bits[i])*8; j++) {
			if (feature_is_set(b->bits[i], j)
			    && !feature_offered(a->bits[i], j)) {
				if (taken(b))
					tal_free(b);
				return false;
			}
		}
	}

	for (size_t i = 0; i < ARRAY_SIZE(a->bits); i++) {
		for (size_t j = 0; j < tal_bytelen(b->bits[i])*8; j++) {
			if (feature_is_set(b->bits[i], j))
				clear_feature_bit(a->bits[i], j);
		}
		trim_features(&a->bits[i]);
	}


	if (taken(b))
		tal_free(b);
	return true;
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

/* BOLT #7:
 *
 *   - MUST set `features` based on what features were negotiated for this channel, according to [BOLT #9](09-features.md#assigned-features-flags)
 *  - MUST set `len` to the minimum length required to hold the `features` bits
 *  it sets.
 */
u8 *get_agreed_channelfeatures(const tal_t *ctx,
			       const struct feature_set *our_features,
			       const u8 *their_features)
{
	u8 *f = tal_dup_talarr(ctx, u8, our_features->bits[CHANNEL_FEATURE]);
	size_t max_len = 0;

	/* Clear any features which they didn't offer too */
	for (size_t i = 0; i < 8 * tal_count(f); i += 2) {
		if (!feature_offered(f, i))
			continue;
		if (!feature_offered(their_features, i)) {
			clear_feature_bit(f, COMPULSORY_FEATURE(i));
			clear_feature_bit(f, OPTIONAL_FEATURE(i));
			trim_features(&f);
			continue;
		}
		max_len = (i / 8) + 1;
	}

	/* Trim to length (unless it's already NULL). */
	if (f)
		tal_resize(&f, max_len);
	return f;
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

bool feature_negotiated(const struct feature_set *our_features,
			const u8 *their_features, size_t f)
{
	return feature_offered(their_features, f)
		&& feature_offered(our_features->bits[INIT_FEATURE], f);
}

bool feature_check_depends(const u8 *their_features,
			   size_t *depender, size_t *missing_dependency)
{
	for (size_t i = 0; i < ARRAY_SIZE(feature_deps); i++) {
		if (!feature_offered(their_features, feature_deps[i].depender))
			continue;
		if (feature_offered(their_features,
				    feature_deps[i].must_also_have))
			continue;
		*depender = feature_deps[i].depender;
		*missing_dependency = feature_deps[i].must_also_have;
		return false;
	}
	return true;
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
static int all_supported_features(const struct feature_set *our_features,
				  const u8 *bitmap,
				  enum feature_place p)
{
	size_t len = tal_count(bitmap) * 8;

	/* It's OK to be odd: only check even bits. */
	for (size_t bitnum = 0; bitnum < len; bitnum += 2) {
		if (!test_bit(bitmap, bitnum/8, bitnum%8))
			continue;

		if (feature_offered(our_features->bits[p], bitnum))
			continue;

		return bitnum;
	}
	return -1;
}

int features_unsupported(const struct feature_set *our_features,
			 const u8 *their_features,
			 enum feature_place p)
{
	return all_supported_features(our_features, their_features, p);
}

const char *feature_name(const tal_t *ctx, size_t f)
{
	static const char *fnames[] = {
		"option_data_loss_protect", 	/* 0/1 */
		"option_initial_routing_sync",
		"option_upfront_shutdown_script",
		"option_gossip_queries",
		"option_var_onion_optin",
		"option_gossip_queries_ex", 	/* 10/11 */
		"option_static_remotekey",
		"option_payment_secret",
		"option_basic_mpp",
		"option_support_large_channel",
		"option_anchor_outputs", 	/* 20/21 */
		"option_anchors",
		"option_route_blinding", /* https://github.com/lightning/bolts/pull/765 */
		"option_shutdown_anysegwit",
		"option_dual_fund",
		"option_amp", /* 30/31 */ /* https://github.com/lightning/bolts/pull/658 */
		NULL,
		"option_quiesce", /* https://github.com/lightning/bolts/pull/869 */
		NULL,
		"option_onion_messages",  /* https://github.com/lightning/bolts/pull/759 */
		"option_want_peer_backup_storage", /* 40/41 */ /* https://github.com/lightning/bolts/pull/881/files */
		"option_provide_peer_backup_storage", /* https://github.com/lightning/bolts/pull/881/files */
		"option_channel_type",
		"option_scid_alias", /* https://github.com/lightning/bolts/pull/910 */
		"option_payment_metadata",
		"option_zeroconf", /* 50/51, https://github.com/lightning/bolts/pull/910 */
		NULL,
		"option_keysend",
		"option_trampoline_routing", /* https://github.com/lightning/bolts/pull/836 */
		NULL,
		NULL, /* 60/61 */
		"option_splice",
		NULL,
		NULL,
		NULL,
		NULL, /* 70/71 */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 80/81 */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 90/91 */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 100/101 */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 110/111 */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 120/121 */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 130/131 */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 140/141 */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 150/151 */
		NULL,
		NULL,
		NULL,
		NULL,
		NULL, /* 160/161 */
		"option_experimental_splice", /* https://github.com/lightning/bolts/pull/863 */
		NULL,
		NULL,
		NULL,
		NULL, /* 170/171 */
	};

	if (f / 2 >= ARRAY_SIZE(fnames) || !fnames[f / 2])
		return tal_fmt(ctx, "option_unknown_%zu/%s",
			       COMPULSORY_FEATURE(f), (f & 1) ? "odd" : "even");

	return tal_fmt(ctx, "%s/%s",
		       fnames[f / 2], (f & 1) ? "odd" : "even");
}

const char **list_supported_features(const tal_t *ctx,
				     const struct feature_set *fset)
{
	const char **list = tal_arr(ctx, const char *, 0);

	for (size_t i = 0; i < tal_bytelen(fset->bits[INIT_FEATURE]) * 8; i++) {
		if (test_bit(fset->bits[INIT_FEATURE], i / 8, i % 8))
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

void featurebits_unset(u8 **ptr, size_t bit)
{
	size_t len = tal_count(*ptr);
	if (bit / 8 >= len)
		return;

	(*ptr)[len - 1 - bit / 8] &= (0 << (bit % 8));

	trim_features(ptr);
}

bool featurebits_eq(const u8 *f1, const u8 *f2)
{
	size_t len = tal_bytelen(f1);

	if (tal_bytelen(f2) > len)
		len = tal_bytelen(f2);

	for (size_t i = 0; i < len * 8; i++) {
		if (feature_is_set(f1, i) != feature_is_set(f2, i))
			return false;
	}
	return true;
}

struct feature_set *fromwire_feature_set(const tal_t *ctx,
					 const u8 **cursor, size_t *max)
{
	struct feature_set *fset = tal(ctx, struct feature_set);

	for (size_t i = 0; i < ARRAY_SIZE(fset->bits); i++)
		fset->bits[i] = fromwire_tal_arrn(fset, cursor, max,
						  fromwire_u16(cursor, max));

	if (!*cursor)
		return tal_free(fset);
	return fset;
}

void towire_feature_set(u8 **pptr, const struct feature_set *fset)
{
	for (size_t i = 0; i < ARRAY_SIZE(fset->bits); i++) {
		towire_u16(pptr, tal_bytelen(fset->bits[i]));
		towire_u8_array(pptr, fset->bits[i], tal_bytelen(fset->bits[i]));
	}
}

const char *fmt_featurebits(const tal_t *ctx, const u8 *featurebits)
{
	size_t size = tal_count(featurebits);
	char *fmt = tal_strdup(ctx, "");
	const char *prefix = "";

	for (size_t i = 0; i < size * 8; i++) {
		if (feature_is_set(featurebits, i)) {
			tal_append_fmt(&fmt, "%s%zu", prefix, i);
			prefix = ",";
		}
	}
	return fmt;
}

struct feature_set *feature_set_dup(const tal_t *ctx,
				    const struct feature_set *other)
{
	struct feature_set *res = tal(ctx, struct feature_set);

	for (size_t i = 0; i < ARRAY_SIZE(res->bits); i++)
		res->bits[i] = tal_dup_talarr(res, u8, other->bits[i]);

	return res;
}
