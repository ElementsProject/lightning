#include "config.h"
#include <ccan/array_size/array_size.h>
#include <common/channel_type.h>

/* BOLT #2:
 * Channel types are an explicit enumeration: for convenience of future
 * definitions they reuse even feature bits, but they are not an
 * arbitrary combination (they represent the persistent features which
 * affect the channel operation).
 *
 * The currently defined basic types are:
 *   - no features (no bits set)
 *   - `option_static_remotekey` (bit 12)
 *   - `option_anchor_outputs` and `option_static_remotekey` (bits 20 and 12)
 *   - `option_anchors_zero_fee_htlc_tx` and `option_static_remotekey` (bits 22
 *      and 12)
 */
struct channel_type *channel_type_none(const tal_t *ctx)
{
	struct channel_type *type = tal(ctx, struct channel_type);

	type->features = tal_arr(type, u8, 0);
	return type;
}

struct channel_type *channel_type_static_remotekey(const tal_t *ctx)
{
	struct channel_type *type = channel_type_none(ctx);

	set_feature_bit(&type->features,
			COMPULSORY_FEATURE(OPT_STATIC_REMOTEKEY));
 	return type;
}

struct channel_type *channel_type_anchor_outputs(const tal_t *ctx)
{
	struct channel_type *type = channel_type_none(ctx);

	set_feature_bit(&type->features,
			COMPULSORY_FEATURE(OPT_ANCHOR_OUTPUTS));
	set_feature_bit(&type->features,
			COMPULSORY_FEATURE(OPT_STATIC_REMOTEKEY));
	return type;
}

void channel_type_set_zeroconf(struct channel_type *type)
{
	set_feature_bit(&type->features,
			COMPULSORY_FEATURE(OPT_ZEROCONF));
}

void channel_type_set_scid_alias(struct channel_type *type)
{
	set_feature_bit(&type->features,
			COMPULSORY_FEATURE(OPT_SCID_ALIAS));
}

struct channel_type *channel_type_anchors_zero_fee_htlc(const tal_t *ctx)
{
	struct channel_type *type = channel_type_none(ctx);

	set_feature_bit(&type->features,
			COMPULSORY_FEATURE(OPT_ANCHORS_ZERO_FEE_HTLC_TX));
	set_feature_bit(&type->features,
			COMPULSORY_FEATURE(OPT_STATIC_REMOTEKEY));
	return type;
}

struct channel_type *default_channel_type(const tal_t *ctx,
					  const struct feature_set *our_features,
					  const u8 *their_features)
{
	/* BOLT #2:
	 * Both peers:
	 *   - if `channel_type` was present in both `open_channel` and `accept_channel`:
	 *     - This is the `channel_type` (they must be equal, required above)
	 *   - otherwise:
	 *     - if `option_anchors_zero_fee_htlc_tx` was negotiated:
	 *       - the `channel_type` is `option_anchors_zero_fee_htlc_tx` and `option_static_remotekey` (bits 22 and 12)
	 *   - otherwise, if `option_anchor_outputs` was negotiated:
	 *     - the `channel_type` is `option_anchor_outputs` and
	 *       `option_static_remotekey` (bits 20 and 12)
	 */
	if (feature_negotiated(our_features, their_features,
			       OPT_ANCHORS_ZERO_FEE_HTLC_TX))
		return channel_type_anchors_zero_fee_htlc(ctx);
	if (feature_negotiated(our_features, their_features,
			       OPT_ANCHOR_OUTPUTS))
		return channel_type_anchor_outputs(ctx);
	else if (feature_negotiated(our_features, their_features,
				    OPT_DUAL_FUND))
		/* OPT_DUAL_FUND implies static remotekey */
		return channel_type_static_remotekey(ctx);
	/* BOLT #2:
	 * - otherwise, if `option_static_remotekey` was negotiated:
	 *   - the `channel_type` is `option_static_remotekey` (bit 12)
	 */
	else if (feature_negotiated(our_features, their_features,
				    OPT_STATIC_REMOTEKEY))
		return channel_type_static_remotekey(ctx);
	/* BOLT #2:
	 *     - otherwise:
	 *       - the `channel_type` is empty
	 */
	else
		return channel_type_none(ctx);
}

bool channel_type_has(const struct channel_type *type, int feature)
{
	return feature_offered(type->features, feature);
}

bool channel_type_has_anchors(const struct channel_type *type)
{
	return feature_offered(type->features, OPT_ANCHOR_OUTPUTS)
		|| feature_offered(type->features, OPT_ANCHORS_ZERO_FEE_HTLC_TX);
}

bool channel_type_eq(const struct channel_type *a,
		     const struct channel_type *b)
{
	return featurebits_eq(a->features, b->features);
}

struct channel_type *channel_type_dup(const tal_t *ctx,
				      const struct channel_type *t)
{
	struct channel_type *ret = tal(ctx, struct channel_type);
	ret->features = tal_dup_talarr(ret, u8, t->features);
	return ret;
}

struct channel_type *channel_type_from(const tal_t *ctx,
				       const u8 *features TAKES)
{
	struct channel_type *ret = tal(ctx, struct channel_type);
	ret->features = tal_dup_talarr(ret, u8, features);
	return ret;
}

struct channel_type *channel_type_accept(const tal_t *ctx,
					 const u8 *t,
					 const struct feature_set *our_features)
{
	struct channel_type *ctype, proposed;
	/* Need to copy since we're going to blank variant bits for equality. */
	proposed.features = tal_dup_talarr(tmpctx, u8, t);

	static const size_t feats[] = {
		OPT_ANCHOR_OUTPUTS,
		OPT_ANCHORS_ZERO_FEE_HTLC_TX,
		OPT_STATIC_REMOTEKEY,
		OPT_SCID_ALIAS,
		OPT_ZEROCONF,
	};

	/* BOLT #2:
	 * Each basic type has the following variations allowed:
	 *   - `option_scid_alias` (bit 46)
	 *   - `option_zeroconf` (bit 50)
	 */
	static const size_t variants[] = {
		OPT_SCID_ALIAS,
		OPT_ZEROCONF,
	};

	for (size_t i = 0; i < ARRAY_SIZE(feats); i++) {
		size_t f = feats[i];

		if (feature_offered(t, f)) {
			/* If we don't offer a feature, we don't allow it. */
			if (!feature_offered(our_features->bits[INIT_FEATURE], f))
				return NULL;
		} else {
			/* We assume that if we *require* a feature, we require
			 * channels have that. */
			if (feature_is_set(our_features->bits[INIT_FEATURE],
					   COMPULSORY_FEATURE(f)))
				return NULL;
		}
	}

	/* Blank variants so we can just check for equality. */
	for (size_t i = 0; i< ARRAY_SIZE(variants); i++)
		featurebits_unset(&proposed.features, variants[i]);

	/* Otherwise, just needs to be a known channel type. */
	if (channel_type_eq(&proposed, channel_type_none(tmpctx)) ||
	    channel_type_eq(&proposed,
			    channel_type_static_remotekey(tmpctx)) ||
	    channel_type_eq(&proposed,
			    channel_type_anchors_zero_fee_htlc(tmpctx)) ||
	    channel_type_eq(&proposed, channel_type_anchor_outputs(tmpctx))) {
		/* At this point we know it matches, and maybe has
		 * a couple of extra options. So let's just reply
		 * with their proposal. */
		ctype = tal(ctx, struct channel_type);
		ctype->features = tal_dup_talarr(ctx, u8, t);
		return ctype;
	}

	return NULL;
}

/* Return an array of feature strings indicating channel type. */
const char **channel_type_name(const tal_t *ctx, const struct channel_type *t)
{
	const char **names = tal_arr(ctx, const char *, 0);

	for (size_t i = 0; i < tal_bytelen(t->features) * CHAR_BIT; i++) {
		if (!feature_is_set(t->features, i))
			continue;
		tal_arr_expand(&names,
			       feature_name(names, i) + strlen("option_"));
	}
	return names;
}
