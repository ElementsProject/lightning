/* This represents a channel type: i.e. the sticky feature bits. */
#ifndef LIGHTNING_COMMON_CHANNEL_TYPE_H
#define LIGHTNING_COMMON_CHANNEL_TYPE_H
#include "config.h"
#include <common/features.h>
#include <wire/channel_type_wiregen.h>

/* Explicit channel types */
struct channel_type *channel_type_none(const tal_t *ctx);
struct channel_type *channel_type_static_remotekey(const tal_t *ctx);
struct channel_type *channel_type_anchor_outputs(const tal_t *ctx);

/* Duplicate a channel_type */
struct channel_type *channel_type_dup(const tal_t *ctx,
				      const struct channel_type *t);

/* Convert feature bits to channel_type */
struct channel_type *channel_type_from(const tal_t *ctx,
				       const u8 *features TAKES);

/* Derive channel type from feature negotiation */
struct channel_type *default_channel_type(const tal_t *ctx,
					  const struct feature_set *our_features,
					  const u8 *their_features);

/* Does this type include this feature? */
bool channel_type_has(const struct channel_type *type, int feature);

/* Are these two channel_types equivalent? */
bool channel_type_eq(const struct channel_type *a,
		     const struct channel_type *b);

/* Return channel_type if this is acceptable, otherwise NULL */
struct channel_type *channel_type_accept(const tal_t *ctx,
					 const u8 *t,
					 const struct feature_set *our_features,
					 const u8 *their_features);
#endif /* LIGHTNING_COMMON_CHANNEL_TYPE_H */
