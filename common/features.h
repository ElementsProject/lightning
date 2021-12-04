#ifndef LIGHTNING_COMMON_FEATURES_H
#define LIGHTNING_COMMON_FEATURES_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

enum feature_place {
	INIT_FEATURE,
	GLOBAL_INIT_FEATURE,
	NODE_ANNOUNCE_FEATURE,
	CHANNEL_FEATURE,
	BOLT11_FEATURE,
};
#define NUM_FEATURE_PLACE (BOLT11_FEATURE+1)

extern const char *feature_place_names[NUM_FEATURE_PLACE];

/* The complete set of features for all contexts */
struct feature_set {
	u8 *bits[NUM_FEATURE_PLACE];
};

/* Create feature set for a known feature. */
struct feature_set *feature_set_for_feature(const tal_t *ctx, int feature);

/* Marshalling a feature set */
struct feature_set *fromwire_feature_set(const tal_t *ctx,
					 const u8 **ptr, size_t *max);
void towire_feature_set(u8 **pptr, const struct feature_set *fset);

/* a |= b, or returns false if features already in a */
bool feature_set_or(struct feature_set *a,
		    const struct feature_set *b TAKES);

/* a - b, or returns false if features not already in a */
bool feature_set_sub(struct feature_set *a,
		     const struct feature_set *b TAKES);

/* Returns -1 if we're OK with all these offered features, otherwise first
 * unsupported (even) feature. */
int features_unsupported(const struct feature_set *our_features,
			 const u8 *their_features,
			 enum feature_place p);

/* For the features in channel_announcement */
u8 *get_agreed_channelfeatures(const tal_t *ctx,
			       const struct feature_set *our_features,
			       const u8 *theirfeatures);

/* Is this feature bit requested? (Either compulsory or optional) */
bool feature_offered(const u8 *features, size_t f);

/* Was this feature bit offered by them and us? */
bool feature_negotiated(const struct feature_set *our_features,
			const u8 *their_features, size_t f);

/* Features can depend on other features: both must be set!
 * Sets @depender, @missing_dependency if returns false.
 */
bool feature_check_depends(const u8 *their_features,
			   size_t *depender, size_t *missing_dependency);

/* Return a list of what (init) features we advertize. */
const char **list_supported_features(const tal_t *ctx,
				     const struct feature_set *fset);

/* Give a name for this feature */
const char *feature_name(const tal_t *ctx, size_t f);

/* Low-level helpers to deal with big-endian bitfields. */
bool feature_is_set(const u8 *features, size_t bit);
void set_feature_bit(u8 **ptr, u32 bit);

/* Given two featurebit vectors, combine them by applying a logical OR. */
u8 *featurebits_or(const tal_t *ctx, const u8 *f1 TAKES, const u8 *f2 TAKES);

/* Are these two feature bitsets functionally equal (one may have
 * trailing zeroes)? */
bool featurebits_eq(const u8 *f1, const u8 *f2);

/* Good for debugging: returns comma-separated string of bits. */
const char *fmt_featurebits(const tal_t *ctx, const u8 *featurebits);

/* BOLT #9:
 *
 * Flags are numbered from the least-significant bit, at bit 0 (i.e. 0x1,
 * an _even_ bit). They are generally assigned in pairs so that features
 * can be introduced as optional (_odd_ bits) and later upgraded to be compulsory
 * (_even_ bits), which will be refused by outdated nodes:
 * see [BOLT #1: The `init` Message](01-messaging.md#the-init-message).
 */
#define COMPULSORY_FEATURE(x)	((x) & 0xFFFFFFFE)
#define OPTIONAL_FEATURE(x)	((x) | 1)

/* BOLT #9:
 *
 * | Bits  | Name                             |...
 * | 0/1   | `option_data_loss_protect`       |...
 * | 3     | `initial_routing_sync`           |...
 * | 4/5   | `option_upfront_shutdown_script` |...
 * | 6/7   | `gossip_queries`                 |...
 * | 8/9   | `var_onion_optin`                |...
 * | 10/11 | `gossip_queries_ex`              |...
 * | 12/13 | `option_static_remotekey`        |...
 */
#define OPT_DATA_LOSS_PROTECT			0
#define OPT_INITIAL_ROUTING_SYNC		2
#define OPT_UPFRONT_SHUTDOWN_SCRIPT		4
#define OPT_GOSSIP_QUERIES			6
#define OPT_VAR_ONION				8
#define OPT_GOSSIP_QUERIES_EX			10
#define OPT_STATIC_REMOTEKEY			12

/* BOLT #9:
 *
 * | 14/15 | `payment_secret` |... IN9 ...
 * | 16/17 | `basic_mpp`      |... IN9 ...
 * | 18/19 | `option_support_large_channel` |... IN ...
 * | 20/21 | `option_anchor_outputs` |... IN ...
 * | 26/27 | `option_shutdown_anysegwit` |... IN ...
 */
#define OPT_PAYMENT_SECRET			14
#define OPT_BASIC_MPP				16
#define OPT_LARGE_CHANNELS			18
#define OPT_ANCHOR_OUTPUTS			20
#define OPT_SHUTDOWN_ANYSEGWIT			26

/* BOLT-f53ca2301232db780843e894f55d95d512f297f9 #9:
 * | 28/29 | `option_dual_fund` | ... IN9 ...
 */
#define OPT_DUAL_FUND 				28

/* BOLT-quiescent #9:
 * | 34/35 | `option_quiesce` | ... IN ...
 */
#define OPT_QUIESCE 				34

/* BOLT-offers #9:
 *
 * | 38/39 | `option_onion_messages` |... IN ...
 */
#define OPT_ONION_MESSAGES			38

#define OPT_SHUTDOWN_WRONG_FUNDING		104

#endif /* LIGHTNING_COMMON_FEATURES_H */
