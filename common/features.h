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

/* The complete set of features for all contexts */
struct feature_set {
	u8 *bits[NUM_FEATURE_PLACE];
};

/* Initialize core features (for lightningd). */
struct feature_set *features_core_init(const u8 *features TAKES);

/* Initialize subdaemon features. */
void features_init(struct feature_set *fset TAKES);

/* Free feature allocations */
void features_cleanup(void);

struct feature_set *fromwire_feature_set(const tal_t *ctx,
					 const u8 **ptr, size_t *max);
void towire_feature_set(u8 **pptr, const struct feature_set *fset);

/* Returns -1 if we're OK with all these offered features, otherwise first
 * unsupported (even) feature. */
int features_unsupported(const u8 *features);

/* For sending our features: tal_count() returns length. */
u8 *get_offered_initfeatures(const tal_t *ctx);
u8 *get_offered_globalinitfeatures(const tal_t *ctx);
u8 *get_offered_nodefeatures(const tal_t *ctx);
u8 *get_offered_bolt11features(const tal_t *ctx);

/* For the features in channel_announcement */
u8 *get_agreed_channelfeatures(const tal_t *ctx, const u8 *theirfeatures);

/* Is this feature bit requested? (Either compulsory or optional) */
bool feature_offered(const u8 *features, size_t f);

/* Was this feature bit offered by them and us? */
bool feature_negotiated(const u8 *lfeatures, size_t f);

/* Return a list of what features we advertize. */
const char **list_supported_features(const tal_t *ctx);

/* Low-level helpers to deal with big-endian bitfields. */
bool feature_is_set(const u8 *features, size_t bit);
void set_feature_bit(u8 **ptr, u32 bit);

/* Given two featurebit vectors, combine them by applying a logical OR. */
u8 *featurebits_or(const tal_t *ctx, const u8 *f1 TAKES, const u8 *f2 TAKES);

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
 */
#define OPT_PAYMENT_SECRET			14
#define OPT_BASIC_MPP				16

#endif /* LIGHTNING_COMMON_FEATURES_H */
