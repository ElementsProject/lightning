#ifndef LIGHTNING_COMMON_FEATURES_H
#define LIGHTNING_COMMON_FEATURES_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/* Returns -1 if we're OK with all these offered features, otherwise first
 * unsupported (even) feature. */
int features_unsupported(const u8 *features);

/* For sending our features: tal_count() returns length. */
u8 *get_offered_initfeatures(const tal_t *ctx);
u8 *get_offered_globalinitfeatures(const tal_t *ctx);
u8 *get_offered_nodefeatures(const tal_t *ctx);
u8 *get_offered_bolt11features(const tal_t *ctx);

/* Is this feature bit requested? (Either compulsory or optional) */
bool feature_offered(const u8 *features, size_t f);

/* Was this feature bit offered by them and us? */
bool feature_negotiated(const u8 *lfeatures, size_t f);

/* Return a list of what features we advertize. */
const char **list_supported_features(const tal_t *ctx);

/* Low-level helpers to deal with big-endian bitfields. */
bool feature_is_set(const u8 *features, size_t bit);
void set_feature_bit(u8 **ptr, u32 bit);

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
