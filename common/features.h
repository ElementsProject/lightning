#ifndef LIGHTNING_COMMON_FEATURES_H
#define LIGHTNING_COMMON_FEATURES_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/* Returns true if we're OK with all these offered features. */
bool features_supported(const u8 *globalfeatures, const u8 *localfeatures);

/* For sending our features: tal_count() returns length. */
u8 *get_offered_globalfeatures(const tal_t *ctx);
u8 *get_offered_localfeatures(const tal_t *ctx);

/* Is this feature bit requested? (Either compulsory or optional) */
bool feature_offered(const u8 *features, size_t f);

/* Was this feature bit offered by them and us? */
bool local_feature_negotiated(const u8 *lfeatures, size_t f);
bool global_feature_negotiated(const u8 *gfeatures, size_t f);

#define COMPULSORY_FEATURE(x)	(x)
#define OPTIONAL_FEATURE(x)	((x)+1)

/* BOLT #9:
 *
 * ## Assigned `localfeatures` flags
 *...
 * | Bits | Name                             |...
 * | 0/1  | `option_data_loss_protect`       |...
 * | 3    | `initial_routing_sync`           |...
 * | 4/5  | `option_upfront_shutdown_script` |...
 * | 6/7  | `gossip_queries`                 |...
 */
#define LOCAL_DATA_LOSS_PROTECT			0
#define LOCAL_INITIAL_ROUTING_SYNC		2
#define LOCAL_UPFRONT_SHUTDOWN_SCRIPT		4
#define LOCAL_GOSSIP_QUERIES			6

#endif /* LIGHTNING_COMMON_FEATURES_H */
