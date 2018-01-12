#ifndef LIGHTNING_COMMON_FEATURES_H
#define LIGHTNING_COMMON_FEATURES_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

/* Returns true if these contain any unsupported features. */
bool unsupported_features(const u8 *gfeatures, const u8 *lfeatures);

/* For sending our features: tal_len() returns length. */
u8 *get_supported_global_features(const tal_t *ctx);
u8 *get_supported_local_features(const tal_t *ctx);

#endif /* LIGHTNING_COMMON_FEATURES_H */
