#ifndef LIGHTNING_LIGHTNINGD_WATCHMAN_H
#define LIGHTNING_LIGHTNINGD_WATCHMAN_H

#include "config.h"

struct lightningd;
struct watchman;

/**
 * watchman_new - Create and initialize a new watchman instance
 * @ctx: tal context to allocate from
 * @ld: lightningd instance
 *
 * Returns a new watchman instance, loading pending operations from datastore.
 */
struct watchman *watchman_new(const tal_t *ctx, struct lightningd *ld);

#endif /* LIGHTNING_LIGHTNINGD_WATCHMAN_H */
