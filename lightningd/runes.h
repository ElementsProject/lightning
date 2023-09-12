#ifndef LIGHTNING_LIGHTNINGD_RUNES_H
#define LIGHTNING_LIGHTNINGD_RUNES_H
#include "config.h"

struct rune;

/* Initialize ld->runes enough for rune_is_ours(): needs HSM. */
struct runes *runes_early_init(struct lightningd *ld);

/* Finish it: needs db. */
void runes_finish_init(struct runes *runes);

/* Is this rune one of ours?  Needed for commando migration.
 * Returns NULL if it is, or a string explaining (usually, "Not derived from master").
 */
const char *rune_is_ours(struct lightningd *ld, const struct rune *rune);

/* Get unique id number of rune. */
u64 rune_unique_id(const struct rune *rune);

#endif /* LIGHTNING_LIGHTNINGD_RUNES_H */
