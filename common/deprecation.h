#ifndef LIGHTNING_COMMON_DEPRECATION_H
#define LIGHTNING_COMMON_DEPRECATION_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/typesafe_cb/typesafe_cb.h>

/**
 * deprecated_ok - should we allow a feature?
 * @deprecated_apis: are deprecated features blanket enabled?
 * @feature: user-visible name for feature
 * @start: (optoonal) first version to deprecate it in.
 * @end: (optional) final version to allow it in (default: 6 months after start).
 * @begs: (optional) tal_arr of strings features to allow after @end.
 * @complain: (optional) loggin callback if they use a deprecated feature.
 *
 * @feature is the name the user will see in the logs, and have to use to manually
 * re-enable it at the end of the deprecation period.
 * @start and @end are of form "v23.08".
 * @complain takes the @feature, and a flag to say if we're allowing it or not.
 */
#define deprecated_ok(deprecated_apis, feature, start, end, begs, complain, cbarg) \
	deprecated_ok_((deprecated_apis), (feature), (start), (end), (begs),	\
		    typesafe_cb_preargs(void, void *, (complain), (cbarg), \
					const char *, bool),		\
		    cbarg)

bool NON_NULL_ARGS(2) deprecated_ok_(bool deprecated_apis,
		    const char *feature,
		    const char *start,
		    const char *end,
		    const char **begs,
		    void (*complain)(const char *feat, bool allowing, void *),
		    void *cbarg);

/* Returns number corresponding to version, or 0 if it doesn't parse */
u32 version_to_number(const char *version);

#endif /* LIGHTNING_COMMON_DEPRECATION_H */
