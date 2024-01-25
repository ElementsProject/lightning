#include "config.h"
#include <assert.h>
#include <ccan/str/str.h>
#include <ccan/tal/tal.h>
#include <common/deprecation.h>
#include <stdlib.h>

#define MONTH_VAL (10)
#define YEAR_VAL (12 * MONTH_VAL)

/* Returns 1 + patchnumber + 10*minor + 120*major.  0 on malformed */
u32 version_to_number(const char *version)
{
	char *yend, *mend;
	long year, month, patchlevel;

	if (version[0] != 'v')
		return 0;

	year = strtol(version + 1, &yend, 10);
	if (yend == version + 1 || *yend != '.')
		return 0;
	if (year > 99)
		return 0;

	month = strtol(yend + 1, &mend, 10);
	if (mend == yend + 1)
		return 0;

	if (month < 1 || month > 12)
		return 0;

	if (*mend == '.') {
		char *endp;
		patchlevel = strtol(mend + 1, &endp, 10);
		if (endp == mend + 1)
			return 0;
		if (patchlevel >= MONTH_VAL)
			return 0;
	} else
		patchlevel = 0;

	return 1 + year*YEAR_VAL + month*MONTH_VAL + patchlevel;
}

enum deprecation_level {
	/* Will be deprecated in future */
	DEPRECATED_SOON,
	/* Deprecated, but still ok unless explicitly disabled */
	DEPRECATED,
	/* Deprecated, and we whine about it */
	DEPRECATED_COMPLAIN,
	/* Deprecated, and we only enable it if they begged */
	DEPRECATED_BEG,
};

static enum deprecation_level deprecation(const char *start,
					  const char *end)
{
	long cur;
	long startnum;
	long endnum;

	/* Versions are hard.  Consider these:
	 * v23.05
	 *  -- A released version
	 * v23.05rc1
	 *  -- A release candidate
	 * v23.05rc4-11-g1e96146
	 *  -- Development off rc4, OR a user's local mods.
	 * v23.05-1-gf165dc0-modded
	 *  -- Development off 23.05, OR a user's local mods.
	 */

	/* If master has moved since release, we want to increment
	 * deprecations.  If a user has made local mods, we don't!
	 * Fortunately, the Makefile sets "CLN_NEXT_VERSION", and
	 * we can simply use this.
	 */
	cur = version_to_number(CLN_NEXT_VERSION);
	assert(cur);
	startnum = version_to_number(start);
	assert(startnum);
	if (end) {
		endnum = version_to_number(end);
		assert(endnum);
		assert(endnum >= startnum);
	} else /* 6 months later */
		endnum = startnum + 6 * MONTH_VAL;

	if (cur < startnum)
		return DEPRECATED_SOON;
	if (cur < endnum)
		return DEPRECATED;
	if (cur == endnum)
		return DEPRECATED_COMPLAIN;
	return DEPRECATED_BEG;
}

bool deprecated_ok_(bool deprecated_apis,
		    const char *feature,
		    const char *start,
		    const char *end,
		    const char **begs,
		    void (*complain)(const char *feature, bool allowing, void *cbarg),
		    void *cbarg)
{
	enum deprecation_level level;
	bool allow;

	/* Not deprecated at all? */
	if (!start)
		return true;

	level = deprecation(start, end);
	switch (level) {
	case DEPRECATED_SOON:
		return false;
	case DEPRECATED:
		/* Complain if we're disallowing becuase it's deprecated */
		allow = deprecated_apis;
		if (!allow)
			goto complain;
		goto no_complain;
	case DEPRECATED_COMPLAIN:
		allow = deprecated_apis;
		/* Always complain about these! */
		goto complain;
	case DEPRECATED_BEG:
		allow = false;
		for (size_t i = 0; i < tal_count(begs); i++) {
			if (streq(feature, begs[i]))
				allow = true;
		}
		/* Don't complain about begging: they've explicitly noted this! */
		if (allow)
			goto no_complain;
		goto complain;
	}
	abort();

complain:
	if (complain)
		complain(feature, allow, cbarg);
no_complain:
	return allow;
}
