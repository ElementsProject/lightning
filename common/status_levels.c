#include "config.h"
#include <ccan/array_size/array_size.h>
#include <common/status_levels.h>

static const char *ll_names[] = {
	"io",
	"io",
	"debug",
	"info",
	"unusual",
	"broken",
};

const char *log_level_name(enum log_level level)
{
	BUILD_ASSERT(ARRAY_SIZE(ll_names) == LOG_LEVEL_MAX+1);
	if ((int)level <= LOG_LEVEL_MAX)
		return ll_names[level];
	return "***unknown***";
}

static bool streq_case(const char *str, const char *s, size_t len)
{
	if (len != strlen(str))
		return false;
	return strncasecmp(str, s, len) == 0;
}

bool log_level_parse(const char *levelstr, size_t len,
		     enum log_level *level)
{
	for (size_t i = 0; i < ARRAY_SIZE(ll_names); i++) {
		if (streq_case(ll_names[i], levelstr, len)) {
			*level = i;
			return true;
		}
	}
	/* We also allow "error" and "warn" */
	if (streq_case("error", levelstr, len)) {
		*level = LOG_BROKEN;
		return true;
	}
	if (streq_case("warn", levelstr, len)) {
		*level = LOG_UNUSUAL;
		return true;
	}

	return false;
}
