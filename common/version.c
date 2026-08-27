#include "config.h"
#include <common/configvar.h>
#include <common/version.h>
#include <stdio.h>

/* Only common/version.c can safely include this.  */
# include "version_gen.h"

const char *version(void)
{
	return VERSION;
}

static char *version_and_exit(const void *unused UNUSED)
{
	printf("%s\n", VERSION);
	if (BUILD_FEATURES[0]) {
		printf("Built with features: %s\n", BUILD_FEATURES);
	}
	exit(0);
}

void opt_register_version(void)
{
	clnopt_noarg("--version|-V", OPT_EARLY|OPT_EXITS,
		     version_and_exit, NULL,
		     "Print version and exit");
}

static bool cmp_release_version(const char *version)
{
	if (version[0] != 'v')
		return false;
	/* FIXME:
	 * Using version+1 here gets false positive on gcc-13 -O3 if VERSION is "":
	 * In function ‘cmp_release_version.constprop’:
	 * cc1: error: offset ‘1’ outside bounds of constant string [-Werror=array-bounds=]
	 */
	return strspn(version, "v.0123456789") == strlen(version);
}

/* Released versions are of form v[year].[month]?(.patch)* */
bool is_released_version(void)
{
	return cmp_release_version(version());
}
