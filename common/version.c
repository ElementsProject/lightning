#include "version.h"
#include <stdio.h>

/* Only common/version.c can safely include this.  */
# include "gen_version.h"

const char *version(void)
{
	return VERSION;
}

char *version_and_exit(const void *unused UNUSED)
{
	printf("%s\n", VERSION);
	if (BUILD_FEATURES[0]) {
		printf("Built with features: %s\n", BUILD_FEATURES);
	}
	exit(0);
}
