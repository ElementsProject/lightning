#include "gen_version.h"
#include "version.h"
#include <stdio.h>

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
