#include "version.h"
#include "gen_version.h"
#include <stdio.h>

char *version_and_exit(const void *unused)
{
	printf("%s\n"
	       "aka. %s\n"
	       "Built with: %s\n", VERSION, VERSION_NAME, BUILD_FEATURES);
	exit(0);
}
