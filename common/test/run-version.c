#include "config.h"
#include "../version.c"
#include <common/setup.h>
#include <assert.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	common_setup(argv[0]);

	assert(cmp_release_version("v22.11"));
	assert(cmp_release_version("v22.11.1"));
	assert(cmp_release_version("v22.11.1-6-gdf29990-modded") == false);

	common_shutdown();
}
