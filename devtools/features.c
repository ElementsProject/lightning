/* Turns a hex string into feature. */
#include "config.h"
#include <ccan/err/err.h>
#include <common/features.h>
#include <common/utils.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	const u8 *features;

	setup_locale();

	if (argc != 2)
		errx(1, "Usage: %s <hexstring>", argv[0]);

	features = tal_hexdata(NULL, argv[1], strlen(argv[1]));
	if (!features)
		errx(1, "bad hexstring");

	for (size_t i = 0; i < tal_bytelen(features) * 8; i++) {
		if (feature_is_set(features, i))
			printf("%s (%s)\n",
			       feature_name(features, i),
			       i % 2 ? "optional" : "compulsory");
	}
	tal_free(features);
}
