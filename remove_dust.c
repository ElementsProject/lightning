#include "remove_dust.h"
#include <assert.h>
#include <stdbool.h>
#include <string.h>

void remove_dust(struct bitcoin_tx *tx, int *map)
{
	size_t i, j, num = tx->output_count;

	assert(tal_count(map) == num);
	/* Do it in map order so we can remove from map, too */
	for (i = 0; i < num; i++) {
		assert(map[i] < tx->output_count);
		if (tx->output[map[i]].amount >= DUST_THRESHOLD)
			continue;

		/* Eliminate that output from tx */
		tx->output_count--;
		memmove(tx->output + map[i], tx->output + map[i] + 1,
			(tx->output_count-map[i]) * sizeof(*tx->output));

		/* Fixup map. */
		for (j = 0; j < num; j++)
			if (map[j] > map[i])
				map[j]--;
		map[i] = -1;
	}
}
