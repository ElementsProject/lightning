#include <ccan/bitops/bitops.h>
#include <ccan/intmap/intmap.c>
#include <ccan/tap/tap.h>
#include <stdio.h>

#define ELEMENTS 8

int main(void)
{
	UINTMAP(void *) umap;

	plan_tests((1 << ELEMENTS) * ELEMENTS);

	/* Run through every combination of elements */
	for (int i = 0; i < (1 << ELEMENTS); i++) {
		/* Set up map */
		uintmap_init(&umap);
		for (int j = 0; j < ELEMENTS; j++) {
			if ((1 << j) & i)
				uintmap_add(&umap, j, &umap);
		}

		/* Try each uintmap_after value */
		for (int j = 0; j < ELEMENTS; j++) {
			intmap_index_t idx = j, next;

			if ((i >> (j + 1)) == 0)
				next = 0;
			else
				next = j + 1 + bitops_ls32(i >> (j + 1));

			if (!uintmap_after(&umap, &idx))
				idx = 0;
			ok1(idx == next);
		}
		uintmap_clear(&umap);
	}

	/* This exits depending on whether all tests passed */
	return exit_status();
}
