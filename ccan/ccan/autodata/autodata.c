// Licensed under BSD-MIT: See LICENSE.
#include "autodata.h"
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#if HAVE_SECTION_START_STOP
void *autodata_get_section(void *start, void *stop, size_t *nump)
{
	*nump = (void **)(stop) - (void **)(start);
	return start;
}

void autodata_free(void *table UNNEEDED)
{
}
#else
#include <ccan/ptr_valid/ptr_valid.h>

void *autodata_make_table(const void *example, const char *name, size_t *nump)
{
	const char *start, *end, *tag;
	struct ptr_valid_batch batch;
	const void *const magic = (void *)AUTODATA_MAGIC;
	void **table = NULL;
	char first_magic;

	if (!ptr_valid_batch_start(&batch))
		return NULL;

	/* Get range to search. */
	for (start = (char *)((intptr_t)example & ~(getpagesize() - 1));
	     ptr_valid_batch(&batch, start-getpagesize(), 1, sizeof(void *),
			     false);
	     start -= getpagesize());

	for (end = (char *)((intptr_t)example & ~(getpagesize() - 1));
	     ptr_valid_batch(&batch, end, 1, sizeof(void *), false);
	     end += getpagesize());

	*nump = 0;
	first_magic = *(char *)&magic;
	for (tag = memchr(start, first_magic, end - start);
	     tag;
	     tag = memchr(tag+1, first_magic, end - (tag + 1))) {
		void *adata[4];

		/* We can read 4 void *'s here? */
		if (tag + sizeof(adata) > end)
			continue;

		memcpy(adata, tag, sizeof(adata));

		/* False match? */
		if (adata[0] != (void *)AUTODATA_MAGIC || adata[1] != tag)
			continue;

		/* OK, check name. */
		if (!ptr_valid_batch_string(&batch, adata[3])
		    || strcmp(name, adata[3]) != 0)
			continue;

		if (!ptr_valid_batch_read(&batch, (char *)adata[2]))
			continue;

		table = realloc(table, sizeof(void *) * (*nump + 1));
		if (!table)
			break;
		table[*nump] = adata[2];
		(*nump)++;
	}
	ptr_valid_batch_end(&batch);
	return table;
}

void autodata_free(void *table)
{
	free(table);
}
#endif
