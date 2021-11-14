#include "config.h"
#include <assert.h>
#include <ccan/strmap/strmap.h>
#include <common/autodata.h>

struct typereg {
	size_t num;
	const void **ptrs;
};

static STRMAP(struct typereg *) typemap;

void autodata_register_(const char *typename, const void *ptr)
{
	struct typereg *t;
	assert(ptr);

	t = strmap_get(&typemap, typename);
	if (!t) {
		t = malloc(sizeof(struct typereg));
		t->num = 0;
		t->ptrs = NULL;
		strmap_add(&typemap, typename, t);
	}

	t->ptrs = realloc(t->ptrs, (t->num + 1) * sizeof(*t->ptrs));
	t->ptrs[t->num] = ptr;
	t->num++;
}

void *autodata_get_(const char *typename, size_t *nump)
{
	struct typereg *t = strmap_get(&typemap, typename);
	if (!t) {
		*nump = 0;
		return NULL;
	}
	*nump = t->num;
	return t->ptrs;
}

static bool free_one(const char *member,
		     struct typereg *t, void *unused)
{
	free(t->ptrs);
	free(t);
	return true;
}

void autodata_cleanup(void)
{
	strmap_iterate(&typemap, free_one, NULL);
	strmap_clear(&typemap);
}
