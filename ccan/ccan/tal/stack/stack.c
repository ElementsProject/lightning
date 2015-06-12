/* Licensed under BSD-MIT - see LICENSE file for details */

#include <ccan/tal/stack/stack.h>
#include <assert.h>

static tal_t *h = NULL;

static void _free_frame(tal_t *o)
{
	h = tal_parent(o);
}

tal_t *tal_newframe_(const char *label)
{
	h = tal_alloc_(h, 0, false, label);
	assert(h != NULL);
	tal_add_destructor(h, _free_frame);
	return h;
}

tal_t *tal_curframe(void)
{
	return h;
}
