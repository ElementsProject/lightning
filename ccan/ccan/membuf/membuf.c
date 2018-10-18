/* MIT (BSD) license - see LICENSE file for details */
#include <ccan/membuf/membuf.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

void membuf_init_(struct membuf *mb,
		  void *elems, size_t num_elems, size_t elemsize,
		  void *(*expandfn)(struct membuf *, void *, size_t))
{

	mb->start = mb->end = 0;
	mb->max_elems = num_elems;
	mb->elems = elems;
	mb->expandfn = expandfn;
}

size_t membuf_prepare_space_(struct membuf *mb,
			     size_t num_extra, size_t elemsize)
{
	char *oldstart = membuf_elems_(mb, elemsize);

	/* Always reset in the trivial empty case. */
	if (mb->start == mb->end)
		mb->start = mb->end = 0;

	if (membuf_num_space_(mb) >= num_extra)
		return 0;

	/* There are two ways to make space: enlarge buffer, and memmove
	 * down.  We use a simple heuristic: if we are using less than half
	 * the buffer, and memmove would get us sufficient space, do that. */
	if (membuf_num_elems_(mb) <= mb->max_elems / 2
	    && membuf_num_elems_(mb) + num_extra <= mb->max_elems) {
		memmove(mb->elems, oldstart, (mb->end - mb->start) * elemsize);
		mb->end -= mb->start;
		mb->start = 0;
	} else {
		void *expand;

		/* Since we're going to expand, at least double. */
		if (num_extra < mb->max_elems)
			num_extra = mb->max_elems;

		expand = mb->expandfn(mb, mb->elems,
				      (mb->max_elems + num_extra) * elemsize);
		if (!expand) {
			errno = ENOMEM;
		} else {
			mb->max_elems += num_extra;
			mb->elems = expand;
		}
	}
	return (char *)membuf_elems_(mb, elemsize) - oldstart;
}

void *membuf_realloc(struct membuf *mb, void *rawelems, size_t newsize)
{
	return realloc(rawelems, newsize);
}
