/*
 * Copyright (c) 2013 Tatsuhiko Kubo <cubicdaiya@gmail.com>
 * Copyright (c) 2018 Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "config.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "libdiff.h"

struct 	onp_coord {
	int		 x;
	int		 y;
	int		 k;
};

struct 	onp_diff {
	const void	 *a; /* shorter subsequence */
	const void	 *b; /* longer subsequence */
	size_t		  m; /* length of "a" */
	size_t	 	  n; /* length of "b" */
	diff_cmp	  cmp; /* comparison function */
	int		 *path;
	size_t	 	  delta;
	size_t	 	  offset;
	size_t	 	  size; /* matrix size */
	size_t		  sz; /* data element width */
	struct onp_coord *pathcoords;
	size_t		  pathcoordsz;
	int 		  swapped; /* seqs swapped from input */
	struct diff	 *result;
};

#define ONP_CMP(_d, _o1, _o2) \
	((_d)->cmp((_d)->a + (_d)->sz * (_o1), \
	           (_d)->b + (_d)->sz * (_o2)))

/*
 * Search shortest path and record the path.
 */
static int
onp_snake(struct onp_diff *diff, int k, int above, int below)
{
	int 	 r, y, x;
	void	*pp;

	y = above > below ? above : below;
	x = y - k;

	r = above > below ?
		diff->path[k - 1 + diff->offset] :
		diff->path[k + 1 + diff->offset];

	while (x < (int)diff->m && y < (int)diff->n &&
	       ONP_CMP(diff, x, y)) {
		++x;
		++y;
	}

	diff->path[k + diff->offset] = diff->pathcoordsz;

	pp = reallocarray
		(diff->pathcoords,
		 diff->pathcoordsz + 1,
		 sizeof(struct onp_coord));
	if (NULL == pp)
		return -1;
	diff->pathcoords = pp;

	assert(x >= 0);
	assert(y >= 0);

	diff->pathcoords[diff->pathcoordsz].x = x;
	diff->pathcoords[diff->pathcoordsz].y = y;
	diff->pathcoords[diff->pathcoordsz].k = r;
	diff->pathcoordsz++;

	return y;
}

static int
onp_addlcs(struct onp_diff *diff, const void *e)
{
	void	*pp;

	pp = reallocarray
		(diff->result->lcs,
		 diff->result->lcssz + 1,
		 sizeof(void *));
	if (NULL == pp)
		return 0;
	diff->result->lcs = pp;
	diff->result->lcs[diff->result->lcssz] = e;
	diff->result->lcssz++;
	return 1;
}

static int
onp_addses(struct onp_diff *diff, const void *e,
	size_t originIdx, size_t targetIdx, enum difft type)
{
	void	*pp;

	pp = reallocarray
		(diff->result->ses,
		 diff->result->sessz + 1,
		 sizeof(struct diff_ses));
	if (NULL == pp)
		return 0;
	diff->result->ses = pp;
	diff->result->ses[diff->result->sessz].originIdx = originIdx;
	diff->result->ses[diff->result->sessz].targetIdx = targetIdx;
	diff->result->ses[diff->result->sessz].type = type;
	diff->result->ses[diff->result->sessz].e = e;
	diff->result->sessz++;
	return 1;
}

static int
onp_genseq(struct onp_diff *diff, const struct onp_coord* v, size_t vsz)
{
	size_t		 xpos, ypos;
	size_t         	 x_idx,  y_idx;  /* offset+1 numbers */
	int		 px_idx, py_idx; /* coordinates */
	int		 complete = 0;
	int		 rc;
	size_t		 i;

	x_idx = y_idx = 1;
	px_idx = py_idx = 0;
	xpos = ypos = 0;

	assert(vsz);

	for (i = vsz - 1; ! complete; --i) {
		while (px_idx < v[i].x || py_idx < v[i].y) {
			if (v[i].y - v[i].x > py_idx - px_idx) {
				rc = ! diff->swapped ?
					onp_addses(diff,
					 diff->b + (ypos * diff->sz),
					 0, y_idx, DIFF_ADD) :
					onp_addses(diff,
					 diff->b + (ypos * diff->sz),
					 y_idx, 0, DIFF_DELETE);
				++ypos;
				++y_idx;
				++py_idx;
			} else if (v[i].y - v[i].x < py_idx - px_idx) {
				rc = ! diff->swapped ?
					onp_addses(diff,
					 diff->a + (xpos * diff->sz),
					 x_idx, 0, DIFF_DELETE) :
					onp_addses(diff,
					 diff->a + (xpos * diff->sz),
					 0, x_idx, DIFF_ADD);
				++xpos;
				++x_idx;
				++px_idx;
			} else {
				rc = ! diff->swapped ?
					onp_addses(diff,
					 diff->a + (xpos * diff->sz),
					 x_idx, y_idx, DIFF_COMMON) :
					onp_addses(diff,
					 diff->b + (ypos * diff->sz),
					 y_idx, x_idx, DIFF_COMMON);
				if (rc)
					rc = ! diff->swapped ?
					  onp_addlcs(diff, diff->a +
						(xpos * diff->sz)) :
					  onp_addlcs(diff, diff->b +
						(ypos * diff->sz));
				++xpos;
				++ypos;
				++x_idx;
				++y_idx;
				++px_idx;
				++py_idx;
			}
			if ( ! rc)
				return -1;
		}
		complete = 0 == i;
	}

	return x_idx > diff->m && y_idx > diff->n;
}

static struct onp_diff *
onp_alloc(diff_cmp cmp, size_t sz,
	const void *a, size_t alen,
	const void *b, size_t blen)
{
	struct onp_diff *diff;

	diff = calloc(1, sizeof(struct onp_diff));

	if (NULL == diff)
		return NULL;

	if (alen > blen) {
		diff->a = b;
		diff->b = a;
		diff->m = blen;
		diff->n = alen;
		diff->swapped = 1;
	} else {
		diff->a = a;
		diff->b = b;
		diff->m = alen;
		diff->n = blen;
		diff->swapped = 0;
	}

	assert(diff->n >= diff->m);
	diff->cmp = cmp;
	diff->sz = sz;
	diff->delta = diff->n - diff->m;
	diff->offset = diff->m + 1;
	diff->size = diff->m + diff->n + 3;

	return diff;
}

static void
onp_free(struct onp_diff *diff)
{

	free(diff->path);
	free(diff->pathcoords);
	free(diff);
}

static int
onp_compose(struct onp_diff *diff, struct diff *result)
{
	int		 rc = 0;
	int		 p = -1;
	int		 k;
	int		*fp = NULL;
	int		 r;
	struct onp_coord	*epc = NULL;
	size_t		 epcsz = 0;
	size_t		 i;
	void		*pp;

	/* Initialise the path from origin to target. */

	fp = malloc(sizeof(int) * diff->size);
	diff->path = malloc(sizeof(int) * diff->size);
	diff->result = result;

	if (NULL == fp || NULL == diff->path)
		goto out;

	for (i = 0; i < diff->size; i++)
		fp[i] = diff->path[i] = -1;

	/*
	 * Run the actual algorithm.
	 * This computes the full path in diff->path from the origin to
	 * the target.
	 */

	do {
		p++;
		for (k = -p;
		     k <= (ssize_t)diff->delta - 1; k++) {
			fp[k + diff->offset] = onp_snake(diff, k,
				fp[k - 1 + diff->offset] + 1,
				fp[k + 1 + diff->offset]);
			if (fp[k + diff->offset] < 0)
				goto out;
		}
		for (k = diff->delta + p;
		     k >= (ssize_t)diff->delta + 1; k--) {
			fp[k + diff->offset] = onp_snake(diff, k,
				fp[k - 1 + diff->offset] + 1,
				fp[k + 1 + diff->offset]);
			if (fp[k + diff->offset] < 0)
				goto out;
		}

		fp[diff->delta + diff->offset] =
			onp_snake(diff, diff->delta,
				fp[diff->delta - 1 + diff->offset] + 1,
				fp[diff->delta + 1 + diff->offset]);
		if (fp[diff->delta + diff->offset] < 0)
			goto out;
	} while (fp[diff->delta + diff->offset] != (ssize_t)diff->n);

	/* Now compute edit distance. */

	assert(p >= 0);
	diff->result->editdist = diff->delta + 2 * p;

	/*
	 * Here we compute the shortest edit script and the least common
	 * subsequence from the path.
	 */

	r = diff->path[diff->delta + diff->offset];

	while(-1 != r) {
		pp = reallocarray
			(epc, epcsz + 1,
			 sizeof(struct onp_coord));
		if (NULL == pp)
			goto out;
		epc = pp;
		epc[epcsz].x = diff->pathcoords[r].x;
		epc[epcsz].y = diff->pathcoords[r].y;
		epcsz++;
		r = diff->pathcoords[r].k;
	}

	if (epcsz)
		onp_genseq(diff, epc, epcsz);

	rc = 1;
out:
	free(fp);
	free(epc);
	return rc;
}

int
diff(struct diff *d, diff_cmp cmp, size_t size,
	const void *base1, size_t nmemb1,
	const void *base2, size_t nmemb2)
{
	struct onp_diff	*p;
	int		 rc;

	p = onp_alloc(cmp, size, base1, nmemb1, base2, nmemb2);
	if (NULL == p)
		return 0;

	rc = onp_compose(p, d);
	onp_free(p);
	return rc;
}
