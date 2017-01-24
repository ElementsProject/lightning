/* CC0 license (public domain) - see LICENSE file for details */
/* This code is based on ccan/strmap.c. */
#include <ccan/intmap/intmap.h>
#include <ccan/short_types/short_types.h>
#include <ccan/str/str.h>
#include <ccan/ilog/ilog.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>

struct node {
	/* These point to strings or nodes. */
	struct intmap child[2];
	/* The bit where these children differ (0 == lsb) */
	u8 bit_num;
};

/* Closest member to this in a non-empty map. */
static struct intmap *closest(struct intmap *n, intmap_index_t index)
{
	/* Anything with NULL value is a node. */
	while (!n->v) {
		u8 direction = (index >> n->u.n->bit_num) & 1;
		n = &n->u.n->child[direction];
	}
	return n;
}

void *intmap_get_(const struct intmap *map, intmap_index_t index)
{
	struct intmap *n;

	/* Not empty map? */
	if (!intmap_empty_(map)) {
		n = closest((struct intmap *)map, index);
		if (index == n->u.i)
			return n->v;
	}
	errno = ENOENT;
	return NULL;
}

bool intmap_add_(struct intmap *map, intmap_index_t index, const void *value)
{
	struct intmap *n;
	struct node *newn;
	u8 bit_num, new_dir;

	assert(value);

	/* Empty map? */
	if (intmap_empty_(map)) {
		map->u.i = index;
		map->v = (void *)value;
		return true;
	}

	/* Find closest existing member. */
	n = closest(map, index);

	/* Find highest bit where they differ. */
	bit_num = ilog64(n->u.i ^ index);
	if (bit_num == 0) {
		errno = EEXIST;
		return false;
	}
	bit_num--;

	assert(bit_num < CHAR_BIT*sizeof(index));

	/* Which direction do we go at this bit? */
	new_dir = (index >> bit_num) & 1;

	/* Allocate new node. */
	newn = malloc(sizeof(*newn));
	if (!newn) {
		errno = ENOMEM;
		return false;
	}
	newn->bit_num = bit_num;
	newn->child[new_dir].v = (void *)value;
	newn->child[new_dir].u.i = index;

	/* Find where to insert: not closest, but first which differs! */
	n = map;
	while (!n->v) {
		u8 direction;

		/* Subtle: bit numbers are "backwards" for comparison */
		if (n->u.n->bit_num < bit_num)
			break;

		direction = (index >> n->u.n->bit_num) & 1;
		n = &n->u.n->child[direction];
	}

	newn->child[!new_dir] = *n;
	n->u.n = newn;
	n->v = NULL;
	return true;
}

void *intmap_del_(struct intmap *map, intmap_index_t index)
{
	struct intmap *parent = NULL, *n;
	u8 direction;
	void *value;

	/* Empty map? */
	if (intmap_empty_(map)) {
		errno = ENOENT;
		return NULL;
	}

	/* Find closest, but keep track of parent. */
	n = map;
	/* Anything with NULL value is a node. */
	while (!n->v) {
		parent = n;
		direction = (index >> n->u.n->bit_num) & 1;
		n = &n->u.n->child[direction];
	}

	/* Did we find it? */
	if (index != n->u.i) {
		errno = ENOENT;
		return NULL;
	}

	value = n->v;

	if (!parent) {
		/* We deleted last node. */
		intmap_init_(map);
	} else {
		struct node *old = parent->u.n;
		/* Raise other node to parent. */
		*parent = old->child[!direction];
		free(old);
	}
	errno = 0;
	return value;
}

void *intmap_first_(const struct intmap *map, intmap_index_t *indexp)
{
	const struct intmap *n;

	if (intmap_empty_(map)) {
		errno = ENOENT;
		return NULL;
	}
	
	n = map;
	/* Anything with NULL value is a node. */
	while (!n->v)
		n = &n->u.n->child[0];
	errno = 0;
	*indexp = n->u.i;
	return n->v;
}
		
void *intmap_after_(const struct intmap *map, intmap_index_t *indexp)
{
	const struct intmap *n, *prev = NULL;

	/* Special case of empty map */
	if (intmap_empty_(map)) {
		errno = ENOENT;
		return NULL;
	}

	/* Follow down, track the last place where we could have set a bit
	 * instead of clearing it: this is the higher alternative tree. */
	n = map;
	while (!n->v) {
		u8 direction = (*indexp >> n->u.n->bit_num) & 1;
		if (!direction)
			prev = n;
		n = &n->u.n->child[direction];
	}

	/* Found a successor? */
	if (n->u.i > *indexp) {
		errno = 0;
		*indexp = n->u.i;
		return n->v;
	}

	/* Nowhere to go back up to? */
	if (!prev) {
		errno = ENOENT;
		return NULL;
	}

	/* Get first one from that other branch. */
	return intmap_first_(&prev->u.n->child[1], indexp);
}

static void clear(struct intmap n)
{
	if (!n.v) {
		clear(n.u.n->child[0]);
		clear(n.u.n->child[1]);
		free(n.u.n);
	}
}

void intmap_clear_(struct intmap *map)
{
	if (!intmap_empty_(map))
		clear(*map);
	intmap_init_(map);
}
