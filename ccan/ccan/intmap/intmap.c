/* CC0 license (public domain) - see LICENSE file for details */
/* This code is based on ccan/strmap.c. */
#include <ccan/bitops/bitops.h>
#include <ccan/intmap/intmap.h>
#include <ccan/short_types/short_types.h>
#include <ccan/str/str.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>

struct node {
	/* These point to strings or nodes. */
	struct intmap child[2];
	/* Encoding both prefix and critbit: 1 is appended to prefix. */
	intmap_index_t prefix_and_critbit;
};

static int critbit(const struct intmap *n)
{
	return bitops_ls64(n->u.n->prefix_and_critbit);
}

static intmap_index_t prefix_mask(int critbit)
{
	/* Mask does not include critbit itself, but can't shift by critbit+1 */
	return -2ULL << critbit;
}

static intmap_index_t prefix_and_critbit(intmap_index_t v, int n)
{
	intmap_index_t critbit = ((intmap_index_t)1 << n);
	return (v & ~(critbit - 1)) | critbit;
}

void *intmap_get_(const struct intmap *map, intmap_index_t index)
{
	/* Not empty map? */
	if (!intmap_empty_(map)) {
		const struct intmap *n = map;
		/* Anything with NULL value is a node. */
		while (!n->v) {
			/* FIXME: compare cmp prefix, if not equal, ENOENT */
			u8 direction = (index >> critbit(n)) & 1;
			n = &n->u.n->child[direction];
		}
		if (index == n->u.i)
			return n->v;
	}
	errno = ENOENT;
	return NULL;
}

static bool split_node(struct intmap *n, intmap_index_t nodeindex,
		       intmap_index_t index, const void *value)
{
	struct node *newn;
	int new_dir;

	/* Find highest bit where they differ. */
	unsigned int critbit = bitops_hs64(nodeindex ^ index);
	assert(critbit < CHAR_BIT*sizeof(index));

	/* Which direction do we go at this bit? */
	new_dir = (index >> critbit) & 1;

	/* Allocate new node. */
	newn = malloc(sizeof(*newn));
	if (!newn) {
		errno = ENOMEM;
		return false;
	}
	newn->prefix_and_critbit = prefix_and_critbit(index, critbit);
	newn->child[new_dir].v = (void *)value;
	newn->child[new_dir].u.i = index;
	newn->child[!new_dir] = *n;

	n->u.n = newn;
	n->v = NULL;
	return true;
}

bool intmap_add_(struct intmap *map, intmap_index_t index, const void *value)
{
	struct intmap *n;

	assert(value);

	/* Empty map? */
	if (intmap_empty_(map)) {
		map->u.i = index;
		map->v = (void *)value;
		return true;
	}

	n = map;
	/* Anything with NULL value is a node. */
	while (!n->v) {
		int crit = critbit(n);
		intmap_index_t mask = prefix_mask(crit);
		u8 direction = (index >> crit) & 1;

		if ((index & mask) != (n->u.n->prefix_and_critbit & mask))
			return split_node(n, n->u.n->prefix_and_critbit & mask,
					  index, value);
		n = &n->u.n->child[direction];
	}

	if (index == n->u.i) {
		errno = EEXIST;
		return false;
	}

	return split_node(n, n->u.i, index, value);
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
		/* FIXME: compare cmp prefix, if not equal, ENOENT */
		parent = n;
		direction = (index >> critbit(n)) & 1;
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
	intmap_index_t index = (*indexp) + 1;

	/* Special case of overflow */
	if (index == 0)
		goto none_left;

	/* Special case of empty map */
	if (intmap_empty_(map))
		goto none_left;

	/* Follow down, until prefix differs. */
	n = map;
	while (!n->v) {
		int crit = critbit(n);
		u8 direction;
		intmap_index_t prefix, idx;

		idx = (index >> crit);
		direction = idx & 1;

		/* Leave critbit in place: we can't shift by 64 anyway */
		idx |= 1;
		prefix = n->u.n->prefix_and_critbit >> crit;

		/* If this entire tree is greater than index, take first */
		if (idx < prefix)
			return intmap_first_(n, indexp);
		/* If this entire tree is less than index, we're past it. */
		else if (idx > prefix)
			goto try_greater_tree;

		/* Remember greater tree for backtracking */
		if (!direction)
			prev = n;
		n = &n->u.n->child[direction];
	}

	/* Found a successor? */
	if (n->u.i >= index) {
		errno = 0;
		*indexp = n->u.i;
		return n->v;
	}

try_greater_tree:
	/* If we ever took a lesser branch, go back to greater branch */
	if (prev)
		return intmap_first_(&prev->u.n->child[1], indexp);

none_left:
	errno = ENOENT;
	return NULL;
}

void *intmap_last_(const struct intmap *map, intmap_index_t *indexp)
{
	const struct intmap *n;

	if (intmap_empty_(map)) {
		errno = ENOENT;
		return NULL;
	}

	n = map;
	/* Anything with NULL value is a node. */
	while (!n->v)
		n = &n->u.n->child[1];
	errno = 0;
	*indexp = n->u.i;
	return n->v;
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

bool intmap_iterate_(const struct intmap *n,
		     bool (*handle)(intmap_index_t, void *, void *),
		     void *data,
		     intmap_index_t offset)
{
	/* Can only happen at root */
	if (intmap_empty_(n))
		return true;

	if (n->v)
		return handle(n->u.i - offset, n->v, data);

	return intmap_iterate_(&n->u.n->child[0], handle, data, offset)
		&& intmap_iterate_(&n->u.n->child[1], handle, data, offset);
}
