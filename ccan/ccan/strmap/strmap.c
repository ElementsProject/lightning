/* This code is based on ccan/strset.c. */
#include <ccan/strmap/strmap.h>
#include <ccan/short_types/short_types.h>
#include <ccan/str/str.h>
#include <ccan/mem/mem.h>
#include <ccan/ilog/ilog.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct node {
	/* These point to strings or nodes. */
	struct strmap child[2];
	/* The byte number where first bit differs. */
	size_t byte_num;
	/* The bit where these children differ. */
	u8 bit_num;
};

/* Closest member to this in a non-empty map. */
static struct strmap *closest(struct strmap *n, const char *member, size_t len)
{
	const u8 *bytes = (const u8 *)member;

	/* Anything with NULL value is a node. */
	while (!n->v) {
		u8 direction = 0;

		if (n->u.n->byte_num < len) {
			u8 c = bytes[n->u.n->byte_num];
			direction = (c >> n->u.n->bit_num) & 1;
		}
		n = &n->u.n->child[direction];
	}
	return n;
}

void *strmap_getn_(const struct strmap *map,
		   const char *member, size_t memberlen)
{
	struct strmap *n;

	/* Not empty map? */
	if (map->u.n) {
		n = closest((struct strmap *)map, member, memberlen);
		if (memeqstr(member, memberlen, n->u.s))
			return n->v;
	}
	errno = ENOENT;
	return NULL;
}

void *strmap_get_(const struct strmap *map, const char *member)
{
	return strmap_getn_(map, member, strlen(member));
}

bool strmap_add_(struct strmap *map, const char *member, const void *value)
{
	size_t len = strlen(member);
	const u8 *bytes = (const u8 *)member;
	struct strmap *n;
	struct node *newn;
	size_t byte_num;
	u8 bit_num, new_dir;

	assert(value);

	/* Empty map? */
	if (!map->u.n) {
		map->u.s = member;
		map->v = (void *)value;
		return true;
	}

	/* Find closest existing member. */
	n = closest(map, member, len);

	/* Find where they differ. */
	for (byte_num = 0; n->u.s[byte_num] == member[byte_num]; byte_num++) {
		if (member[byte_num] == '\0') {
			/* All identical! */
			errno = EEXIST;
			return false;
		}
	}

	/* Find which bit differs (if we had ilog8, we'd use it) */
	bit_num = ilog32_nz((u8)n->u.s[byte_num] ^ bytes[byte_num]) - 1;
	assert(bit_num < CHAR_BIT);

	/* Which direction do we go at this bit? */
	new_dir = ((bytes[byte_num]) >> bit_num) & 1;

	/* Allocate new node. */
	newn = malloc(sizeof(*newn));
	if (!newn) {
		errno = ENOMEM;
		return false;
	}
	newn->byte_num = byte_num;
	newn->bit_num = bit_num;
	newn->child[new_dir].v = (void *)value;
	newn->child[new_dir].u.s = member;

	/* Find where to insert: not closest, but first which differs! */
	n = map;
	while (!n->v) {
		u8 direction = 0;

		if (n->u.n->byte_num > byte_num)
			break;
		/* Subtle: bit numbers are "backwards" for comparison */
		if (n->u.n->byte_num == byte_num && n->u.n->bit_num < bit_num)
			break;

		if (n->u.n->byte_num < len) {
			u8 c = bytes[n->u.n->byte_num];
			direction = (c >> n->u.n->bit_num) & 1;
		}
		n = &n->u.n->child[direction];
	}

	newn->child[!new_dir] = *n;
	n->u.n = newn;
	n->v = NULL;
	return true;
}

char *strmap_del_(struct strmap *map, const char *member, void **valuep)
{
	size_t len = strlen(member);
	const u8 *bytes = (const u8 *)member;
	struct strmap *parent = NULL, *n;
	const char *ret = NULL;
	u8 direction = 0; /* prevent bogus gcc warning. */

	/* Empty map? */
	if (!map->u.n) {
		errno = ENOENT;
		return NULL;
	}

	/* Find closest, but keep track of parent. */
	n = map;
	/* Anything with NULL value is a node. */
	while (!n->v) {
		u8 c = 0;

		parent = n;
		if (n->u.n->byte_num < len) {
			c = bytes[n->u.n->byte_num];
			direction = (c >> n->u.n->bit_num) & 1;
		} else
			direction = 0;
		n = &n->u.n->child[direction];
	}

	/* Did we find it? */
	if (!streq(member, n->u.s)) {
		errno = ENOENT;
		return NULL;
	}

	ret = n->u.s;
	if (valuep)
		*valuep = n->v;

	if (!parent) {
		/* We deleted last node. */
		map->u.n = NULL;
	} else {
		struct node *old = parent->u.n;
		/* Raise other node to parent. */
		*parent = old->child[!direction];
		free(old);
	}

	return (char *)ret;
}

/* Defer child[1] of a node we're descending past. */
static void iter_push(struct strmap_iter *it, struct strmap *slot)
{
	if (STRMAP_NUM_ITER_PARENTS == 0) {
		it->dropped = true;
		return;
	}
	if (it->num_parents == STRMAP_NUM_ITER_PARENTS) {
		/* Full: drop the *shallowest* deferral (kept in-order by
		 * the slow path once the stack runs out). */
		memmove(&it->parents[0], &it->parents[1],
			sizeof(it->parents[0]) * (STRMAP_NUM_ITER_PARENTS - 1));
		it->num_parents--;
		it->dropped = true;
	}
	it->parents[it->num_parents++] = slot;
}

/* Descend leftmost from *slot, deferring child[1]s, and yield the leaf. */
static const char *iter_descend(struct strmap_iter *it, struct strmap *slot,
				void **valuep)
{
	while (!slot->v) {
		iter_push(it, &slot->u.n->child[1]);
		slot = &slot->u.n->child[0];
	}
	*valuep = slot->v;
	return slot->u.s;
}

/* Successor of cur by value: O(depth), no stack. */
static const char *iter_successor(const struct strmap *map,
				  const char *cur, void **valuep)
{
	size_t len = strlen(cur);
	const u8 *bytes = (const u8 *)cur;
	struct strmap n, cand;
	bool have_cand = false;

	n = *(struct strmap *)map;
	while (!n.v) {
		u8 c = 0, direction;

		if (n.u.n->byte_num < len)
			c = bytes[n.u.n->byte_num];
		direction = (c >> n.u.n->bit_num) & 1;
		if (direction == 0) {
			/* Everything in child[1] sorts after child[0]. */
			cand = n.u.n->child[1];
			have_cand = true;
		}
		n = n.u.n->child[direction];
	}

	if (!have_cand)
		return NULL;

	/* Leftmost member of the deepest candidate subtree. */
	while (!cand.v)
		cand = cand.u.n->child[0];
	*valuep = cand.v;
	return cand.u.s;
}

const char *strmap_iter_first_(struct strmap_iter *it,
			       const struct strmap *map, void **valuep)
{
	it->num_parents = 0;
	it->dropped = false;
	it->slow_mode = false;

	if (!map->u.n)
		return NULL;

	return iter_descend(it, (struct strmap *)map, valuep);
}

const char *strmap_iter_next_(struct strmap_iter *it,
			      const struct strmap *map, const char *cur,
			      void **valuep)
{
	struct strmap *slot;

	if (!it->slow_mode) {
		if (it->num_parents != 0) {
			slot = it->parents[--it->num_parents];
			return iter_descend(it, slot, valuep);
		}
		if (!it->dropped)
			return NULL;
		/* We dropped deferrals past STRMAP_NUM_ITER_PARENTS;
		 * from here on, find successors by re-descent. */
		it->dropped = false;
		it->slow_mode = true;
	}

	return iter_successor(map, cur, valuep);
}

void strmap_iterate_(const struct strmap *map,
		     bool (*handle)(const char *, void *, void *),
		     const void *data)
{
	struct strmap_iter it;
	const char *m;
	void *v;

	for (m = strmap_iter_first_(&it, map, &v);
	     m;
	     m = strmap_iter_next_(&it, map, m, &v)) {
		if (!handle(m, v, (void *)data))
			break;
	}
}

const struct strmap *strmap_prefix_(const struct strmap *map,
				    const char *prefix)
{
	const struct strmap *n, *top;
	size_t len = strlen(prefix);
	const u8 *bytes = (const u8 *)prefix;

	/* Empty map -> return empty map. */
	if (!map->u.n)
		return map;

	top = n = map;

	/* We walk to find the top, but keep going to check prefix matches. */
	while (!n->v) {
		u8 c = 0, direction;

		if (n->u.n->byte_num < len)
			c = bytes[n->u.n->byte_num];

		direction = (c >> n->u.n->bit_num) & 1;
		n = &n->u.n->child[direction];
		if (c)
			top = n;
	}

	if (!strstarts(n->u.s, prefix)) {
		/* Convenient return for prefixes which do not appear in map. */
		static const struct strmap empty_map;
		return &empty_map;
	}

	return top;
}

/* Recursive fallback for strmap_clear_'s OOM path. */
static void clear(struct strmap n)
{
	if (!n.v) {
		clear(n.u.n->child[0]);
		clear(n.u.n->child[1]);
		free(n.u.n);
	}
}

void strmap_clear_(struct strmap *map)
{
	uintptr_t inline_stack[STRMAP_NUM_ITER_PARENTS];
	uintptr_t *stack = inline_stack;
	size_t num = 0, max = STRMAP_NUM_ITER_PARENTS;
	uintptr_t cur;
	bool have_cur;

	if (!map->u.n)
		return;

	/* Post-order without recursion: slot pointers tagged in their
	 * low bits (0 = visit child[0], 1 = visit child[1], 2 = free). */
	cur = (uintptr_t)map;
	have_cur = true;

	while (have_cur || num) {
		struct strmap *slot;
		unsigned int tag;

		if (!have_cur)
			cur = stack[--num];
		have_cur = false;
		slot = (struct strmap *)(cur & ~(uintptr_t)3);
		tag = cur & 3;

		if (slot->v) {
			/* Leaf: caller-owned, keep. */
			continue;
		}
		if (tag == 2) {
			free(slot->u.n);
			continue;
		}

		/* tag 0 or 1: requeue for the next phase, then descend. */
		{
			struct strmap *child = &slot->u.n->child[tag];

			if (num == max) {
				uintptr_t *ns;
				size_t nmax = max ? max * 2 : 64;

				if (stack == inline_stack) {
					ns = malloc(nmax * sizeof(*ns));
					if (ns)
						memcpy(ns, stack,
						       num * sizeof(*ns));
				} else {
					ns = realloc(stack, nmax * sizeof(*ns));
				}
				if (ns) {
					stack = ns;
					max = nmax;
				} else {
					/* OOM: finish this subtree
					 * recursively. */
					clear(*child);
					if (tag == 0)
						clear(slot->u.n->child[1]);
					free(slot->u.n);
					continue;
				}
			}
			stack[num++] = (uintptr_t)slot | (tag + 1);
			cur = (uintptr_t)child;
			have_cur = true;
		}
	}

	if (stack != inline_stack)
		free(stack);
	map->u.n = NULL;
}
