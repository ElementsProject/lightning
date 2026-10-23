/* This code is based on the public domain code at
 * http://github.com/agl/critbit writtem by Adam Langley
 * <agl@imperialviolet.org>.
 *
 * Here are the main implementation differences:
 * (1) We don't strdup the string on insert; we use the pointer we're given.
 * (2) We use a straight bit number rather than a mask; it's simpler.
 * (3) We don't use the bottom bit of the pointer, but instead use a leading
 *     zero to distinguish nodes from strings.
 * (4) The empty string (which would look like a node) is handled
 *     using a special "empty node".
 * (5) Delete returns the string, so you can free it if you want to.
 * (6) Unions instead of void *, bool instead of int.
 */
#include <ccan/strset/strset.h>
#include <ccan/short_types/short_types.h>
#include <ccan/likely/likely.h>
#include <ccan/str/str.h>
#include <ccan/ilog/ilog.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct node {
	/* To differentiate us from strings. */
	char nul_byte;
	/* The bit where these children differ. */
	u8 bit_num;
	/* The byte number where first bit differs (-1 == empty string node). */
	size_t byte_num;
	/* These point to strings or nodes. */
	struct strset child[2];
};

/* Closest member to this in a non-empty set. */
static const char *closest(struct strset n, const char *member)
{
	size_t len = strlen(member);
	const u8 *bytes = (const u8 *)member;

	/* Anything with first byte 0 is a node. */
	while (!n.u.s[0]) {
		u8 direction = 0;

		/* Special node which represents the empty string. */
		if (unlikely(n.u.n->byte_num == (size_t)-1)) {
			n = n.u.n->child[0];
			break;
		}

		if (n.u.n->byte_num < len) {
			u8 c = bytes[n.u.n->byte_num];
			direction = (c >> n.u.n->bit_num) & 1;
		}
		n = n.u.n->child[direction];
	}
	return n.u.s;
}

char *strset_get(const struct strset *set, const char *member)
{
	const char *str;

	/* Non-empty set? */
	if (set->u.n) {
		str = closest(*set, member);
		if (streq(member, str))
			return (char *)str;
	}
	errno = ENOENT;
	return NULL;
}

static bool set_string(struct strset *set,
		       struct strset *n, const char *member)
{
	/* Substitute magic empty node if this is the empty string */
	if (unlikely(!member[0])) {
		n->u.n = malloc(sizeof(*n->u.n));
		if (unlikely(!n->u.n)) {
			errno = ENOMEM;
			return false;
		}
		n->u.n->nul_byte = '\0';
		n->u.n->byte_num = (size_t)-1;
		/* Attach the string to child[0] */
		n = &n->u.n->child[0];
	}
	n->u.s = member;
	return true;
}

bool strset_add(struct strset *set, const char *member)
{
	size_t len = strlen(member);
	const u8 *bytes = (const u8 *)member;
	struct strset *np;
	const char *str;
	struct node *newn;
	size_t byte_num;
	u8 bit_num, new_dir;

	/* Empty set? */
	if (!set->u.n) {
		return set_string(set, set, member);
	}

	/* Find closest existing member. */
	str = closest(*set, member);

	/* Find where they differ. */
	for (byte_num = 0; str[byte_num] == member[byte_num]; byte_num++) {
		if (member[byte_num] == '\0') {
			/* All identical! */
			errno = EEXIST;
			return false;
		}
	}

	/* Find which bit differs (if we had ilog8, we'd use it) */
	bit_num = ilog32_nz((u8)str[byte_num] ^ bytes[byte_num]) - 1;
	assert(bit_num < CHAR_BIT);

	/* Which direction do we go at this bit? */
	new_dir = ((bytes[byte_num]) >> bit_num) & 1;

	/* Allocate new node. */
	newn = malloc(sizeof(*newn));
	if (!newn) {
		errno = ENOMEM;
		return false;
	}
	newn->nul_byte = '\0';
	newn->byte_num = byte_num;
	newn->bit_num = bit_num;
	if (unlikely(!set_string(set, &newn->child[new_dir], member))) {
		free(newn);
		return false;
	}

	/* Find where to insert: not closest, but first which differs! */
	np = set;
	while (!np->u.s[0]) {
		u8 direction = 0;

		/* Special node which represents the empty string will
		 * break here too! */
		if (np->u.n->byte_num > byte_num)
			break;
		/* Subtle: bit numbers are "backwards" for comparison */
		if (np->u.n->byte_num == byte_num && np->u.n->bit_num < bit_num)
			break;

		if (np->u.n->byte_num < len) {
			u8 c = bytes[np->u.n->byte_num];
			direction = (c >> np->u.n->bit_num) & 1;
		}
		np = &np->u.n->child[direction];
	}

	newn->child[!new_dir]= *np;
	np->u.n = newn;
	return true;
}

char *strset_del(struct strset *set, const char *member)
{
	size_t len = strlen(member);
	const u8 *bytes = (const u8 *)member;
	struct strset *parent = NULL, *n;
	const char *ret = NULL;
	u8 direction = 0; /* prevent bogus gcc warning. */

	/* Empty set? */
	if (!set->u.n) {
		errno = ENOENT;
		return NULL;
	}

	/* Find closest, but keep track of parent. */
	n = set;
	/* Anything with first byte 0 is a node. */
	while (!n->u.s[0]) {
		u8 c = 0;

		/* Special node which represents the empty string. */
		if (unlikely(n->u.n->byte_num == (size_t)-1)) {
			const char *empty_str = n->u.n->child[0].u.s;

			if (member[0]) {
				errno = ENOENT;
				return NULL;
			}

			/* Sew empty string back so remaining logic works */
			free(n->u.n);
			n->u.s = empty_str;
			break;
		}

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

	if (!parent) {
		/* We deleted last node. */
		set->u.n = NULL;
	} else {
		struct node *old = parent->u.n;
		/* Raise other node to parent. */
		*parent = old->child[!direction];
		free(old);
	}

	return (char *)ret;
}

void strset_iterate_(const struct strset *set,
		     bool (*handle)(const char *, void *), const void *data)
{
	struct strset_iter it;
	const char *m;

	for (m = strset_iter_first(&it, set);
	     m;
	     m = strset_iter_next(&it, set, m)) {
		if (!handle(m, (void *)data))
			break;
	}
}

/* Defer child[1] of a node we're descending past. */
static void iter_push(struct strset_iter *it, struct strset *slot)
{
	if (STRSET_NUM_ITER_PARENTS == 0) {
		it->dropped = true;
		return;
	}
	if (it->num_parents == STRSET_NUM_ITER_PARENTS) {
		/* Full: drop the *shallowest* deferral (kept in-order by
		 * the slow_mode path once the stack runs out). */
		memmove(&it->parents[0], &it->parents[1],
			sizeof(it->parents[0]) * (STRSET_NUM_ITER_PARENTS - 1));
		it->num_parents--;
		it->dropped = true;
	}
	it->parents[it->num_parents++] = slot;
}

/* Descend leftmost from *slot, deferring child[1]s, and yield the leaf. */
static const char *iter_descend(struct strset_iter *it, struct strset *slot)
{
	while (!slot->u.s[0]) {
		/* Empty-string node: the string is child[0]. */
		if (unlikely(slot->u.n->byte_num == (size_t)-1)) {
			slot = &slot->u.n->child[0];
			break;
		}
		iter_push(it, &slot->u.n->child[1]);
		slot = &slot->u.n->child[0];
	}
	return slot->u.s;
}

/* Successor of cur by value: O(depth), no stack. */
static const char *iter_successor(const struct strset *set,
				  const char *cur)
{
	size_t len = strlen(cur);
	const u8 *bytes = (const u8 *)cur;
	struct strset n, cand;
	bool have_cand = false;

	n = *(struct strset *)set;
	while (!n.u.s[0]) {
		u8 c = 0, direction;

		/* Empty-string node: only holds "" in child[0]. */
		if (unlikely(n.u.n->byte_num == (size_t)-1))
			break;
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
	while (!cand.u.s[0]) {
		if (unlikely(cand.u.n->byte_num == (size_t)-1)) {
			cand = cand.u.n->child[0];
			break;
		}
		cand = cand.u.n->child[0];
	}
	return cand.u.s;
}

const char *strset_iter_first(struct strset_iter *it,
			      const struct strset *set)
{
	it->num_parents = 0;
	it->dropped = false;
	it->slow_mode = false;

	if (!set->u.n)
		return NULL;

	return iter_descend(it, (struct strset *)set);
}

const char *strset_iter_next(struct strset_iter *it,
			     const struct strset *set,
			     const char *cur)
{
	struct strset *slot;

	if (likely(!it->slow_mode)) {
		if (it->num_parents != 0) {
			slot = it->parents[--it->num_parents];
			return iter_descend(it, slot);
		}
		if (!it->dropped)
			return NULL;
		/* We dropped deferrals past STRSET_NUM_ITER_PARENTS;
		 * from here on, find successors by re-descent. */
		it->dropped = false;
		it->slow_mode = true;
	}

	return iter_successor(set, cur);
}

const struct strset *strset_prefix(const struct strset *set, const char *prefix)
{
	const struct strset *n, *top;
	size_t len = strlen(prefix);
	const u8 *bytes = (const u8 *)prefix;

	/* Empty set -> return empty set. */
	if (!set->u.n)
		return set;

	top = n = set;

	/* We walk to find the top, but keep going to check prefix matches. */
	while (!n->u.s[0]) {
		u8 c = 0, direction;

		/* Special node which represents the empty string. */
		if (unlikely(n->u.n->byte_num == (size_t)-1)) {
			n = &n->u.n->child[0];
			break;
		}

		if (n->u.n->byte_num < len)
			c = bytes[n->u.n->byte_num];

		direction = (c >> n->u.n->bit_num) & 1;
		n = &n->u.n->child[direction];
		if (c)
			top = n;
	}

	if (!strstarts(n->u.s, prefix)) {
		/* Convenient return for prefixes which do not appear in set. */
		static const struct strset empty_set;
		return &empty_set;
	}

	return top;
}

/* Recursive fallback for strset_clear's OOM path. */
static void clear(struct strset n)
{
	if (!n.u.s[0]) {
		if (likely(n.u.n->byte_num != (size_t)-1)) {
			clear(n.u.n->child[0]);
			clear(n.u.n->child[1]);
		}
		free(n.u.n);
	}
}

void strset_clear(struct strset *set)
{
	uintptr_t inline_stack[STRSET_NUM_ITER_PARENTS];
	uintptr_t *stack = inline_stack;
	size_t num = 0, max = STRSET_NUM_ITER_PARENTS;
	uintptr_t cur;
	bool have_cur;

	if (!set->u.n)
		return;

	/* Post-order without recursion: slot pointers tagged in their
	 * low bits (0 = visit child[0], 1 = visit child[1], 2 = free). */
	cur = (uintptr_t)set;
	have_cur = true;

	while (have_cur || num) {
		struct strset *slot;
		unsigned int tag;

		if (!have_cur)
			cur = stack[--num];
		have_cur = false;
		slot = (struct strset *)(cur & ~(uintptr_t)3);
		tag = cur & 3;

		if (slot->u.s[0]) {
			/* Leaf: caller-owned, keep. */
			continue;
		}
		if (unlikely(slot->u.n->byte_num == (size_t)-1)) {
			/* Empty-string node: child[0] is the caller-owned
			 * string itself; child[1] is unused. */
			free(slot->u.n);
			continue;
		}
		if (tag == 2) {
			free(slot->u.n);
			continue;
		}

		/* tag 0 or 1: requeue for the next phase, then descend. */
		{
			struct strset *child = &slot->u.n->child[tag];

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
	set->u.n = NULL;
}
