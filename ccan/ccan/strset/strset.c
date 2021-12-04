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

static bool iterate(struct strset n,
		    bool (*handle)(const char *, void *), const void *data)
{
	if (n.u.s[0])
		return handle(n.u.s, (void *)data);
	if (unlikely(n.u.n->byte_num == (size_t)-1))
		return handle(n.u.n->child[0].u.s, (void *)data);

	return iterate(n.u.n->child[0], handle, data)
		&& iterate(n.u.n->child[1], handle, data);
}

void strset_iterate_(const struct strset *set,
		     bool (*handle)(const char *, void *), const void *data)
{
	/* Empty set? */
	if (!set->u.n)
		return;

	iterate(*set, handle, data);
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
	if (set->u.n)
		clear(*set);
	set->u.n = NULL;
}
