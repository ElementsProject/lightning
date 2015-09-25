/* This code is based on ccan/strset.c. */
#include <ccan/strmap/strmap.h>
#include <ccan/short_types/short_types.h>
#include <ccan/str/str.h>
#include <ccan/ilog/ilog.h>
#include <assert.h>
#include <stdlib.h>
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
static struct strmap *closest(struct strmap *n, const char *member)
{
	size_t len = strlen(member);
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

void *strmap_get_(const struct strmap *map, const char *member)
{
	struct strmap *n;

	/* Not empty map? */
	if (map->u.n) {
		n = closest((struct strmap *)map, member);
		if (streq(member, n->u.s))
			return n->v;
	}
	errno = ENOENT;
	return NULL;
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
	n = closest(map, member);

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

static bool iterate(struct strmap n,
		    bool (*handle)(const char *, void *, void *),
		    const void *data)
{
	if (n.v)
		return handle(n.u.s, n.v, (void *)data);

	return iterate(n.u.n->child[0], handle, data)
		&& iterate(n.u.n->child[1], handle, data);
}

void strmap_iterate_(const struct strmap *map,
		     bool (*handle)(const char *, void *, void *),
		     const void *data)
{
	/* Empty map? */
	if (!map->u.n)
		return;

	iterate(*map, handle, data);
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
	if (map->u.n)
		clear(*map);
	map->u.n = NULL;
}
