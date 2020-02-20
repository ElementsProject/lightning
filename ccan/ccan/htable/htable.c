/* Licensed under LGPLv2+ - see LICENSE file for details */
#include <ccan/htable/htable.h>
#include <ccan/compiler/compiler.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>

/* We use 0x1 as deleted marker. */
#define HTABLE_DELETED (0x1)

/* perfect_bitnum 63 means there's no perfect bitnum */
#define NO_PERFECT_BIT (sizeof(uintptr_t) * CHAR_BIT - 1)

static void *htable_default_alloc(struct htable *ht, size_t len)
{
	return calloc(len, 1);
}

static void htable_default_free(struct htable *ht, void *p)
{
	free(p);
}

static void *(*htable_alloc)(struct htable *, size_t) = htable_default_alloc;
static void (*htable_free)(struct htable *, void *) = htable_default_free;

void htable_set_allocator(void *(*alloc)(struct htable *, size_t len),
			  void (*free)(struct htable *, void *p))
{
	if (!alloc)
		alloc = htable_default_alloc;
	if (!free)
		free = htable_default_free;
	htable_alloc = alloc;
	htable_free = free;
}

/* We clear out the bits which are always the same, and put metadata there. */
static inline uintptr_t get_extra_ptr_bits(const struct htable *ht,
					   uintptr_t e)
{
	return e & ht->common_mask;
}

static inline void *get_raw_ptr(const struct htable *ht, uintptr_t e)
{
	return (void *)((e & ~ht->common_mask) | ht->common_bits);
}

static inline uintptr_t make_hval(const struct htable *ht,
				  const void *p, uintptr_t bits)
{
	return ((uintptr_t)p & ~ht->common_mask) | bits;
}

static inline bool entry_is_valid(uintptr_t e)
{
	return e > HTABLE_DELETED;
}

static inline uintptr_t ht_perfect_mask(const struct htable *ht)
{
	return (uintptr_t)2 << ht->perfect_bitnum;
}

static inline uintptr_t get_hash_ptr_bits(const struct htable *ht,
					  size_t hash)
{
	/* Shuffling the extra bits (as specified in mask) down the
	 * end is quite expensive.  But the lower bits are redundant, so
	 * we fold the value first. */
	return (hash ^ (hash >> ht->bits))
		& ht->common_mask & ~ht_perfect_mask(ht);
}

void htable_init(struct htable *ht,
		 size_t (*rehash)(const void *elem, void *priv), void *priv)
{
	struct htable empty = HTABLE_INITIALIZER(empty, NULL, NULL);
	*ht = empty;
	ht->rehash = rehash;
	ht->priv = priv;
	ht->table = &ht->common_bits;
}

static inline size_t ht_max(const struct htable *ht)
{
	return ((size_t)3 << ht->bits) / 4;
}

static inline size_t ht_max_with_deleted(const struct htable *ht)
{
	return ((size_t)9 << ht->bits) / 10;
}

bool htable_init_sized(struct htable *ht,
		       size_t (*rehash)(const void *, void *),
		       void *priv, size_t expect)
{
	htable_init(ht, rehash, priv);

	/* Don't go insane with sizing. */
	for (ht->bits = 1; ((size_t)3 << ht->bits) / 4 < expect; ht->bits++) {
		if (ht->bits == 30)
			break;
	}

	ht->table = htable_alloc(ht, sizeof(size_t) << ht->bits);
	if (!ht->table) {
		ht->table = &ht->common_bits;
		return false;
	}
	(void)htable_debug(ht, HTABLE_LOC);
	return true;
}
	
void htable_clear(struct htable *ht)
{
	if (ht->table != &ht->common_bits)
		htable_free(ht, (void *)ht->table);
	htable_init(ht, ht->rehash, ht->priv);
}

bool htable_copy_(struct htable *dst, const struct htable *src)
{
	uintptr_t *htable = htable_alloc(dst, sizeof(size_t) << src->bits);

	if (!htable)
		return false;

	*dst = *src;
	dst->table = htable;
	memcpy(dst->table, src->table, sizeof(size_t) << src->bits);
	return true;
}

static size_t hash_bucket(const struct htable *ht, size_t h)
{
	return h & ((1 << ht->bits)-1);
}

static void *htable_val(const struct htable *ht,
			struct htable_iter *i, size_t hash, uintptr_t perfect)
{
	uintptr_t h2 = get_hash_ptr_bits(ht, hash) | perfect;

	while (ht->table[i->off]) {
		if (ht->table[i->off] != HTABLE_DELETED) {
			if (get_extra_ptr_bits(ht, ht->table[i->off]) == h2)
				return get_raw_ptr(ht, ht->table[i->off]);
		}
		i->off = (i->off + 1) & ((1 << ht->bits)-1);
		h2 &= ~perfect;
	}
	return NULL;
}

void *htable_firstval_(const struct htable *ht,
		       struct htable_iter *i, size_t hash)
{
	i->off = hash_bucket(ht, hash);
	return htable_val(ht, i, hash, ht_perfect_mask(ht));
}

void *htable_nextval_(const struct htable *ht,
		      struct htable_iter *i, size_t hash)
{
	i->off = (i->off + 1) & ((1 << ht->bits)-1);
	return htable_val(ht, i, hash, 0);
}

void *htable_first_(const struct htable *ht, struct htable_iter *i)
{
	for (i->off = 0; i->off < (size_t)1 << ht->bits; i->off++) {
		if (entry_is_valid(ht->table[i->off]))
			return get_raw_ptr(ht, ht->table[i->off]);
	}
	return NULL;
}

void *htable_next_(const struct htable *ht, struct htable_iter *i)
{
	for (i->off++; i->off < (size_t)1 << ht->bits; i->off++) {
		if (entry_is_valid(ht->table[i->off]))
			return get_raw_ptr(ht, ht->table[i->off]);
	}
	return NULL;
}

void *htable_prev_(const struct htable *ht, struct htable_iter *i)
{
	for (;;) {
		if (!i->off)
			return NULL;
		i->off --;
		if (entry_is_valid(ht->table[i->off]))
			return get_raw_ptr(ht, ht->table[i->off]);
	}
}

/* This does not expand the hash table, that's up to caller. */
static void ht_add(struct htable *ht, const void *new, size_t h)
{
	size_t i;
	uintptr_t perfect = ht_perfect_mask(ht);

	i = hash_bucket(ht, h);

	while (entry_is_valid(ht->table[i])) {
		perfect = 0;
		i = (i + 1) & ((1 << ht->bits)-1);
	}
	ht->table[i] = make_hval(ht, new, get_hash_ptr_bits(ht, h)|perfect);
}

static COLD bool double_table(struct htable *ht)
{
	unsigned int i;
	size_t oldnum = (size_t)1 << ht->bits;
	uintptr_t *oldtable, e;

	oldtable = ht->table;
	ht->table = htable_alloc(ht, sizeof(size_t) << (ht->bits+1));
	if (!ht->table) {
		ht->table = oldtable;
		return false;
	}
	ht->bits++;

	/* If we lost our "perfect bit", get it back now. */
	if (ht->perfect_bitnum == NO_PERFECT_BIT && ht->common_mask) {
		for (i = 0; i < sizeof(ht->common_mask) * CHAR_BIT; i++) {
			if (ht->common_mask & ((size_t)2 << i)) {
				ht->perfect_bitnum = i;
				break;
			}
		}
	}

	if (oldtable != &ht->common_bits) {
		for (i = 0; i < oldnum; i++) {
			if (entry_is_valid(e = oldtable[i])) {
				void *p = get_raw_ptr(ht, e);
				ht_add(ht, p, ht->rehash(p, ht->priv));
			}
		}
		htable_free(ht, oldtable);
	}
	ht->deleted = 0;

	(void)htable_debug(ht, HTABLE_LOC);
	return true;
}

static COLD void rehash_table(struct htable *ht)
{
	size_t start, i;
	uintptr_t e, perfect = ht_perfect_mask(ht);

	/* Beware wrap cases: we need to start from first empty bucket. */
	for (start = 0; ht->table[start]; start++);

	for (i = 0; i < (size_t)1 << ht->bits; i++) {
		size_t h = (i + start) & ((1 << ht->bits)-1);
		e = ht->table[h];
		if (!e)
			continue;
		if (e == HTABLE_DELETED)
			ht->table[h] = 0;
		else if (!(e & perfect)) {
			void *p = get_raw_ptr(ht, e);
			ht->table[h] = 0;
			ht_add(ht, p, ht->rehash(p, ht->priv));
		}
	}
	ht->deleted = 0;
	(void)htable_debug(ht, HTABLE_LOC);
}

/* We stole some bits, now we need to put them back... */
static COLD void update_common(struct htable *ht, const void *p)
{
	unsigned int i;
	uintptr_t maskdiff, bitsdiff;

	if (ht->elems == 0) {
		/* Always reveal one bit of the pointer in the bucket,
		 * so it's not zero or HTABLE_DELETED (1), even if
		 * hash happens to be 0.  Assumes (void *)1 is not a
		 * valid pointer. */
		for (i = sizeof(uintptr_t)*CHAR_BIT - 1; i > 0; i--) {
			if ((uintptr_t)p & ((uintptr_t)1 << i))
				break;
		}

		ht->common_mask = ~((uintptr_t)1 << i);
		ht->common_bits = ((uintptr_t)p & ht->common_mask);
		ht->perfect_bitnum = 0;
		(void)htable_debug(ht, HTABLE_LOC);
		return;
	}

	/* Find bits which are unequal to old common set. */
	maskdiff = ht->common_bits ^ ((uintptr_t)p & ht->common_mask);

	/* These are the bits which go there in existing entries. */
	bitsdiff = ht->common_bits & maskdiff;

	for (i = 0; i < (size_t)1 << ht->bits; i++) {
		if (!entry_is_valid(ht->table[i]))
			continue;
		/* Clear the bits no longer in the mask, set them as
		 * expected. */
		ht->table[i] &= ~maskdiff;
		ht->table[i] |= bitsdiff;
	}

	/* Take away those bits from our mask, bits and perfect bit. */
	ht->common_mask &= ~maskdiff;
	ht->common_bits &= ~maskdiff;
	if (ht_perfect_mask(ht) & maskdiff)
		ht->perfect_bitnum = NO_PERFECT_BIT;
	(void)htable_debug(ht, HTABLE_LOC);
}

bool htable_add_(struct htable *ht, size_t hash, const void *p)
{
	if (ht->elems+1 > ht_max(ht) && !double_table(ht))
		return false;
	if (ht->elems+1 + ht->deleted > ht_max_with_deleted(ht))
		rehash_table(ht);
	assert(p);
	if (((uintptr_t)p & ht->common_mask) != ht->common_bits)
		update_common(ht, p);

	ht_add(ht, p, hash);
	ht->elems++;
	return true;
}

bool htable_del_(struct htable *ht, size_t h, const void *p)
{
	struct htable_iter i;
	void *c;

	for (c = htable_firstval(ht,&i,h); c; c = htable_nextval(ht,&i,h)) {
		if (c == p) {
			htable_delval(ht, &i);
			return true;
		}
	}
	return false;
}

void htable_delval_(struct htable *ht, struct htable_iter *i)
{
	assert(i->off < (size_t)1 << ht->bits);
	assert(entry_is_valid(ht->table[i->off]));

	ht->elems--;
	ht->table[i->off] = HTABLE_DELETED;
	ht->deleted++;
}

void *htable_pick_(const struct htable *ht, size_t seed, struct htable_iter *i)
{
	void *e;
	struct htable_iter unwanted;

	if (!i)
		i = &unwanted;
	i->off = seed % ((size_t)1 << ht->bits);
	e = htable_next(ht, i);
	if (!e)
		e = htable_first(ht, i);
	return e;
}

struct htable *htable_check(const struct htable *ht, const char *abortstr)
{
	void *p;
	struct htable_iter i;
	size_t n = 0;

	/* Use non-DEBUG versions here, to avoid infinite recursion with
	 * CCAN_HTABLE_DEBUG! */
	for (p = htable_first_(ht, &i); p; p = htable_next_(ht, &i)) {
		struct htable_iter i2;
		void *c;
		size_t h = ht->rehash(p, ht->priv);
		bool found = false;

		n++;

		/* Open-code htable_get to avoid CCAN_HTABLE_DEBUG */
		for (c = htable_firstval_(ht, &i2, h);
		     c;
		     c = htable_nextval_(ht, &i2, h)) {
			if (c == p) {
				found = true;
				break;
			}
		}

		if (!found) {
			if (abortstr) {
				fprintf(stderr,
					"%s: element %p in position %zu"
					" cannot find itself\n",
					abortstr, p, i.off);
				abort();
			}
			return NULL;
		}
	}
	if (n != ht->elems) {
		if (abortstr) {
			fprintf(stderr,
				"%s: found %zu elems, expected %zu\n",
				abortstr, n, ht->elems);
			abort();
		}
		return NULL;
	}

	return (struct htable *)ht;
}
