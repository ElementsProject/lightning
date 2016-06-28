/* Licensed under LGPLv2+ - see LICENSE file for details */
#include <ccan/htable/htable.h>
#include <ccan/compiler/compiler.h>
#include <stdlib.h>
#include <limits.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>

/* We use 0x1 as deleted marker. */
#define HTABLE_DELETED (0x1)

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

static inline uintptr_t get_hash_ptr_bits(const struct htable *ht,
					  size_t hash)
{
	/* Shuffling the extra bits (as specified in mask) down the
	 * end is quite expensive.  But the lower bits are redundant, so
	 * we fold the value first. */
	return (hash ^ (hash >> ht->bits))
		& ht->common_mask & ~ht->perfect_bit;
}

void htable_init(struct htable *ht,
		 size_t (*rehash)(const void *elem, void *priv), void *priv)
{
	struct htable empty = HTABLE_INITIALIZER(empty, NULL, NULL);
	*ht = empty;
	ht->rehash = rehash;
	ht->priv = priv;
	ht->table = &ht->perfect_bit;
}

/* We've changed ht->bits, update ht->max and ht->max_with_deleted */
static void htable_adjust_capacity(struct htable *ht)
{
	ht->max = ((size_t)3 << ht->bits) / 4;
	ht->max_with_deleted = ((size_t)9 << ht->bits) / 10;
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

	ht->table = calloc(1 << ht->bits, sizeof(size_t));
	if (!ht->table) {
		ht->table = &ht->perfect_bit;
		return false;
	}
	htable_adjust_capacity(ht);
	return true;
}
	
void htable_clear(struct htable *ht)
{
	if (ht->table != &ht->perfect_bit)
		free((void *)ht->table);
	htable_init(ht, ht->rehash, ht->priv);
}

bool htable_copy(struct htable *dst, const struct htable *src)
{
	uintptr_t *htable = malloc(sizeof(size_t) << src->bits);

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

void *htable_firstval(const struct htable *ht,
		      struct htable_iter *i, size_t hash)
{
	i->off = hash_bucket(ht, hash);
	return htable_val(ht, i, hash, ht->perfect_bit);
}

void *htable_nextval(const struct htable *ht,
		     struct htable_iter *i, size_t hash)
{
	i->off = (i->off + 1) & ((1 << ht->bits)-1);
	return htable_val(ht, i, hash, 0);
}

void *htable_first(const struct htable *ht, struct htable_iter *i)
{
	for (i->off = 0; i->off < (size_t)1 << ht->bits; i->off++) {
		if (entry_is_valid(ht->table[i->off]))
			return get_raw_ptr(ht, ht->table[i->off]);
	}
	return NULL;
}

void *htable_next(const struct htable *ht, struct htable_iter *i)
{
	for (i->off++; i->off < (size_t)1 << ht->bits; i->off++) {
		if (entry_is_valid(ht->table[i->off]))
			return get_raw_ptr(ht, ht->table[i->off]);
	}
	return NULL;
}

void *htable_prev(const struct htable *ht, struct htable_iter *i)
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
	uintptr_t perfect = ht->perfect_bit;

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
	ht->table = calloc(1 << (ht->bits+1), sizeof(size_t));
	if (!ht->table) {
		ht->table = oldtable;
		return false;
	}
	ht->bits++;
	htable_adjust_capacity(ht);

	/* If we lost our "perfect bit", get it back now. */
	if (!ht->perfect_bit && ht->common_mask) {
		for (i = 0; i < sizeof(ht->common_mask) * CHAR_BIT; i++) {
			if (ht->common_mask & ((size_t)1 << i)) {
				ht->perfect_bit = (size_t)1 << i;
				break;
			}
		}
	}

	if (oldtable != &ht->perfect_bit) {
		for (i = 0; i < oldnum; i++) {
			if (entry_is_valid(e = oldtable[i])) {
				void *p = get_raw_ptr(ht, e);
				ht_add(ht, p, ht->rehash(p, ht->priv));
			}
		}
		free(oldtable);
	}
	ht->deleted = 0;
	return true;
}

static COLD void rehash_table(struct htable *ht)
{
	size_t start, i;
	uintptr_t e;

	/* Beware wrap cases: we need to start from first empty bucket. */
	for (start = 0; ht->table[start]; start++);

	for (i = 0; i < (size_t)1 << ht->bits; i++) {
		size_t h = (i + start) & ((1 << ht->bits)-1);
		e = ht->table[h];
		if (!e)
			continue;
		if (e == HTABLE_DELETED)
			ht->table[h] = 0;
		else if (!(e & ht->perfect_bit)) {
			void *p = get_raw_ptr(ht, e);
			ht->table[h] = 0;
			ht_add(ht, p, ht->rehash(p, ht->priv));
		}
	}
	ht->deleted = 0;
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
		ht->perfect_bit = 1;
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
	ht->perfect_bit &= ~maskdiff;
}

bool htable_add(struct htable *ht, size_t hash, const void *p)
{
	if (ht->elems+1 > ht->max && !double_table(ht))
		return false;
	if (ht->elems+1 + ht->deleted > ht->max_with_deleted)
		rehash_table(ht);
	assert(p);
	if (((uintptr_t)p & ht->common_mask) != ht->common_bits)
		update_common(ht, p);

	ht_add(ht, p, hash);
	ht->elems++;
	return true;
}

bool htable_del(struct htable *ht, size_t h, const void *p)
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

void htable_delval(struct htable *ht, struct htable_iter *i)
{
	assert(i->off < (size_t)1 << ht->bits);
	assert(entry_is_valid(ht->table[i->off]));

	ht->elems--;
	ht->table[i->off] = HTABLE_DELETED;
	ht->deleted++;
}
