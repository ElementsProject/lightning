#include <ccan/htable/htable_type.h>
#include <ccan/htable/htable.c>
#include <ccan/tap/tap.h>
#include <stdbool.h>
#include <string.h>

#define NUM_BITS 7
#define NUM_VALS (1 << NUM_BITS)

struct obj {
	/* Makes sure we don't try to treat and obj as a key or vice versa */
	unsigned char unused;
	unsigned int key;
};

static const unsigned int *objkey(const struct obj *obj)
{
	return &obj->key;
}

/* We use the number divided by two as the hash (for lots of
   collisions), plus set all the higher bits so we can detect if they
   don't get masked out. */
static size_t objhash(const unsigned int *key)
{
	size_t h = *key / 2;
	h |= -1UL << NUM_BITS;
	return h;
}

static bool cmp(const struct obj *obj, const unsigned int *key)
{
	return obj->key == *key;
}

HTABLE_DEFINE_TYPE(struct obj, objkey, objhash, cmp, htable_obj);

static void add_vals(struct htable_obj *ht,
		     struct obj val[], unsigned int num)
{
	unsigned int i;

	for (i = 0; i < num; i++) {
		if (htable_obj_get(ht, &i)) {
			fail("%u already in hash", i);
			return;
		}
		htable_obj_add(ht, &val[i]);
		if (htable_obj_get(ht, &i) != &val[i]) {
			fail("%u not added to hash", i);
			return;
		}
	}
	pass("Added %u numbers to hash", i);
}

static void find_vals(const struct htable_obj *ht,
		      const struct obj val[], unsigned int num)
{
	unsigned int i;

	for (i = 0; i < num; i++) {
		if (htable_obj_get(ht, &i) != &val[i]) {
			fail("%u not found in hash", i);
			return;
		}
	}
	ok1(htable_obj_count(ht) == i);
}

static void del_vals(struct htable_obj *ht,
		     const struct obj val[], unsigned int num)
{
	unsigned int i;

	for (i = 0; i < num; i++) {
		if (!htable_obj_delkey(ht, &val[i].key)) {
			fail("%u not deleted from hash", i);
			return;
		}
	}
	pass("Deleted %u numbers in hash", i);
}

static void del_vals_bykey(struct htable_obj *ht,
			   const struct obj val[] UNNEEDED, unsigned int num)
{
	unsigned int i;

	for (i = 0; i < num; i++) {
		if (!htable_obj_delkey(ht, &i)) {
			fail("%u not deleted by key from hash", i);
			return;
		}
	}
	pass("Deleted %u numbers by key from hash", i);
}

static bool check_mask(struct htable *ht, const struct obj val[], unsigned num)
{
	uint64_t i;

	for (i = 0; i < num; i++) {
		if (((uintptr_t)&val[i] & ht->common_mask) != ht->common_bits)
			return false;
	}
	return true;
}

int main(void)
{
	unsigned int i;
	struct htable_obj ht, ht2;
	struct obj val[NUM_VALS], *result;
	unsigned int dne;
	void *p;
	struct htable_obj_iter iter;

	plan_tests(35);
	for (i = 0; i < NUM_VALS; i++)
		val[i].key = i;
	dne = i;

	htable_obj_init(&ht);
	ok1(htable_obj_count(&ht) == 0);
	ok1(ht_max(&ht.raw) == 0);
	ok1(ht.raw.bits == 0);

	/* We cannot find an entry which doesn't exist. */
	ok1(!htable_obj_get(&ht, &dne));
	ok1(!htable_obj_pick(&ht, 0, NULL));

	/* Fill it, it should increase in size. */
	add_vals(&ht, val, NUM_VALS);
	ok1(ht.raw.bits == NUM_BITS + 1);
	ok1(ht_max(&ht.raw) < (1 << ht.raw.bits));

	/* Mask should be set. */
	ok1(ht.raw.common_mask != 0);
	ok1(ht.raw.common_mask != -1);
	ok1(check_mask(&ht.raw, val, NUM_VALS));

	/* Find all. */
	find_vals(&ht, val, NUM_VALS);
	ok1(!htable_obj_get(&ht, &dne));
	ok1(htable_obj_pick(&ht, 0, NULL));
	ok1(htable_obj_pick(&ht, 0, &iter));

	/* Walk once, should get them all. */
	i = 0;
	for (p = htable_obj_first(&ht,&iter); p; p = htable_obj_next(&ht, &iter))
		i++;
	ok1(i == NUM_VALS);
	i = 0;
	for (p = htable_obj_prev(&ht,&iter); p; p = htable_obj_prev(&ht, &iter))
		i++;
	ok1(i == NUM_VALS);

	/* Delete all. */
	del_vals(&ht, val, NUM_VALS);
	ok1(!htable_obj_get(&ht, &val[0].key));

	/* Worst case, a "pointer" which doesn't have any matching bits. */
	htable_add(&ht.raw, 0, (void *)~(uintptr_t)&val[NUM_VALS-1]);
	htable_obj_add(&ht, &val[NUM_VALS-1]);
	ok1(ht.raw.common_mask == 0);
	ok1(ht.raw.common_bits == 0);
	/* Delete the bogus one before we trip over it. */
	htable_del(&ht.raw, 0, (void *)~(uintptr_t)&val[NUM_VALS-1]);

	/* Add the rest. */
	add_vals(&ht, val, NUM_VALS-1);

	/* Check we can find them all. */
	find_vals(&ht, val, NUM_VALS);
	ok1(!htable_obj_get(&ht, &dne));

	/* Check copy. */
	ok1(htable_obj_copy(&ht2, &ht));

	/* Delete them all by key. */
	del_vals_bykey(&ht, val, NUM_VALS);
	del_vals_bykey(&ht2, val, NUM_VALS);

	/* Write two of the same value. */
	val[1] = val[0];
	htable_obj_add(&ht, &val[0]);
	htable_obj_add(&ht, &val[1]);
	i = 0;

	result = htable_obj_getfirst(&ht, &i, &iter);
	ok1(result == &val[0] || result == &val[1]);
	if (result == &val[0]) {
		ok1(htable_obj_getnext(&ht, &i, &iter) == &val[1]);
		ok1(htable_obj_getnext(&ht, &i, &iter) == NULL);

		/* Deleting first should make us iterate over the other. */
		ok1(htable_obj_del(&ht, &val[0]));
		ok1(htable_obj_getfirst(&ht, &i, &iter) == &val[1]);
		ok1(htable_obj_getnext(&ht, &i, &iter) == NULL);
	} else {
		ok1(htable_obj_getnext(&ht, &i, &iter) == &val[0]);
		ok1(htable_obj_getnext(&ht, &i, &iter) == NULL);

		/* Deleting first should make us iterate over the other. */
		ok1(htable_obj_del(&ht, &val[1]));
		ok1(htable_obj_getfirst(&ht, &i, &iter) == &val[0]);
		ok1(htable_obj_getnext(&ht, &i, &iter) == NULL);
	}

	htable_obj_clear(&ht);
	ok1(htable_obj_count(&ht) == 0);
	htable_obj_clear(&ht2);
	ok1(htable_obj_count(&ht2) == 0);
	return exit_status();
}
