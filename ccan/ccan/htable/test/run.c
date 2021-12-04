#include <ccan/htable/htable.h>
#include <ccan/htable/htable.c>
#include <ccan/tap/tap.h>
#include <stdbool.h>
#include <string.h>

#define NUM_BITS 7
#define NUM_VALS (1 << NUM_BITS)

/* We use the number divided by two as the hash (for lots of
   collisions), plus set all the higher bits so we can detect if they
   don't get masked out. */
static size_t hash(const void *elem, void *unused UNNEEDED)
{
	size_t h = *(uint64_t *)elem / 2;
	h |= -1UL << NUM_BITS;
	return h;
}

static bool objcmp(const void *htelem, void *cmpdata)
{
	return *(uint64_t *)htelem == *(uint64_t *)cmpdata;
}

static void add_vals(struct htable *ht,
		     const uint64_t val[],
		     unsigned int off, unsigned int num)
{
	uint64_t i;

	for (i = off; i < off+num; i++) {
		if (htable_get(ht, hash(&i, NULL), objcmp, &i)) {
			fail("%llu already in hash", (long long)i);
			return;
		}
		htable_add(ht, hash(&val[i], NULL), &val[i]);
		if (htable_get(ht, hash(&i, NULL), objcmp, &i) != &val[i]) {
			fail("%llu not added to hash", (long long)i);
			return;
		}
	}
	pass("Added %llu numbers to hash", (long long)i);
}

#if 0
static void refill_vals(struct htable *ht,
			const uint64_t val[], unsigned int num)
{
	uint64_t i;

	for (i = 0; i < num; i++) {
		if (htable_get(ht, hash(&i, NULL), objcmp, &i))
			continue;
		htable_add(ht, hash(&val[i], NULL), &val[i]);
	}
}
#endif

static void find_vals(struct htable *ht,
		      const uint64_t val[], unsigned int num)
{
	uint64_t i;

	for (i = 0; i < num; i++) {
		if (htable_get(ht, hash(&i, NULL), objcmp, &i) != &val[i]) {
			fail("%llu not found in hash", (long long)i);
			return;
		}
	}
	ok1(htable_count(ht) == i);
}

static void del_vals(struct htable *ht,
		     const uint64_t val[], unsigned int num)
{
	uint64_t i;

	for (i = 0; i < num; i++) {
		if (!htable_del(ht, hash(&val[i], NULL), &val[i])) {
			fail("%llu not deleted from hash", (long long)i);
			return;
		}
	}
	pass("Deleted %llu numbers in hash", (long long)i);
}

static bool check_mask(struct htable *ht, uint64_t val[], unsigned num)
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
	unsigned int i, weight;
	uintptr_t perfect_bit;
	struct htable ht;
	uint64_t val[NUM_VALS];
	uint64_t dne;
	void *p;
	struct htable_iter iter;

	plan_tests(43);
	for (i = 0; i < NUM_VALS; i++)
		val[i] = i;
	dne = i;

	htable_init(&ht, hash, NULL);
	ok1(htable_count(&ht) == 0);
	ok1(ht_max(&ht) == 0);
	ok1(ht.bits == 0);

	/* We cannot find an entry which doesn't exist. */
	ok1(!htable_get(&ht, hash(&dne, NULL), objcmp, &dne));

	/* This should increase it once. */
	add_vals(&ht, val, 0, 1);
	ok1(ht.bits == 1);
	ok1(ht_max(&ht) == 1);
	weight = 0;
	for (i = 0; i < sizeof(ht.common_mask) * CHAR_BIT; i++) {
		if (ht.common_mask & ((uintptr_t)1 << i)) {
			weight++;
		}
	}
	/* Only one bit should be clear. */
	ok1(weight == i-1);

	/* Mask should be set. */
	ok1(check_mask(&ht, val, 1));

	/* htable_pick should always return that value */
	ok1(htable_pick(&ht, 0, NULL) == val);
	ok1(htable_pick(&ht, 1, NULL) == val);
	ok1(htable_pick(&ht, 0, &iter) == val);
	ok1(get_raw_ptr(&ht, ht.table[iter.off]) == val);
	
	/* This should increase it again. */
	add_vals(&ht, val, 1, 1);
	ok1(ht.bits == 2);
	ok1(ht_max(&ht) == 3);

	/* Mask should be set. */
	ok1(ht.common_mask != 0);
	ok1(ht.common_mask != -1);
	ok1(check_mask(&ht, val, 2));

	/* Now do the rest. */
	add_vals(&ht, val, 2, NUM_VALS - 2);

	/* Find all. */
	find_vals(&ht, val, NUM_VALS);
	ok1(!htable_get(&ht, hash(&dne, NULL), objcmp, &dne));

	/* Walk once, should get them all. */
	i = 0;
	for (p = htable_first(&ht,&iter); p; p = htable_next(&ht, &iter))
		i++;
	ok1(i == NUM_VALS);

	i = 0;
	for (p = htable_prev(&ht, &iter); p; p = htable_prev(&ht, &iter))
		i++;
	ok1(i == NUM_VALS);

	/* Delete all. */
	del_vals(&ht, val, NUM_VALS);
	ok1(!htable_get(&ht, hash(&val[0], NULL), objcmp, &val[0]));

	/* Worst case, a "pointer" which doesn't have any matching bits. */
	htable_add(&ht, 0, (void *)~(uintptr_t)&val[NUM_VALS-1]);
	htable_add(&ht, hash(&val[NUM_VALS-1], NULL), &val[NUM_VALS-1]);
	ok1(ht.common_mask == 0);
	ok1(ht.common_bits == 0);
	/* Get rid of bogus pointer before we trip over it! */
	htable_del(&ht, 0, (void *)~(uintptr_t)&val[NUM_VALS-1]);

	/* Add the rest. */
	add_vals(&ht, val, 0, NUM_VALS-1);

	/* Check we can find them all. */
	find_vals(&ht, val, NUM_VALS);
	ok1(!htable_get(&ht, hash(&dne, NULL), objcmp, &dne));

	/* Corner cases: wipe out the perfect bit using bogus pointer. */
	htable_clear(&ht);
	htable_add(&ht, 0, (void *)((uintptr_t)&val[NUM_VALS-1]));
	ok1(ht_perfect_mask(&ht));
	perfect_bit = ht_perfect_mask(&ht);
	htable_add(&ht, 0, (void *)((uintptr_t)&val[NUM_VALS-1]
				   | perfect_bit));
	ok1(ht_perfect_mask(&ht) == 0);
	htable_del(&ht, 0, (void *)((uintptr_t)&val[NUM_VALS-1] | perfect_bit));

	/* Enlarging should restore it... */
	add_vals(&ht, val, 0, NUM_VALS-1);

	ok1(ht_perfect_mask(&ht) != 0);
	htable_clear(&ht);

	ok1(htable_init_sized(&ht, hash, NULL, 1024));
	ok1(ht_max(&ht) >= 1024);
	htable_clear(&ht);

	ok1(htable_init_sized(&ht, hash, NULL, 1023));
	ok1(ht_max(&ht) >= 1023);
	htable_clear(&ht);

	ok1(htable_init_sized(&ht, hash, NULL, 1025));
	ok1(ht_max(&ht) >= 1025);
	htable_clear(&ht);

	ok1(htable_count(&ht) == 0);
	ok1(htable_pick(&ht, 0, NULL) == NULL);

	return exit_status();
}
