/* Density measurements for hashtables. */
#include <ccan/err/err.h>
#include <ccan/htable/htable_type.h>
#include <ccan/htable/htable.c>
#include <ccan/hash/hash.h>
#include <ccan/ptrint/ptrint.h>
#include <ccan/time/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* We don't actually hash objects: we put values in as if they were ptrs */
static uintptr_t key(const ptrint_t *obj)
{
	return ptr2int(obj);
}

static size_t hash_uintptr(uintptr_t key)
{
	return hashl(&key, 1, 0);
}

static bool cmp(const ptrint_t *p, uintptr_t k)
{
	return key(p) == k;
}

HTABLE_DEFINE_NODUPS_TYPE(ptrint_t, key, hash_uintptr, cmp, htable_ptrint);

/* Nanoseconds per operation */
static size_t normalize(const struct timeabs *start,
			const struct timeabs *stop,
			unsigned int num)
{
	return time_to_nsec(time_divide(time_between(*stop, *start), num));
}

static size_t average_run(const struct htable_ptrint *ht, size_t count, size_t *longest)
{
	size_t i, total = 0;

	*longest = 0;
	for (i = 0; i < count; i++) {
		size_t h = hash_uintptr(i + 2);
		size_t run = 1;

		while (get_raw_ptr(&ht->raw, ht->raw.table[h % ((size_t)1 << ht->raw.bits)]) != int2ptr(i + 2)) {
			h++;
			run++;
		}
		total += run;
		if (run > *longest)
			*longest = run;
	}
	return total / count;
}

int main(int argc, char *argv[])
{
	unsigned int i;
	size_t num;
	struct timeabs start, stop;
	struct htable_ptrint ht;

	if (argc != 2)
		errx(1, "Usage: density <power-of-2-tablesize>");

	num = atoi(argv[1]);

	printf("Total buckets, buckets used, nanoseconds search time per element, avg run, longest run\n");
	for (i = 1; i <= 99; i++) {
		uintptr_t j;
		struct htable_ptrint_iter it;
		size_t count, avg_run, longest_run;
		ptrint_t *p;

		htable_ptrint_init_sized(&ht, num * 3 / 4);
		assert((1 << ht.raw.bits) == num);

		/* Can't put 0 or 1 in the hash table: multiply by a prime. */
		for (j = 0; j < num * i / 100; j++) {
			htable_ptrint_add(&ht, int2ptr(j + 2));
			/* stop it from doubling! */
			ht.raw.elems = num / 2;
		}
		/* Must not have changed! */
		assert((1 << ht.raw.bits) == num);

		/* Clean cache */
		count = 0;
		for (p = htable_ptrint_first(&ht, &it); p; p = htable_ptrint_next(&ht, &it))
			count++;
		assert(count == num * i / 100);
		start = time_now();
		for (j = 0; j < count; j++)
			assert(htable_ptrint_get(&ht, j + 2));
		stop = time_now();
		avg_run = average_run(&ht, count, &longest_run);
		printf("%zu,%zu,%zu,%zu,%zu\n",
		       num, count, normalize(&start, &stop, count), avg_run, longest_run);
		fflush(stdout);
		htable_ptrint_clear(&ht);
	}

	return 0;
}
