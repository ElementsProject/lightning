/* Simple speed tests for a hash of strings. */
#include <ccan/htable/htable_type.h>
#include <ccan/htable/htable.c>
#include <ccan/tal/str/str.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/tal.h>
#include <ccan/hash/hash.h>
#include <ccan/time/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

static size_t hashcount;

static const char *strkey(const char *str)
{
	return str;
}

static size_t hash_str(const char *key)
{
	hashcount++;
	return hash(key, strlen(key), 0);
}

static bool cmp(const char *obj, const char *key)
{
	return strcmp(obj, key) == 0;
}

HTABLE_DEFINE_NODUPS_TYPE(char, strkey, hash_str, cmp, htable_str);

/* Nanoseconds per operation */
static size_t normalize(const struct timeabs *start,
			const struct timeabs *stop,
			unsigned int num)
{
	return time_to_nsec(time_divide(time_between(*stop, *start), num));
}

int main(int argc, char *argv[])
{
	size_t i, j, num;
	struct timeabs start, stop;
	struct htable_str ht;
	char **words, **misswords;

	words = tal_strsplit(NULL, grab_file(NULL,
					     argv[1] ? argv[1] : "/usr/share/dict/words"), "\n",
			     STR_NO_EMPTY);
	htable_str_init(&ht);
	num = tal_count(words) - 1;
	/* Note that on my system, num is just > 98304, where we double! */
	printf("%zu words\n", num);

	/* Append and prepend last char for miss testing. */
	misswords = tal_arr(words, char *, num);
	for (i = 0; i < num; i++) {
		char lastc;
		if (strlen(words[i]))
			lastc = words[i][strlen(words[i])-1];
		else
			lastc = 'z';
		misswords[i] = tal_fmt(misswords, "%c%s%c%c",
				       lastc, words[i], lastc, lastc);
	}

	printf("#01: Initial insert: ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++)
		htable_str_add(&ht, words[i]);
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("Bytes allocated: %zu\n",
	       sizeof(ht.raw.table[0]) << ht.raw.bits);

	printf("#02: Initial lookup (match): ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++)
		if (htable_str_get(&ht, words[i]) != words[i])
			abort();
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#03: Initial lookup (miss): ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++) {
		if (htable_str_get(&ht, misswords[i]))
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	/* Lookups in order are very cache-friendly for judy; try random */
	printf("#04: Initial lookup (random): ");
	fflush(stdout);
	start = time_now();
	for (i = 0, j = 0; i < num; i++, j = (j + 10007) % num)
		if (htable_str_get(&ht, words[j]) != words[j])
			abort();
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	hashcount = 0;
	printf("#05: Initial delete all: ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++)
		if (!htable_str_del(&ht, words[i]))
			abort();
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#06: Initial re-inserting: ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++)
		htable_str_add(&ht, words[i]);
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	hashcount = 0;
	printf("#07: Deleting first half: ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i+=2)
		if (!htable_str_del(&ht, words[i]))
			abort();
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#08: Adding (a different) half: ");
	fflush(stdout);

	start = time_now();
	for (i = 0; i < num; i+=2)
		htable_str_add(&ht, misswords[i]);
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#09: Lookup after half-change (match): ");
	fflush(stdout);
	start = time_now();
	for (i = 1; i < num; i+=2)
		if (htable_str_get(&ht, words[i]) != words[i])
			abort();
	for (i = 0; i < num; i+=2) {
		if (htable_str_get(&ht, misswords[i]) != misswords[i])
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#10: Lookup after half-change (miss): ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i+=2)
		if (htable_str_get(&ht, words[i]))
			abort();
	for (i = 1; i < num; i+=2) {
		if (htable_str_get(&ht, misswords[i]))
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	/* Hashtables with delete markers can fill with markers over time.
	 * so do some changes to see how it operates in long-term. */
	printf("#11: Churn 1: ");
	start = time_now();
	for (j = 0; j < num; j+=2) {
		if (!htable_str_del(&ht, misswords[j]))
			abort();
		if (!htable_str_add(&ht, words[j]))
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#12: Churn 2: ");
	start = time_now();
	for (j = 1; j < num; j+=2) {
		if (!htable_str_del(&ht, words[j]))
			abort();
		if (!htable_str_add(&ht, misswords[j]))
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#13: Churn 3: ");
	start = time_now();
	for (j = 1; j < num; j+=2) {
		if (!htable_str_del(&ht, misswords[j]))
			abort();
		if (!htable_str_add(&ht, words[j]))
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	/* Now it's back to normal... */
	printf("#14: Post-Churn lookup (match): ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++)
		if (htable_str_get(&ht, words[i]) != words[i])
			abort();
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#15: Post-Churn lookup (miss): ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++) {
		if (htable_str_get(&ht, misswords[i]))
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	/* Lookups in order are very cache-friendly for judy; try random */
	printf("#16: Post-Churn lookup (random): ");
	fflush(stdout);
	start = time_now();
	for (i = 0, j = 0; i < num; i++, j = (j + 10007) % num)
		if (htable_str_get(&ht, words[j]) != words[j])
			abort();
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	return 0;
}
