/* Simple speed tests using strset code.
 *
 * Results on my 32 bit Intel(R) Core(TM) i5 CPU M 560  @ 2.67GHz, gcc 4.5.2:
 * Run 100 times: Min-Max(Avg)
 #01: Initial insert:   212-219(214)
 #02: Initial lookup (match):   161-169(162)
 #03: Initial lookup (miss):   157-163(158)
 #04: Initial lookup (random):   450-479(453)
 #05: Initial delete all:   126-137(128)
 #06: Initial re-inserting:   193-198(194)
 #07: Deleting first half:   99-102(99)
 #08: Adding (a different) half:   143-154(144)
 #09: Lookup after half-change (match):   183-189(184)
 #10: Lookup after half-change (miss):   198-212(199)
 #11: Churn 1:   274-282(276)
 #12: Churn 2:   279-296(282)
 #13: Churn 3:   278-294(280)
 #14: Post-Churn lookup (match):   170-180(171)
 #15: Post-Churn lookup (miss):   175-186(176)
 #16: Post-Churn lookup (random):   522-534(525)
 */
#include <ccan/tal/str/str.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/talloc/talloc.h>
#include <ccan/time/time.h>
#include <ccan/strset/strset.c>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

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
	struct strset set;
	char **words, **misswords;

	words = tal_strsplit(NULL, grab_file(NULL,
					     argv[1] ? argv[1] : "/usr/share/dict/words"),
			     "\n", STR_NO_EMPTY);
	strset_init(&set);
	num = tal_count(words) - 1;
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
		strset_add(&set, words[i]);
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

#if 0
	printf("Nodes allocated: %zu (%zu bytes)\n",
	       allocated, allocated * sizeof(critbit0_node));
#endif

	printf("#02: Initial lookup (match): ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++)
		if (!strset_get(&set, words[i]))
			abort();
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#03: Initial lookup (miss): ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++) {
		if (strset_get(&set, misswords[i]))
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	/* Lookups in order are very cache-friendly for judy; try random */
	printf("#04: Initial lookup (random): ");
	fflush(stdout);
	start = time_now();
	for (i = 0, j = 0; i < num; i++, j = (j + 10007) % num)
		if (!strset_get(&set, words[j]))
			abort();
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#05: Initial delete all: ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++)
		if (!strset_del(&set, words[i]))
			abort();
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#06: Initial re-inserting: ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++)
		strset_add(&set, words[i]);
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#07: Deleting first half: ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i+=2)
		if (!strset_del(&set, words[i]))
			abort();
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#08: Adding (a different) half: ");
	fflush(stdout);

	start = time_now();
	for (i = 0; i < num; i+=2)
		strset_add(&set, misswords[i]);
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#09: Lookup after half-change (match): ");
	fflush(stdout);
	start = time_now();
	for (i = 1; i < num; i+=2)
		if (!strset_get(&set, words[i]))
			abort();
	for (i = 0; i < num; i+=2) {
		if (!strset_get(&set, misswords[i]))
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#10: Lookup after half-change (miss): ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i+=2)
		if (strset_get(&set, words[i]))
			abort();
	for (i = 1; i < num; i+=2) {
		if (strset_get(&set, misswords[i]))
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	/* Hashtables with delete markers can fill with markers over time.
	 * so do some changes to see how it operates in long-term. */
	printf("#11: Churn 1: ");
	start = time_now();
	for (j = 0; j < num; j+=2) {
		if (!strset_del(&set, misswords[j]))
			abort();
		if (!strset_add(&set, words[j]))
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#12: Churn 2: ");
	start = time_now();
	for (j = 1; j < num; j+=2) {
		if (!strset_del(&set, words[j]))
			abort();
		if (!strset_add(&set, misswords[j]))
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#13: Churn 3: ");
	start = time_now();
	for (j = 1; j < num; j+=2) {
		if (!strset_del(&set, misswords[j]))
			abort();
		if (!strset_add(&set, words[j]))
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	/* Now it's back to normal... */
	printf("#14: Post-Churn lookup (match): ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++)
		if (!strset_get(&set, words[i]))
			abort();
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	printf("#15: Post-Churn lookup (miss): ");
	fflush(stdout);
	start = time_now();
	for (i = 0; i < num; i++) {
		if (strset_get(&set, misswords[i]))
			abort();
	}
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	/* Lookups in order are very cache-friendly for judy; try random */
	printf("#16: Post-Churn lookup (random): ");
	fflush(stdout);
	start = time_now();
	for (i = 0, j = 0; i < num; i++, j = (j + 10007) % num)
		if (!strset_get(&set, words[j]))
			abort();
	stop = time_now();
	printf(" %zu ns\n", normalize(&start, &stop, num));

	return 0;
}
