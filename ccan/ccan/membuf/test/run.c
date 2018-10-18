#include <ccan/membuf/membuf.h>
#include <stdlib.h>
#include <string.h>

static int num_realloc, num_memmove;

void *memmove_test(void *dest, const void *src, size_t n);
void *realloc_test(void *ptr, size_t size);

void *memmove_test(void *dest, const void *src, size_t n)
{
	num_memmove++;
	return memmove(dest, src, n);
}

void *realloc_test(void *ptr, size_t size)
{
	num_realloc++;
	return realloc(ptr, size);
}

#undef memmove
#define memmove memmove_test

#undef realloc
#define realloc realloc_test

/* Include the C files directly. */
#include <ccan/membuf/membuf.c>
#include <ccan/tap/tap.h>

int main(void)
{
	int prev_reallocs;
	MEMBUF(int) intbuf;

	/* This is how many tests you plan to run */
	plan_tests(13 + 100 * 4 + 999);

	membuf_init(&intbuf, malloc(10 * sizeof(int)), 10, membuf_realloc);
	ok1(membuf_num_elems(&intbuf) == 0);
	ok1(membuf_num_space(&intbuf) == 10);
	ok1(membuf_space(&intbuf) != NULL);

	/* Add 100 ints. */
	for (int i = 0; i < 100; i++) {
		memcpy(membuf_add(&intbuf, 1), &i, sizeof(i));
		ok1(membuf_num_elems(&intbuf) == i+1);

		/* Make sure membuf_elems works */
		if (i == 0)
			ok1(memcmp(membuf_elems(&intbuf), &i, sizeof(i)) == 0);
	}


	/* Pull 100 ints. */
	for (int i = 0; i < 100; i++) {
		ok1(memcmp(membuf_consume(&intbuf, 1), &i, sizeof(i)) == 0);
		ok1(membuf_num_elems(&intbuf) == 100 - i - 1);
	}

	/* Should not have continuously realloced or memmoved */
	ok1(num_realloc < 10);
	ok1(num_memmove == 0);

	/* Doing it again should give 0 reallocs. */
	prev_reallocs = num_realloc;
	for (int i = 0; i < 100; i++) {
		memcpy(membuf_add(&intbuf, 1), &i, sizeof(i));
		ok1(membuf_num_elems(&intbuf) == i+1);
	}
	ok1(num_realloc == prev_reallocs);
	ok1(num_memmove == 0);

	membuf_consume(&intbuf, 100);

	/* Keep a single element in the queue, make sure we don't realloc! */
	for (int i = 0; i < 1000; i++) {
		memcpy(membuf_add(&intbuf, 1), &i, sizeof(i));
		if (i > 0) {
			int prev = i - 1;
			ok1(memcmp(membuf_consume(&intbuf, 1),
				   &prev, sizeof(prev)) == 0);
		}
	}

	ok1(num_realloc == prev_reallocs);
	/* Should have moved occasionally. */
	ok1(num_memmove < 20);

	ok1(membuf_consume(&intbuf, 1));
	ok1(membuf_num_elems(&intbuf) == 0);

	/* Force it to more-than-double; make sure that works! */
	memset(membuf_add(&intbuf, 300), 0, 300*sizeof(int));
	ok1(membuf_num_elems(&intbuf) == 300);

	/* Free buffer so valgrind is happy. */
	free(membuf_cleanup(&intbuf));

	/* This exits depending on whether all tests passed */
	return exit_status();
}
