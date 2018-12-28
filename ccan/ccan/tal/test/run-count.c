#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

static bool move;
#define ALIGN (sizeof(void *)*2)

static void *my_alloc(size_t len)
{
	char *ret = malloc(len + ALIGN);
	memcpy(ret, &len, sizeof(len));
	return ret + ALIGN;
}

static void my_free(void *p)
{
	if (p)
		free((char *)p - ALIGN);
}

static void *my_realloc(void *old, size_t new_size)
{
	char *ret;

	/* Test what happens if we always move */
	if (move) {
		size_t old_size = *(size_t *)((char *)old - ALIGN);
		ret = my_alloc(new_size);
		memcpy(ret, old, old_size > new_size ? new_size : old_size);
		my_free(old);
	} else {
		ret = realloc((char *)old - ALIGN, new_size + ALIGN);
		memcpy(ret, &new_size, sizeof(new_size));
		ret += ALIGN;
	}
	return ret;
}

int main(void)
{
	char *p1, *p2;
	unsigned int i;

	tal_set_backend(my_alloc, my_realloc, my_free, NULL);

	plan_tests(2 + 19 * 3);

	p1 = NULL;
	ok1(tal_bytelen(p1) == 0);
	ok1(tal_count(p1) == 0);

	for (i = 0; i < 3; i++) {
		move = i;

		p1 = tal(NULL, char);
		ok1(p1);
		ok1(tal_count(p1) == 1);

		p2 = tal_arr(p1, char, 1);
		ok1(p2);
		ok1(tal_count(p2) == 1);
		ok1(tal_resize(&p2, 2));
		ok1(tal_count(p2) == 2);
		ok1(tal_check(NULL, NULL));
		tal_free(p2);

		/* Resize twice. */
		p2 = tal_arrz(p1, char, 7);
		ok1(p2);
		ok1(tal_count(p2) == 7);
		ok1(tal_check(NULL, NULL));
		tal_resize(&p2, 20);
		ok1(p2);
		ok1(tal_check(NULL, NULL));
		ok1(tal_count(p2) == 20);
		/* Tickles non-moving logic, as we do not update bounds. */
		if (i == 2)
			move = false;
		tal_resize(&p2, 300);
		ok1(p2);
		ok1(tal_check(NULL, NULL));
		ok1(tal_count(p2) == 300);
		ok1(tal_resize(&p2, 0));
		ok1(tal_count(p2) == 0);
		ok1(tal_check(NULL, NULL));
		tal_free(p2);
		tal_free(p1);
	}

	tal_cleanup();
	return exit_status();
}
