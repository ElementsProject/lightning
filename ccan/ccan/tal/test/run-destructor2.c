#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

static void destroy_inc(char *p UNNEEDED, int *destroy_count)
{
	(*destroy_count)++;
}

static void destroy_dec(char *p UNNEEDED, int *destroy_count)
{
	(*destroy_count)--;
}

int main(void)
{
	char *p;
	int destroy_count1 = 0, destroy_count2 = 0;

	plan_tests(10);

	p = tal(NULL, char);
	/* Del must match both fn and arg. */
	ok1(tal_add_destructor2(p, destroy_inc, &destroy_count1));
	ok1(!tal_del_destructor2(p, destroy_inc, &destroy_count2));
	ok1(!tal_del_destructor2(p, destroy_dec, &destroy_count1));
	ok1(tal_del_destructor2(p, destroy_inc, &destroy_count1));
	ok1(!tal_del_destructor2(p, destroy_inc, &destroy_count1));

	ok1(tal_add_destructor2(p, destroy_inc, &destroy_count1));
	ok1(tal_add_destructor2(p, destroy_dec, &destroy_count2));
	ok1(tal_free(p) == NULL);
	ok1(destroy_count1 == 1);
	ok1(destroy_count2 == -1);

	tal_cleanup();
	return exit_status();
}
