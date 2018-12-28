#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

#define NUM 1000

static int set_children(const tal_t *parent, char val)
{
	char *iter;
	int num = 0;

	for (iter = tal_first(parent); iter; iter = tal_next(iter)) {
		ok1(*iter == '0');
		*iter = val;
		num++;
		num += set_children(iter, val);
	}
	return num;
}

static void check_children(const tal_t *parent, char val)
{
	const char *iter;

	for (iter = tal_first(parent); iter; iter = tal_next(iter)) {
		ok1(*iter == val);
		check_children(iter, val);
	}
}

int main(void)
{
	char *p[NUM] = { NULL };
	int i;

	plan_tests(NUM + 1 + NUM);

	/* Create a random tree */
	for (i = 0; i < NUM; i++) {
		p[i] = tal(p[rand() % (i + 1)], char);
		*p[i] = '0';
	}

	i = set_children(NULL, '1');
	ok1(i == NUM);

	check_children(NULL, '1');
	for (i = NUM-1; i >= 0; i--)
		tal_free(p[i]);

	tal_cleanup();
	return exit_status();
}
