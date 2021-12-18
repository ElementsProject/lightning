#include <ccan/strset/strset.h>
#include <ccan/strset/strset.c>
#include <ccan/tap/tap.h>
#include <stdio.h>

/* Must be > 100, see below. */
#define NUM 200

static bool in_order(const char *value, unsigned int *count)
{
	int i = atoi(value);
	ok1(*count == i);
	(*count)++;
	return true;
}

static bool find_empty(const char *value, char *empty)
{
	if (value == empty)
		pass("Found empty entry!");
	return true;
}

int main(void)
{
	struct strset set;
	const struct strset *sub;
	unsigned int i;
	char *str[NUM], *empty;

	plan_tests(7 + 1 + 10 + 100);
	strset_init(&set);

	for (i = 0; i < NUM; i++) {
		char template[10];
		sprintf(template, "%08u", i);
		str[i] = strdup(template);
	}

	for (i = 0; i < NUM; i++)
		strset_add(&set, str[i]);

	/* Nothing */
	sub = strset_prefix(&set, "a");
	ok1(strset_empty(sub));

	/* Everything */
	sub = strset_prefix(&set, "0");
	ok1(sub->u.n == set.u.n);
	sub = strset_prefix(&set, "");
	ok1(sub->u.n == set.u.n);

	/* Singleton. */
	sub = strset_prefix(&set, "00000000");
	i = 0;
	strset_iterate(sub, in_order, &i);
	ok1(i == 1);

	/* First 10. */
	sub = strset_prefix(&set, "0000000");
	i = 0;
	strset_iterate(sub, in_order, &i);
	ok1(i == 10);

	/* First 100. */
	sub = strset_prefix(&set, "000000");
	i = 0;
	strset_iterate(sub, in_order, &i);
	ok1(i == 100);

	/* Everything, *plus* empty string. */
	empty = strdup("");
	strset_add(&set, empty);

	sub = strset_prefix(&set, "");
	/* Check we get *our* empty string back! */
	strset_iterate(sub, find_empty, empty);

	strset_clear(&set);

	for (i = 0; i < NUM; i++)
		free(str[i]);
	free(empty);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
