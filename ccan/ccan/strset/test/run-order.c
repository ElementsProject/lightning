#include <ccan/strset/strset.h>
#include <ccan/strset/strset.c>
#include <ccan/tap/tap.h>
#include <stdio.h>

#define NUM 1000

static bool in_order(const char *value, unsigned int *count)
{
	int i = atoi(value);
	ok1(*count == i);
	(*count)++;
	return true;
}

static bool in_order_by_2(const char *value, unsigned int *count)
{
	int i = atoi(value);
	ok1(*count == i);
	(*count) += 2;
	return true;
}

static bool dump(const char *value, void *unused)
{
	diag("%s", value);
	return true;
}

int main(void)
{
	struct strset set;
	unsigned int i;
	char *str[NUM];

	plan_tests(NUM * 2 + 3 * NUM / 2);
	strset_init(&set);

	for (i = 0; i < NUM; i++) {
		char template[10];
		sprintf(template, "%08u", i);
		str[i] = strdup(template);
	}

	for (i = 0; i < NUM; i++)
		strset_add(&set, str[i]);

	strset_iterate(&set, dump, NULL);

	/* Iterate. */
	i = 0;
	strset_iterate(&set, in_order, &i);

	/* Preserve order after deletion. */
	for (i = 0; i < NUM; i += 2)
		ok1(strset_del(&set, str[i]) == str[i]);

	i = 1;
	strset_iterate(&set, in_order_by_2, &i);

	for (i = 1; i < NUM; i += 2)
		ok1(strset_del(&set, str[i]) == str[i]);

	/* empty traverse. */
	strset_iterate(&set, in_order_by_2, (unsigned int *)NULL);

	/* insert backwards, should be fine. */
	for (i = 0; i < NUM; i++)
		strset_add(&set, str[NUM-1-i]);

	i = 0;
	strset_iterate(&set, in_order, &i);

	strset_clear(&set);

	for (i = 0; i < NUM; i++)
		free(str[i]);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
