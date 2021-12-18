/* Test high bit handling. */
#include <ccan/strset/strset.h>
#include <ccan/strset/strset.c>
#include <ccan/tap/tap.h>

#define NUM 1000

static void encode(char template[3], unsigned int val)
{
	assert(val < 255 * 255);
	template[0] = (val / 255) + 1;
	template[1] = (val % 255) + 1;
	template[2] = '\0';
}

static bool in_order(const char *value, unsigned int *count)
{
	char template[3];
	encode(template, *count);
	ok1(streq(value, template));
	(*count)++;
	return true;
}

static bool in_order_by_2(const char *value, unsigned int *count)
{
	char template[3];
	encode(template, *count);
	ok1(streq(value, template));
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

	plan_tests(NUM + 3 * NUM / 2);
	strset_init(&set);

	for (i = 0; i < NUM; i++) {
		char template[3];
		encode(template, i);
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

	for (i = 0; i < NUM; i++)
		free(str[i]);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
