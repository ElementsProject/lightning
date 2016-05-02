#include <ccan/strmap/strmap.h>
#include <ccan/strmap/strmap.c>
#include <ccan/tap/tap.h>
#include <stdio.h>

#define NUM 1000

static bool in_order(const char *member, char *value, unsigned int *count)
{
	int i = atoi(member);
	ok1(i == atoi(value));
	ok1(*count == i);
	(*count)++;
	return true;
}

static bool in_order_by_2(const char *member, char *value, unsigned int *count)
{
	int i = atoi(member);
	ok1(i == atoi(value));
	ok1(*count == i);
	(*count) += 2;
	return true;
}

static bool dump(const char *member, char *value, bool *ok)
{
	diag("%s=>%s", member, value);
	if (value != member + 1)
		*ok = false;
	return true;
}

int main(void)
{
	STRMAP(char *) map;
	unsigned int i;
	char *str[NUM];
	bool dump_ok;

	plan_tests(1 + NUM * 4 + 3 * NUM);
	strmap_init(&map);

	for (i = 0; i < NUM; i++) {
		char template[10];
		sprintf(template, "%08u", i);
		str[i] = strdup(template);
	}

	for (i = 0; i < NUM; i++)
		strmap_add(&map, str[i], str[i]+1);

	dump_ok = true;
	strmap_iterate(&map, dump, &dump_ok);
	ok1(dump_ok);

	/* Iterate. */
	i = 0;
	strmap_iterate(&map, in_order, &i);

	/* Preserve order after deletion. */
	for (i = 0; i < NUM; i += 2) {
		char *v;
		ok1(strmap_del(&map, str[i], &v) == str[i]);
		ok1(v == str[i] + 1);
	}

	i = 1;
	strmap_iterate(&map, in_order_by_2, &i);

	for (i = 1; i < NUM; i += 2) {
		char *v;
		ok1(strmap_del(&map, str[i], &v) == str[i]);
		ok1(v == str[i] + 1);
	}

	/* empty traverse. */
	strmap_iterate(&map, in_order_by_2, (unsigned int *)NULL);

	/* insert backwards, should be fine. */
	for (i = 0; i < NUM; i++)
		strmap_add(&map, str[NUM-1-i], str[NUM-1-i]+1);

	i = 0;
	strmap_iterate(&map, in_order, &i);

	strmap_clear(&map);

	for (i = 0; i < NUM; i++)
		free(str[i]);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
