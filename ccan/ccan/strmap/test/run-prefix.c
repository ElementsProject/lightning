#include <ccan/strmap/strmap.h>
#include <ccan/strmap/strmap.c>
#include <ccan/tap/tap.h>
#include <stdio.h>

/* Must be > 100, see below. */
#define NUM 200

static bool in_order(const char *index, char *value, unsigned int *count)
{
	int i = atoi(index);
	ok1(i == atoi(value));
	ok1(*count == i);
	(*count)++;
	return true;
}

static bool find_empty(const char *index, char *value UNNEEDED, char *empty)
{
	if (index == empty)
		pass("Found empty entry!");
	return true;
}

int main(void)
{
	typedef STRMAP(char *) map_t;
	map_t map;
	const map_t *sub;
	unsigned int i;
	char *str[NUM], *empty;

	plan_tests(8 + 2 * (1 + 10 + 100) + 1);
	strmap_init(&map);

	for (i = 0; i < NUM; i++) {
		char template[10];
		sprintf(template, "%08u", i);
		str[i] = strdup(template);
	}

	/* All prefixes of an empty map are empty. */
	sub = strmap_prefix(&map, "a");
	ok1(strmap_empty(sub));
	sub = strmap_prefix(&map, "");
	ok1(strmap_empty(sub));

	for (i = 0; i < NUM; i++)
		strmap_add(&map, str[i], str[i]+1);

	/* Nothing */
	sub = strmap_prefix(&map, "a");
	ok1(strmap_empty(sub));

	/* Everything */
	sub = strmap_prefix(&map, "0");
	ok1(tcon_unwrap(sub)->u.n == tcon_unwrap(&map)->u.n);
	sub = strmap_prefix(&map, "");
	ok1(tcon_unwrap(sub)->u.n == tcon_unwrap(&map)->u.n);

	/* Single. */
	sub = strmap_prefix(&map, "00000000");
	i = 0;
	strmap_iterate(sub, in_order, &i);
	ok1(i == 1);

	/* First 10. */
	sub = strmap_prefix(&map, "0000000");
	i = 0;
	strmap_iterate(sub, in_order, &i);
	ok1(i == 10);

	/* First 100. */
	sub = strmap_prefix(&map, "000000");
	i = 0;
	strmap_iterate(sub, in_order, &i);
	ok1(i == 100);

	/* Everything, *plus* empty string. */
	empty = strdup("");
	strmap_add(&map, empty, empty);

	sub = strmap_prefix(&map, "");
	/* Check we get *our* empty string back! */
	strmap_iterate(sub, find_empty, empty);

	strmap_clear(&map);

	for (i = 0; i < NUM; i++)
		free(str[i]);
	free(empty);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
