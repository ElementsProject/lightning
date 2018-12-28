#include <ccan/list/list.h>
#include <ccan/tap/tap.h>
#include <ccan/list/list.c>
#include <stdbool.h>
#include <stdio.h>

struct child {
	const char *name;
	struct list_node list;
};

static bool children(const struct list_head *list)
{
	return !list_empty(list);
}

static const struct child *first_child(const struct list_head *list)
{
	return list_top(list, struct child, list);
}

static const struct child *last_child(const struct list_head *list)
{
	return list_tail(list, struct child, list);
}

static void check_children(const struct list_head *list)
{
	list_check(list, "bad child list");
}

static void print_children(const struct list_head *list)
{
	const struct child *c;
	list_for_each(list, c, list)
		printf("%s\n", c->name);
}

int main(void)
{
	LIST_HEAD(h);

	children(&h);
	first_child(&h);
	last_child(&h);
	check_children(&h);
	print_children(&h);
	return 0;
}
