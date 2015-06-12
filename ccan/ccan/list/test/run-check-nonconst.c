#include <ccan/list/list.h>
#include <ccan/tap/tap.h>
#include <ccan/list/list.c>
#include "helper.h"

struct child {
	const char *name;
	struct list_node list;
};

int main(int argc, char *argv[])
{
	struct child c1, c2;
	struct list_head list = LIST_HEAD_INIT(list);

	plan_tests(1);

	list_add(&list, &c1.list);
	list_add_tail(list_check(&list, "Bad list!"), &c2.list);
	list_del_from(list_check(&list, "Bad list!"),
		      list_check_node(&c2.list, "Bad node!"));
	list_del_from(list_check(&list, "Bad list!"),
		      list_check_node(&c1.list, "Bad node!"));
	ok1(list_empty(list_check(&list, "Bad emptied list")));

	return exit_status();
}
