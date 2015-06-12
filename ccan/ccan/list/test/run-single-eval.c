/* Make sure macros only evaluate their args once. */
#include <ccan/list/list.h>
#include <ccan/tap/tap.h>
#include <ccan/list/list.c>

struct parent {
	const char *name;
	struct list_head children;
	unsigned int num_children;
	int eval_count;
};

struct child {
	const char *name;
	struct list_node list;
};

static LIST_HEAD(static_list);

#define ref(obj, counter) ((counter)++, (obj))

int main(int argc, char *argv[])
{
	struct parent parent;
	struct child c1, c2, c3, *c, *n;
	unsigned int i;
	unsigned int static_count = 0, parent_count = 0, list_count = 0,
		node_count = 0;
	struct list_head list = LIST_HEAD_INIT(list);

	plan_tests(74);
	/* Test LIST_HEAD, LIST_HEAD_INIT, list_empty and check_list */
	ok1(list_empty(ref(&static_list, static_count)));
	ok1(static_count == 1);
	ok1(list_check(ref(&static_list, static_count), NULL));
	ok1(static_count == 2);
	ok1(list_empty(ref(&list, list_count)));
	ok1(list_count == 1);
	ok1(list_check(ref(&list, list_count), NULL));
	ok1(list_count == 2);

	parent.num_children = 0;
	list_head_init(ref(&parent.children, parent_count));
	ok1(parent_count == 1);
	/* Test list_head_init */
	ok1(list_empty(ref(&parent.children, parent_count)));
	ok1(parent_count == 2);
	ok1(list_check(ref(&parent.children, parent_count), NULL));
	ok1(parent_count == 3);

	c2.name = "c2";
	list_add(ref(&parent.children, parent_count), &c2.list);
	ok1(parent_count == 4);
	/* Test list_add and !list_empty. */
	ok1(!list_empty(ref(&parent.children, parent_count)));
	ok1(parent_count == 5);
	ok1(c2.list.next == &parent.children.n);
	ok1(c2.list.prev == &parent.children.n);
	ok1(parent.children.n.next == &c2.list);
	ok1(parent.children.n.prev == &c2.list);
	/* Test list_check */
	ok1(list_check(ref(&parent.children, parent_count), NULL));
	ok1(parent_count == 6);

	c1.name = "c1";
	list_add(ref(&parent.children, parent_count), &c1.list);
	ok1(parent_count == 7);
	/* Test list_add and !list_empty. */
	ok1(!list_empty(ref(&parent.children, parent_count)));
	ok1(parent_count == 8);
	ok1(c2.list.next == &parent.children.n);
	ok1(c2.list.prev == &c1.list);
	ok1(parent.children.n.next == &c1.list);
	ok1(parent.children.n.prev == &c2.list);
	ok1(c1.list.next == &c2.list);
	ok1(c1.list.prev == &parent.children.n);
	/* Test list_check */
	ok1(list_check(ref(&parent.children, parent_count), NULL));
	ok1(parent_count == 9);

	c3.name = "c3";
	list_add_tail(ref(&parent.children, parent_count), &c3.list);
	ok1(parent_count == 10);
	/* Test list_add_tail and !list_empty. */
	ok1(!list_empty(ref(&parent.children, parent_count)));
	ok1(parent_count == 11);
	ok1(parent.children.n.next == &c1.list);
	ok1(parent.children.n.prev == &c3.list);
	ok1(c1.list.next == &c2.list);
	ok1(c1.list.prev == &parent.children.n);
	ok1(c2.list.next == &c3.list);
	ok1(c2.list.prev == &c1.list);
	ok1(c3.list.next == &parent.children.n);
	ok1(c3.list.prev == &c2.list);
	/* Test list_check */
	ok1(list_check(ref(&parent.children, parent_count), NULL));
	ok1(parent_count == 12);

	/* Test list_check_node */
	ok1(list_check_node(&c1.list, NULL));
	ok1(list_check_node(&c2.list, NULL));
	ok1(list_check_node(&c3.list, NULL));

	/* Test list_top */
	ok1(list_top(ref(&parent.children, parent_count), struct child, list) == &c1);
	ok1(parent_count == 13);

	/* Test list_tail */
	ok1(list_tail(ref(&parent.children, parent_count), struct child, list) == &c3);
	ok1(parent_count == 14);

	/* Test list_for_each. */
	i = 0;
	list_for_each(&parent.children, c, list) {
		switch (i++) {
		case 0:
			ok1(c == &c1);
			break;
		case 1:
			ok1(c == &c2);
			break;
		case 2:
			ok1(c == &c3);
			break;
		}
		if (i > 2)
			break;
	}
	ok1(i == 3);

	/* Test list_for_each_safe, list_del and list_del_from. */
	i = 0;
	list_for_each_safe(&parent.children, c, n, list) {
		switch (i++) {
		case 0:
			ok1(c == &c1);
			list_del(ref(&c->list, node_count));
			ok1(node_count == 1);
			break;
		case 1:
			ok1(c == &c2);
			list_del_from(ref(&parent.children, parent_count),
				      ref(&c->list, node_count));
			ok1(node_count == 2);
			break;
		case 2:
			ok1(c == &c3);
			list_del_from(ref(&parent.children, parent_count),
				      ref(&c->list, node_count));
			ok1(node_count == 3);
			break;
		}
		ok1(list_check(ref(&parent.children, parent_count), NULL));
		if (i > 2)
			break;
	}
	ok1(i == 3);
	ok1(parent_count == 19);
	ok1(list_empty(ref(&parent.children, parent_count)));
	ok1(parent_count == 20);

	/* Test list_top/list_tail on empty list. */
	ok1(list_top(ref(&parent.children, parent_count), struct child, list) == NULL);
	ok1(parent_count == 21);
	ok1(list_tail(ref(&parent.children, parent_count), struct child, list) == NULL);
	ok1(parent_count == 22);
	return exit_status();
}
