#include <ccan/list/list.h>
#include <ccan/tap/tap.h>
#include <ccan/list/list.c>
#include <stdarg.h>

static bool list_expect(struct list_head *h, ...)
{
	va_list ap;
	struct list_node *n = &h->n, *expected;

	va_start(ap, h);
	while ((expected = va_arg(ap, struct list_node *)) != NULL) {
		n = n->next;
		if (n != expected)
			return false;
	}
	return (n->next == &h->n);
}

int main(int argc, char *argv[])
{
	struct list_head h1, h2;
	struct list_node n[4];

	plan_tests(40);

	list_head_init(&h1);
	list_head_init(&h2);

	/* Append an empty list to an empty list. */
	list_append_list(&h1, &h2);
	ok1(list_empty(&h1));
	ok1(list_empty(&h2));
	ok1(list_check(&h1, NULL));
	ok1(list_check(&h2, NULL));

	/* Prepend an empty list to an empty list. */
	list_prepend_list(&h1, &h2);
	ok1(list_empty(&h1));
	ok1(list_empty(&h2));
	ok1(list_check(&h1, NULL));
	ok1(list_check(&h2, NULL));

	/* Append an empty list to a non-empty list */
	list_add(&h1, &n[0]);
	list_append_list(&h1, &h2);
	ok1(list_empty(&h2));
	ok1(list_check(&h1, NULL));
	ok1(list_check(&h2, NULL));
	ok1(list_expect(&h1, &n[0], NULL));

	/* Prepend an empty list to a non-empty list */
	list_prepend_list(&h1, &h2);
	ok1(list_empty(&h2));
	ok1(list_check(&h1, NULL));
	ok1(list_check(&h2, NULL));
	ok1(list_expect(&h1, &n[0], NULL));

	/* Append a non-empty list to an empty list. */
	list_append_list(&h2, &h1);
	ok1(list_empty(&h1));
	ok1(list_check(&h1, NULL));
	ok1(list_check(&h2, NULL));
	ok1(list_expect(&h2, &n[0], NULL));

	/* Prepend a non-empty list to an empty list. */
	list_prepend_list(&h1, &h2);
	ok1(list_empty(&h2));
	ok1(list_check(&h1, NULL));
	ok1(list_check(&h2, NULL));
	ok1(list_expect(&h1, &n[0], NULL));

	/* Prepend a non-empty list to non-empty list. */
	list_add(&h2, &n[1]);
	list_prepend_list(&h1, &h2);
	ok1(list_empty(&h2));
	ok1(list_check(&h1, NULL));
	ok1(list_check(&h2, NULL));
	ok1(list_expect(&h1, &n[1], &n[0], NULL));

	/* Append a non-empty list to non-empty list. */
	list_add(&h2, &n[2]);
	list_append_list(&h1, &h2);
	ok1(list_empty(&h2));
	ok1(list_check(&h1, NULL));
	ok1(list_check(&h2, NULL));
	ok1(list_expect(&h1, &n[1], &n[0], &n[2], NULL));

	/* Prepend a 2-entry list to a 2-entry list. */
	list_del_from(&h1, &n[2]);
	list_add(&h2, &n[2]);
	list_add_tail(&h2, &n[3]);
	list_prepend_list(&h1, &h2);
	ok1(list_empty(&h2));
	ok1(list_check(&h1, NULL));
	ok1(list_check(&h2, NULL));
	ok1(list_expect(&h1, &n[2], &n[3], &n[1], &n[0], NULL));

	/* Append a 2-entry list to a 2-entry list. */
	list_del_from(&h1, &n[2]);
	list_del_from(&h1, &n[3]);
	list_add(&h2, &n[2]);
	list_add_tail(&h2, &n[3]);
	list_append_list(&h1, &h2);
	ok1(list_empty(&h2));
	ok1(list_check(&h1, NULL));
	ok1(list_check(&h2, NULL));
	ok1(list_expect(&h1, &n[1], &n[0], &n[2], &n[3], NULL));

	return exit_status();
}
