#include <setjmp.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <err.h>

/* We don't actually want it to exit... */
static jmp_buf aborted;
#define abort() longjmp(aborted, 1)

#define fprintf my_fprintf
static char printf_buffer[1000];

static int my_fprintf(FILE *stream, const char *format, ...)
{
	va_list ap;
	int ret;
	va_start(ap, format);
	ret = vsprintf(printf_buffer, format, ap);
	va_end(ap);
	return ret;
}

#include <ccan/list/list.h>
#include <ccan/tap/tap.h>
#include <ccan/list/list.c>

int main(int argc, char *argv[])
{
	struct list_head list;
	struct list_node n1;
	char expect[100];

	plan_tests(9);
	/* Empty list. */
	list.n.next = &list.n;
	list.n.prev = &list.n;
	ok1(list_check(&list, NULL) == &list);

	/* Bad back ptr */
	list.n.prev = &n1;
	/* Non-aborting version. */
	ok1(list_check(&list, NULL) == NULL);

	/* Aborting version. */
	sprintf(expect, "test message: prev corrupt in node %p (0) of %p\n",
		&list, &list);
	if (setjmp(aborted) == 0) {
		list_check(&list, "test message");
		fail("list_check on empty with bad back ptr didn't fail!");
	} else {
		ok1(strcmp(printf_buffer, expect) == 0);
	}

	/* n1 in list. */
	list.n.next = &n1;
	list.n.prev = &n1;
	n1.prev = &list.n;
	n1.next = &list.n;
	ok1(list_check(&list, NULL) == &list);
	ok1(list_check_node(&n1, NULL) == &n1);

	/* Bad back ptr */
	n1.prev = &n1;
	ok1(list_check(&list, NULL) == NULL);
	ok1(list_check_node(&n1, NULL) == NULL);

	/* Aborting version. */
	sprintf(expect, "test message: prev corrupt in node %p (1) of %p\n",
		&n1, &list);
	if (setjmp(aborted) == 0) {
		list_check(&list, "test message");
		fail("list_check on n1 bad back ptr didn't fail!");
	} else {
		ok1(strcmp(printf_buffer, expect) == 0);
	}

	sprintf(expect, "test message: prev corrupt in node %p (0) of %p\n",
		&n1, &n1);
	if (setjmp(aborted) == 0) {
		list_check_node(&n1, "test message");
		fail("list_check_node on n1 bad back ptr didn't fail!");
	} else {
		ok1(strcmp(printf_buffer, expect) == 0);
	}

	return exit_status();
}
