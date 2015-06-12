/* Check that CCAN_LIST_DEBUG works */
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

#define CCAN_LIST_DEBUG 1
#include <ccan/list/list.h>
#include <ccan/tap/tap.h>
#include <ccan/list/list.c>

int main(int argc, char *argv[])
{
	struct list_head list;
	struct list_node n1;
	char expect[100];

	plan_tests(2);
	/* Empty list. */
	list.n.next = &list.n;
	list.n.prev = &list.n;
	ok1(list_check(&list, NULL) == &list);

	/* Bad back ptr */
	list.n.prev = &n1;

	/* Aborting version. */
	sprintf(expect, "run-CCAN_LIST_DEBUG.c:50: prev corrupt in node %p (0) of %p\n",
		&list, &list);
	if (setjmp(aborted) == 0) {
		assert(list_empty(&list));
		fail("list_empty on empty with bad back ptr didn't fail!");
	} else {
		/* __FILE__ might give full path. */
		int prep = strlen(printf_buffer) - strlen(expect);
		ok1(prep >= 0 && strcmp(printf_buffer + prep, expect) == 0);
	}

	return exit_status();
}
