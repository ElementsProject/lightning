#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

static void destroy_errno(char *p)
{
	errno = ENOENT;
}

int main(void)
{
	char *p;

	plan_tests(2);

	p = tal(NULL, char);
	ok1(tal_add_destructor(p, destroy_errno));

	/* Errno save/restored across free. */
	errno = EINVAL;
	tal_free(p);
	ok1(errno == EINVAL);

	tal_cleanup();
	return exit_status();
}
