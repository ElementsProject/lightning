#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

static void destroy_errno(char *p UNNEEDED)
{
	/* Errno restored for all the destructors. */
	ok1(errno == EINVAL);
	errno = ENOENT;
}

int main(void)
{
	char *p;

	plan_tests(5);

	p = tal(NULL, char);
	ok1(tal_add_destructor(p, destroy_errno));
	ok1(tal_add_destructor(p, destroy_errno));

	/* Errno save/restored across free. */
	errno = EINVAL;
	tal_free(p);
	ok1(errno == EINVAL);

	tal_cleanup();
	return exit_status();
}
