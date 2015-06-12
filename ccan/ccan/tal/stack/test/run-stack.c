#include <ccan/tal/stack/stack.h>
#include <ccan/tal/stack/stack.c>
#include <ccan/tap/tap.h>

int main(void)
{
	tal_t *parent, *cur;

	plan_tests(8);

	/* initial frame is NULL */
	ok1(tal_curframe() == NULL);

	/* create new frame and make sure all is OK */
	cur = tal_newframe();
	ok1(tal_curframe() == cur);
	ok1(tal_parent(cur) == NULL);

	/* create another frame */
	parent = cur;
	cur = tal_newframe();
	ok1(tal_curframe() == cur);
	ok1(tal_parent(cur) == parent);

	/* unwind */
	tal_free(cur);
	ok1(tal_curframe() == parent);
	cur = tal_curframe();
	ok1(tal_parent(cur) == NULL);
	tal_free(cur);
	ok1(tal_curframe() == NULL);

	tal_cleanup();
	return exit_status();
}
