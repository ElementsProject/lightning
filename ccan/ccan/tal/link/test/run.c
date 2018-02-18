#include <ccan/tal/link/link.c>
#include <ccan/tap/tap.h>
#include <stdlib.h>
#include <err.h>

static unsigned int destroy_count = 0;
static void destroy_obj(void *obj UNNEEDED)
{
	destroy_count++;
}

int main(void)
{
	char *linkable, *p1, *p2, *p3;
	void **voidpp;

	plan_tests(23);

	linkable = tal(NULL, char);
	ok1(tal_linkable(linkable) == linkable);
	ok1(tal_add_destructor(linkable, destroy_obj));
	/* First, free it immediately. */
	tal_free(linkable);
	ok1(destroy_count == 1);

	/* Now create and remove a single link. */
	linkable = tal_linkable(tal(NULL, char));
	ok1(tal_add_destructor(linkable, destroy_obj));
	ok1(p1 = tal_link(NULL, linkable));
	ok1(p1 == linkable);
	tal_delink(NULL, linkable);
	ok1(destroy_count == 2);

	/* Two links.*/
	linkable = tal_linkable(tal(NULL, char));
	ok1(tal_add_destructor(linkable, destroy_obj));
	ok1(p1 = tal_link(NULL, linkable));
	ok1(p1 == linkable);
	ok1(p2 = tal_link(NULL, linkable));
	ok1(p2 == linkable);
	tal_delink(NULL, linkable);
	tal_delink(NULL, linkable);
	ok1(destroy_count == 3);

	/* Three links.*/
	linkable = tal_linkable(tal(NULL, char));
	ok1(tal_add_destructor(linkable, destroy_obj));
	ok1(p1 = tal_link(NULL, linkable));
	ok1(p1 == linkable);
	ok1(p2 = tal_link(NULL, linkable));
	ok1(p2 == linkable);
	ok1(p3 = tal_link(NULL, linkable));
	ok1(p3 == linkable);
	tal_delink(NULL, linkable);
	tal_delink(NULL, linkable);
	tal_delink(NULL, linkable);
	ok1(destroy_count == 4);

	/* Now, indirectly. */
	voidpp = tal(NULL, void *);
	linkable = tal_linkable(tal(NULL, char));
	ok1(tal_add_destructor(linkable, destroy_obj));
/* Suppress gratuitous warning with tests_compile_without_features */
#if HAVE_STATEMENT_EXPR
	tal_link(voidpp, linkable);
#else
	(void)tal_link(voidpp, linkable);
#endif
	tal_free(voidpp);
	ok1(destroy_count == 5);

	return exit_status();
}
