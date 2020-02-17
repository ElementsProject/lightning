#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

static char *parent, *child;
static int destroy_count;

/* Parent gets destroyed first. */
static void destroy_parent(char *p)
{
	ok1(p == parent);
	ok1(destroy_count == 0);
	/* Can still access child. */
	*child = '1';
	destroy_count++;
}

static void destroy_child(char *p)
{
	ok1(p == child);
	ok1(destroy_count == 1);
	/* Can still access parent (though destructor has been called). */
	*parent = '1';
	destroy_count++;
}

static void destroy_inc(char *p UNNEEDED)
{
	destroy_count++;
}

static void remove_own_destructor(char *p)
{
	destroy_count++;
	ok1(!tal_del_destructor(p, remove_own_destructor));
}

int main(void)
{
	char *child2;

	plan_tests(21);

	destroy_count = 0;
	parent = tal(NULL, char);
	child = tal(parent, char);
	ok1(tal_add_destructor(parent, destroy_parent));
	ok1(tal_add_destructor(child, destroy_child));
	tal_free(parent);
	ok1(destroy_count == 2);

	destroy_count = 0;
	parent = tal(NULL, char);
	child = tal(parent, char);
	ok1(tal_add_destructor(parent, destroy_parent));
	ok1(tal_add_destructor(child, destroy_child));
	ok1(tal_del_destructor(child, destroy_child));
	tal_free(parent);
	ok1(destroy_count == 1);

	destroy_count = 0;
	parent = tal(NULL, char);
	child = tal(parent, char);
	child2 = tal(parent, char);
	ok1(tal_add_destructor(parent, destroy_inc));
	ok1(tal_add_destructor(parent, destroy_inc));
	ok1(tal_add_destructor(child, destroy_inc));
	ok1(tal_add_destructor(child2, destroy_inc));
	tal_free(parent);
	ok1(destroy_count == 4);

	destroy_count = 0;
	parent = tal(NULL, char);
	ok1(tal_add_destructor(parent, remove_own_destructor));
	tal_free(parent);
	ok1(destroy_count == 1);
	
	tal_cleanup();
	return exit_status();
}
