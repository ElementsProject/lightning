/* Regression test (2026-08 review of 4bd458cb): if a destructor's
 * rescue-steal fails because add_child(newpar) can't allocate, the
 * object must still be freed -- not silently re-attached to its old
 * parent (which, if the old parent is itself mid-del_tree, re-fires
 * the destructor and loops under persistent allocation failure). */
#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>
#include <unistd.h>

static char *newpar;
static bool steal_ok;
static unsigned int destroy_count;

static void *null_alloc(size_t size)
{
	(void)size;
	return NULL;
}

static void *null_realloc(void *p, size_t size)
{
	(void)p;
	(void)size;
	return NULL;
}

static void my_errorfn(const char *msg)
{
	(void)msg;
}

static void rescue_destructor(char *p)
{
	destroy_count++;
	steal_ok = (tal_steal(newpar, p) == p);
}

int main(void)
{
	char *oldpar, *victim;

	plan_tests(6);
	alarm(10);

	/* Case 1: simple rescue under allocation failure. */
	newpar = tal(NULL, char);	/* no children property yet */
	oldpar = tal(NULL, char);
	victim = tal(oldpar, char);
	ok1(tal_add_destructor(victim, rescue_destructor));

	destroy_count = 0;
	tal_set_backend(null_alloc, null_realloc, free, my_errorfn);
	tal_free(victim);
	tal_set_backend(malloc, realloc, free, my_errorfn);

	ok1(destroy_count == 1);
	ok1(!steal_ok);
	/* The object was really freed: not re-attached to oldpar. */
	ok1(tal_first(oldpar) == NULL);
	tal_free(oldpar);
	tal_free(newpar);

	/* Case 2: old parent itself being destroyed (must not loop). */
	newpar = tal(NULL, char);
	oldpar = tal(NULL, char);
	victim = tal(oldpar, char);
	ok1(tal_add_destructor(victim, rescue_destructor));

	destroy_count = 0;
	tal_set_backend(null_alloc, null_realloc, free, my_errorfn);
	tal_free(oldpar);
	tal_set_backend(malloc, realloc, free, my_errorfn);

	ok1(destroy_count == 1);
	tal_free(newpar);

	tal_cleanup();
	return exit_status();
}
