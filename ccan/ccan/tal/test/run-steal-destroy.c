#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

static char *rescue;
static unsigned int destroy_count;
static bool steal_result;

static void steal_self(char *p)
{
	destroy_count++;
	/* Rescue ourselves: succeeds if rescue is alive, fails if it
	 * is also being destroyed. */
	steal_result = (tal_steal(rescue, p) == p);
}

int main(void)
{
	char *victim, *parent, *child;

	plan_tests(10);

	/* Rescue to a live parent: object survives tal_free(). */
	rescue = tal(NULL, char);
	victim = tal(NULL, char);
	destroy_count = 0;
	ok1(tal_add_destructor(victim, steal_self));
	tal_free(victim);
	ok1(destroy_count == 1);
	ok1(steal_result);
	ok1(tal_parent(victim) == rescue);
	ok1(tal_first(rescue) == victim);
	*victim = '1'; /* still valid */
	ok1(*victim == '1');

	/* Freeing rescue now: destructor fires again, but stealing into
	 * the dying rescue fails, so victim is freed (no hang, no UAF). */
	tal_free(rescue);
	ok1(destroy_count == 2);
	ok1(!steal_result);

	/* Direct case: child destructor tries to steal into the parent
	 * currently being freed. */
	parent = tal(NULL, char);
	child = tal(parent, char);
	rescue = parent;
	destroy_count = 0;
	ok1(tal_add_destructor(child, steal_self));
	tal_free(parent);
	ok1(destroy_count == 1);

	tal_cleanup();
	return exit_status();
}
