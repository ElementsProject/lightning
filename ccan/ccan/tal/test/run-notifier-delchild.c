#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

static unsigned int del_child_calls, steal_calls;
static bool rescued;
static char *rescue;

/* Recursive tal_free() of the announced child must be a no-op. */
static void free_child(char *parent, enum tal_notify_type type, void *info)
{
	(void)parent;
	if (type == TAL_NOTIFY_DEL_CHILD) {
		del_child_calls++;
		tal_free(info);
	}
}

/* tal_steal() of the announced child rescues it. */
static void steal_child(char *parent, enum tal_notify_type type, void *info)
{
	(void)parent;
	if (type == TAL_NOTIFY_DEL_CHILD) {
		steal_calls++;
		rescued = (tal_steal(rescue, info) == info);
	}
}

int main(void)
{
	char *parent, *child;

	plan_tests(7);

	/* Recursive free from DEL_CHILD notifier: no-op, no recursion. */
	parent = tal(NULL, char);
	ok1(tal_add_notifier(parent, TAL_NOTIFY_DEL_CHILD, free_child));
	child = tal(parent, char);
	tal_free(child);
	ok1(del_child_calls == 1);
	/* Parent is intact and childless. */
	ok1(tal_first(parent) == NULL);
	ok1(tal_del_notifier(parent, free_child));

	/* Steal from DEL_CHILD notifier: rescues the child. */
	rescue = tal(NULL, char);
	ok1(tal_add_notifier(parent, TAL_NOTIFY_DEL_CHILD, steal_child));
	child = tal(parent, char);
	tal_free(child);
	ok1(steal_calls == 1);
	ok1(rescued && tal_parent(child) == rescue);

	tal_free(rescue);
	tal_free(parent);
	tal_cleanup();
	return exit_status();
}
