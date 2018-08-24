#include <ccan/tal/tal.h>
#include <ccan/tal/tal.c>
#include <ccan/tap/tap.h>

static enum tal_notify_type expect;
static void *expect_info;
static char *ctx;
static unsigned int notified1, notified2, notified_null;

/* Make sure we always move on resize. */
static void *my_realloc(void *old, size_t size)
{
	void *new = realloc(old, size);
	if (new == old) {
		void *p = malloc(size);
		memcpy(p, old, size);
		free(old);
		new = p;
	}
	return new;
}

static void notify1(char *p, enum tal_notify_type notify, void *info)
{
	ok1(p == ctx);
	ok1(notify == expect);
	if (expect_info == &expect_info)
		expect_info = info;
	else
		ok1(info == expect_info);
	notified1++;
}

static void notify2(char *ctx UNNEEDED,
		    enum tal_notify_type notify UNNEEDED,
		    void *info UNNEEDED)
{
	notified2++;
}

static void notify_null(void *p, enum tal_notify_type notify, void *info)
{
	ok1(p == NULL);
	ok1(notify == expect);
	if (expect_info == &expect_info)
		expect_info = info;
	else
		ok1(info == expect_info);
	notified_null++;
}

static bool seen_move, seen_resize;
static void resize_notifier(char *p, enum tal_notify_type notify, void *info)
{
	if (notify == TAL_NOTIFY_MOVE) {
		ok1(!seen_move);
		ok1(!seen_resize);
		ok1(info == ctx);
		ok1(p != ctx);
		ctx = p;
		seen_move = true;
	} else if (notify == TAL_NOTIFY_RESIZE) {
		ok1(!seen_resize);
		ok1(seen_move);
		ok1(p == ctx);
		ok1((size_t)info == 100);
		seen_resize = true;
	} else
		fail("Unexpected notifier %i", notify);
}

int main(void)
{
	char *child, *new_ctx;

	plan_tests(65);

	ctx = tal(NULL, char);
	ok1(tal_add_notifier(ctx, 511, notify1));
	ok1(notified1 == 0);
	ok1(notified2 == 0);

	expect = TAL_NOTIFY_STEAL;
	expect_info = NULL;
	ok1(tal_steal(NULL, ctx) == ctx);
	ok1(notified1 == 1);

	expect = TAL_NOTIFY_ADD_NOTIFIER;
	expect_info = notify2;
	ok1(tal_add_notifier(ctx, TAL_NOTIFY_RENAME|TAL_NOTIFY_ADD_NOTIFIER
			     |TAL_NOTIFY_DEL_NOTIFIER, notify2));
	ok1(notified1 == 2);
	ok1(notified2 == 0);

	expect = TAL_NOTIFY_RENAME;
	expect_info = (char *)"newname";
	ok1(tal_set_name(ctx, (char *)expect_info));
	ok1(notified1 == 3);
	ok1(notified2 == 1);

	expect = TAL_NOTIFY_DEL_NOTIFIER;
	expect_info = notify2;
	ok1(tal_del_notifier(ctx, notify2));
	ok1(notified1 == 4);
	ok1(notified2 == 1);

	/* Failed delete should not call notifier! */
	expect = TAL_NOTIFY_DEL_NOTIFIER;
	expect_info = notify2;
	ok1(!tal_del_notifier(ctx, notify2));
	ok1(notified1 == 4);
	ok1(notified2 == 1);

	expect = TAL_NOTIFY_ADD_CHILD;
	expect_info = &expect_info;
	child = tal(ctx, char);
	ok1(notified1 == 5);
	ok1(notified2 == 1);
	ok1(expect_info == child);

	expect = TAL_NOTIFY_DEL_CHILD;
	expect_info = child;
	tal_free(child);
	ok1(notified1 == 6);
	ok1(notified2 == 1);

	expect = TAL_NOTIFY_FREE;
	expect_info = ctx;
	tal_free(ctx);
	ok1(notified1 == 7);
	ok1(notified2 == 1);

	/* Notifiers on NULL work, too. */
	ok1(tal_add_notifier(NULL, TAL_NOTIFY_ADD_CHILD|TAL_NOTIFY_DEL_CHILD,
			     notify_null));
	expect = TAL_NOTIFY_ADD_CHILD;
	expect_info = &expect_info;
	child = tal(NULL, char);
	ok1(notified_null == 1);

	expect = TAL_NOTIFY_DEL_CHILD;
	expect_info = child;
	tal_free(child);
	ok1(notified_null == 2);
	ok1(tal_del_notifier(NULL, notify_null));

	tal_set_backend(NULL, my_realloc, NULL, NULL);
	ctx = new_ctx = tal(NULL, char);
	ok1(tal_add_notifier(new_ctx, 511, resize_notifier));
	ok1(tal_resize(&new_ctx, 100));
	ok1(seen_move);
	ok1(seen_resize);
	tal_del_notifier(new_ctx, resize_notifier);
	tal_free(new_ctx);

	tal_cleanup();
	return exit_status();
}
