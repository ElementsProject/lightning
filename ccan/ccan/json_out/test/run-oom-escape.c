/* Regression test (auditor-added, temporary): the escape paths do not
 * handle json_escape_len() returning NULL (it is a tal allocation and
 * fails on OOM):
 *   json_out_addv   (ccan/json_out/json_out.c:261-262): strlen(e->s)
 *   json_out_addstrn (ccan/json_out/json_out.c:309-311): str = e->s
 *
 * Today the crash actually happens one frame earlier, inside the
 * dependency: ccan/json_escape/json_escape.c escape() does not check
 * its tal_arr() result either (json_escape.c:63, first dereferenced at
 * json_escape.c:123).  This test must pass after BOTH are repaired:
 * json_escape returning NULL on OOM and json_out mapping that to a
 * false return.
 *
 * Allocation failure is simulated with tal_set_backend installed only
 * around the call under test, so the escape allocation is the one that
 * fails.
 *
 * Currently fails (NULL dereference); must pass after repair.
 */
#include "config.h"

#include <stdlib.h>
#include <unistd.h>

#include <ccan/json_out/json_out.c>
#include <ccan/tal/tal.h>
#include <ccan/tap/tap.h>

static void ignoring_error(const char *msg)
{
	(void)msg;
}

static void *failing_alloc(size_t size)
{
	(void)size;
	return NULL;
}

static void restore_backend(void)
{
	tal_set_backend(malloc, realloc, free, (void (*)(const char *))abort);
}

int main(void)
{
	struct json_out *jout;
	bool ok;

	alarm(10);
	plan_tests(2);

	/* json_out_add() with a string needing escape. */
	jout = json_out_new(NULL);
	json_out_start(jout, NULL, '{');
	tal_set_backend(failing_alloc, NULL, NULL, ignoring_error);
	ok = json_out_add(jout, "f", true, "%s", "a\nb");
	restore_backend();
	ok1(!ok);
	tal_free(jout);

	/* json_out_addstrn() with a string needing escape. */
	jout = json_out_new(NULL);
	json_out_start(jout, NULL, '{');
	tal_set_backend(failing_alloc, NULL, NULL, ignoring_error);
	ok = json_out_addstrn(jout, "f", "a\nb", 3);
	restore_backend();
	ok1(!ok);
	tal_free(jout);

	return exit_status();
}
